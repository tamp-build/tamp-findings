using Microsoft.EntityFrameworkCore;
using Tamp.Findings.Api.Contracts;
using Tamp.Findings.Data;
using Tamp.Findings.Domain.Entities;
using Tamp.Findings.Domain.Hashing;

namespace Tamp.Findings.Api.Endpoints;

public static class IngestEndpoints
{
    public static IEndpointRouteBuilder MapIngest(this IEndpointRouteBuilder app)
    {
        app.MapPost("/ingest/findings", IngestAsync)
           .WithName("IngestFindings")
           .WithSummary("Ingest a batch of findings from one scanner run for one component version");
        return app;
    }

    private static async Task<IResult> IngestAsync(IngestRequest req, FindingsDbContext db, CancellationToken ct)
    {
        if (string.IsNullOrWhiteSpace(req.Client)) return Results.BadRequest("client is required");
        if (string.IsNullOrWhiteSpace(req.Project)) return Results.BadRequest("project is required");
        if (string.IsNullOrWhiteSpace(req.Component)) return Results.BadRequest("component is required");
        if (string.IsNullOrWhiteSpace(req.Version)) return Results.BadRequest("version is required");

        var client = await db.Clients.FirstOrDefaultAsync(c => c.Name == req.Client, ct);
        if (client is null)
        {
            client = new Client { Name = req.Client };
            db.Clients.Add(client);
        }

        var project = await db.Projects
            .FirstOrDefaultAsync(p => p.ClientId == client.Id && p.Name == req.Project, ct);
        if (project is null)
        {
            project = new Project { ClientId = client.Id, Name = req.Project };
            db.Projects.Add(project);
        }

        var component = await db.Components
            .FirstOrDefaultAsync(c => c.ProjectId == project.Id && c.Name == req.Component, ct);
        if (component is null)
        {
            component = new Component { ProjectId = project.Id, Name = req.Component, Kind = req.ComponentKind };
            db.Components.Add(component);
        }
        else if (req.ComponentKind is not null && component.Kind != req.ComponentKind)
        {
            component.Kind = req.ComponentKind;
        }

        ComponentFlavor? flavor = null;
        if (!string.IsNullOrWhiteSpace(req.Flavor))
        {
            flavor = await db.ComponentFlavors
                .FirstOrDefaultAsync(f => f.ComponentId == component.Id && f.Name == req.Flavor, ct);
            if (flavor is null)
            {
                flavor = new ComponentFlavor { ComponentId = component.Id, Name = req.Flavor };
                db.ComponentFlavors.Add(flavor);
            }
        }

        var version = await db.ComponentVersions.FirstOrDefaultAsync(v =>
            v.ComponentId == component.Id &&
            v.FlavorId == (flavor != null ? flavor.Id : (Guid?)null) &&
            v.VersionString == req.Version, ct);

        if (version is null)
        {
            version = new ComponentVersion
            {
                ComponentId = component.Id,
                FlavorId = flavor?.Id,
                VersionString = req.Version,
                CommitSha = req.CommitSha,
                BranchName = req.Branch,
                BuildId = req.BuildId,
                PullRequestRef = req.PullRequestRef,
            };
            db.ComponentVersions.Add(version);
        }
        else
        {
            // Update build-context fields if newly supplied. Useful when the
            // same version string is re-ingested with richer metadata.
            if (req.CommitSha is not null) version.CommitSha = req.CommitSha;
            if (req.Branch is not null) version.BranchName = req.Branch;
            if (req.BuildId is not null) version.BuildId = req.BuildId;
            if (req.PullRequestRef is not null) version.PullRequestRef = req.PullRequestRef;
        }

        // Persist parents before processing findings so the FK targets exist
        // when we query existing findings for this version.
        await db.SaveChangesAsync(ct);

        var existing = await db.Findings
            .Where(f => f.ComponentVersionId == version.Id)
            .ToDictionaryAsync(f => f.Hash, ct);

        // In-batch dedup: a single scanner run may emit the same effective
        // finding twice (e.g., overlapping OpenGrep rule patterns). Collapse
        // them so the unique index doesn't reject the SaveChanges.
        var pendingInsert = new Dictionary<string, Finding>(StringComparer.Ordinal);

        var now = DateTimeOffset.UtcNow;
        var inserted = 0;
        var updated = 0;

        foreach (var f in req.Findings)
        {
            var hash = FindingHasher.Compute(req.Scanner, f.RuleId, f.FilePath, f.Snippet, f.Line);

            if (existing.TryGetValue(hash, out var current))
            {
                current.LastSeen = now;
                current.Severity = f.Severity;
                current.Title = f.Title;
                current.Description = f.Description;
                current.Line = f.Line;
                current.Snippet = f.Snippet;
                updated++;
            }
            else if (pendingInsert.TryGetValue(hash, out var queued))
            {
                // Same hash earlier in this same batch — fold into the queued
                // insert (latest wins on the mutable fields).
                queued.Severity = f.Severity;
                queued.Title = f.Title;
                queued.Description = f.Description;
                queued.Line = f.Line;
                queued.Snippet = f.Snippet;
                updated++;
            }
            else
            {
                var finding = new Finding
                {
                    ComponentVersionId = version.Id,
                    Hash = hash,
                    Scanner = req.Scanner,
                    RuleId = f.RuleId,
                    Severity = f.Severity,
                    Title = f.Title,
                    Description = f.Description,
                    FilePath = f.FilePath,
                    Line = f.Line,
                    Snippet = f.Snippet,
                    FirstSeen = now,
                    LastSeen = now,
                };
                db.Findings.Add(finding);
                pendingInsert[hash] = finding;
                inserted++;
            }
        }

        await db.SaveChangesAsync(ct);
        return Results.Ok(new IngestResponse(version.Id, inserted, updated));
    }
}
