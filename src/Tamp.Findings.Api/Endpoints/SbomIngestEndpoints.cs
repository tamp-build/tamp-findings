using Microsoft.EntityFrameworkCore;
using Tamp.Findings.Api.Authentication;
using Tamp.Findings.Api.Contracts;
using Tamp.Findings.Data;
using Tamp.Findings.Domain.Entities;

namespace Tamp.Findings.Api.Endpoints;

public static class SbomIngestEndpoints
{
    public static IEndpointRouteBuilder MapSbomIngest(this IEndpointRouteBuilder app)
    {
        app.MapPost("/ingest/sbom", IngestAsync)
           .WithName("IngestSbom")
           .WithSummary("Ingest a CycloneDX-shaped SBOM (components + deps + vulnerabilities) for one component version. Requires Authorization: Bearer cli_… or prj_…")
           .AllowAnonymous()
           .AddEndpointFilter<IngestAuthFilter>();
        return app;
    }

    private static async Task<IResult> IngestAsync(SbomIngestRequest req, HttpContext ctx, FindingsDbContext db, CancellationToken ct)
    {
        if (string.IsNullOrWhiteSpace(req.Client)) return Results.BadRequest("client is required");
        if (string.IsNullOrWhiteSpace(req.Project)) return Results.BadRequest("project is required");
        if (string.IsNullOrWhiteSpace(req.Component)) return Results.BadRequest("component is required");
        if (string.IsNullOrWhiteSpace(req.Version)) return Results.BadRequest("version is required");

        var token = IngestAuthFilter.CurrentToken(ctx);
        var (resolved, scopeErr) = await ResolveComponentVersionAsync(db, token, req, ct);
        if (scopeErr is not null) return scopeErr;
        var version = resolved!;

        // Replace-on-ingest: an SBOM is a point-in-time view. Re-uploading
        // the same component version's SBOM means the previous snapshot is
        // stale; cascade delete cleans up the old components/deps/vulns.
        var existing = await db.SbomSnapshots
            .Where(s => s.ComponentVersionId == version.Id)
            .ToListAsync(ct);
        if (existing.Count > 0)
        {
            db.SbomSnapshots.RemoveRange(existing);
            await db.SaveChangesAsync(ct);
        }

        var snapshot = new SbomSnapshot
        {
            ComponentVersionId = version.Id,
            SerialNumber = req.SerialNumber,
            SpecVersion = req.SpecVersion,
            ToolName = req.ToolName,
            ToolVersion = req.ToolVersion,
            // TFND-21: persist the verbatim metadata.tools record(s).
            MetadataTools = req.MetadataTools is null ? new() : req.MetadataTools.ToList(),
            IngestedAt = DateTimeOffset.UtcNow,
        };
        db.SbomSnapshots.Add(snapshot);
        await db.SaveChangesAsync(ct);

        // Materialize components, keying a purl->Guid map so dependency
        // edges (which reference purls in the payload) can resolve to ids.
        var purlToId = new Dictionary<string, Guid>(StringComparer.Ordinal);
        var totalVulns = 0;
        foreach (var c in req.Components)
        {
            if (string.IsNullOrWhiteSpace(c.Purl)) continue;
            if (purlToId.ContainsKey(c.Purl)) continue;

            var comp = new SbomComponent
            {
                SbomSnapshotId = snapshot.Id,
                Purl = c.Purl,
                Name = c.Name,
                Version = c.Version,
                Kind = c.Kind,
                License = c.License,
                // TFND-21: per-component hash map (algorithm → value).
                Hashes = c.Hashes is null ? new() : c.Hashes.ToDictionary(kv => kv.Key, kv => kv.Value),
            };
            db.SbomComponents.Add(comp);
            purlToId[c.Purl] = comp.Id;

            foreach (var v in c.Vulnerabilities)
            {
                db.Vulnerabilities.Add(new Vulnerability
                {
                    SbomComponentId = comp.Id,
                    AdvisoryId = v.AdvisoryId,
                    Severity = v.Severity,
                    Title = v.Title,
                    Description = v.Description,
                    FixedInVersion = v.FixedInVersion,
                    ReferenceUrl = v.ReferenceUrl,
                    Source = v.Source,
                    CvssScore = v.CvssScore,
                    CvssVector = v.CvssVector,
                });
                totalVulns++;
            }
        }
        await db.SaveChangesAsync(ct);

        // Dependency edges — silently skip any whose parent or child PURL
        // isn't in the components list (some tools list edges to externals
        // they didn't enumerate as components).
        var depsAdded = 0;
        // Some SBOM emitters (Syft especially) can list the same edge more
        // than once when a transitive dep is reached via multiple paths.
        // Dedupe in-batch so the unique index on (snapshot, parent, child)
        // doesn't reject the SaveChanges.
        var seenEdges = new HashSet<(Guid, Guid)>();
        foreach (var d in req.Dependencies)
        {
            if (!purlToId.TryGetValue(d.ParentPurl, out var pid)) continue;
            if (!purlToId.TryGetValue(d.ChildPurl, out var cid)) continue;
            if (!seenEdges.Add((pid, cid))) continue;
            db.SbomDependencies.Add(new SbomDependency
            {
                SbomSnapshotId = snapshot.Id,
                ParentComponentId = pid,
                ChildComponentId = cid,
            });
            depsAdded++;
        }
        await db.SaveChangesAsync(ct);

        return Results.Ok(new SbomIngestResponse(
            version.Id,
            snapshot.Id,
            purlToId.Count,
            depsAdded,
            totalVulns));
    }

    // Resolves the client/project (token-scoped via IngestScopeGuard) and
    // then auto-creates the component/flavor/version chain under that
    // scope. Returns (version, null) on success or (null, errorResult)
    // when scope auth fails.
    private static async Task<(ComponentVersion? version, IResult? error)> ResolveComponentVersionAsync(
        FindingsDbContext db, IngestToken? token, SbomIngestRequest req, CancellationToken ct)
    {
        var (_, project, scopeErr) = await IngestScopeGuard.ResolveAndGuardAsync(db, token, req.Client, req.Project, ct);
        if (scopeErr is not null) return (null, scopeErr);

        var componentLower = req.Component.ToLower();
        var component = await db.Components
            .FirstOrDefaultAsync(c => c.ProjectId == project!.Id && c.Name.ToLower() == componentLower, ct);
        if (component is null)
        {
            component = new Component { ProjectId = project!.Id, Name = req.Component, Kind = req.ComponentKind };
            db.Components.Add(component);
        }

        ComponentFlavor? flavor = null;
        if (!string.IsNullOrWhiteSpace(req.Flavor))
        {
            var flavorLower = req.Flavor.ToLower();
            flavor = await db.ComponentFlavors
                .FirstOrDefaultAsync(f => f.ComponentId == component.Id && f.Name.ToLower() == flavorLower, ct);
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
        await db.SaveChangesAsync(ct);
        return (version, null);
    }
}
