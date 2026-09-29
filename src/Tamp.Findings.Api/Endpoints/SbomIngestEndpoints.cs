using Tamp.Findings.Application.Ingest;
using Microsoft.EntityFrameworkCore;
using Tamp.Findings.Api.Authentication;
using Tamp.Findings.Api.Contracts;
using Tamp.Findings.Data;
using Tamp.Findings.Domain.Entities;

using Tamp.Findings.Application.Auditing;

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

    private static async Task<IResult> IngestAsync(
        SbomIngestRequest req, HttpContext ctx, FindingsDbContext db,
        CveReconciler reconciler, AuditLog audit,
        Tamp.Findings.Application.Projects.ScoreSnapshotService snapshots, CancellationToken ct)
    {
        if (string.IsNullOrWhiteSpace(req.Client)) return Results.BadRequest("client is required");
        if (string.IsNullOrWhiteSpace(req.Project)) return Results.BadRequest("project is required");
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

        // TFND-16: this SBOM may be what a previously-orphaned OsvScanner or
        // Trivy CVE finding was waiting for. Reconciling on this side too is
        // what makes ingest order not matter.
        var reconciled = await reconciler.ReconcileAsync([version.Id], ct);

        await IngestAudit.RecordAsync(audit, db, token, version.Id,
            $"sbom: {purlToId.Count} components, {depsAdded} deps, {totalVulns + reconciled.Attached} CVEs — {req.Project}@{req.Version}", ct);
        await db.SaveChangesAsync(ct);

        await snapshots.RecordForBuildAsync(version.Id, ct);   // TFND-176: cve/licence/staleness moved the score

        return Results.Ok(new SbomIngestResponse(
            version.Id,
            snapshot.Id,
            purlToId.Count,
            depsAdded,
            // Vulnerabilities from the SBOM payload PLUS any advisory findings
            // this pass attached. The number is "how many CVEs this build now
            // knows about", which is what a caller is asking.
            totalVulns + reconciled.Attached));
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

        var version = await BuildResolver.GetOrCreateAsync(db, project!.Id, req.Flavor, req.Version,
            req.CommitSha, req.Branch, req.BuildId, req.PullRequestRef, ct);
        // TFND-165: stamp the build with the actor that produced this ingest.
        version.ApplyActor(req.Actor);
        await db.SaveChangesAsync(ct);
        return (version, null);
    }
}
