using Tamp.Findings.Application.Ingest;
using Tamp.Findings.Application.Auditing;
using Tamp.Findings.Application.Authorization;
using Microsoft.EntityFrameworkCore;
using Tamp.Findings.Api.Authentication;
using Tamp.Findings.Api.Contracts;
using Tamp.Findings.Data;
using Tamp.Findings.Domain.Entities;
using Tamp.Findings.Domain.Hashing;
using Tamp.Findings.Domain.Suppressions;
using Tamp.Findings.Domain.Values;

namespace Tamp.Findings.Api.Endpoints;

public static class IngestEndpoints
{
    public static IEndpointRouteBuilder MapIngest(this IEndpointRouteBuilder app)
    {
        app.MapPost("/ingest/findings", IngestAsync)
           .WithName("IngestFindings")
           .WithSummary("Ingest a batch of findings from one scanner run for one component version. Requires Authorization: Bearer cli_… or prj_… ingest token.")
           .AllowAnonymous()
           .AddEndpointFilter<IngestAuthFilter>();
        return app;
    }

    private static async Task<IResult> IngestAsync(
        IngestRequest req, HttpContext ctx, FindingsDbContext db,
        CveReconciler reconciler, Tamp.Findings.Api.Services.CheckPublishQueue checks,
        AuditLog audit, Tamp.Findings.Application.Projects.ScoreSnapshotService snapshots,
        CancellationToken ct)
    {
        if (string.IsNullOrWhiteSpace(req.Client)) return Results.BadRequest("client is required");
        if (string.IsNullOrWhiteSpace(req.Project)) return Results.BadRequest("project is required");
        if (string.IsNullOrWhiteSpace(req.Component)) return Results.BadRequest("component is required");
        if (string.IsNullOrWhiteSpace(req.Version)) return Results.BadRequest("version is required");

        var token = IngestAuthFilter.CurrentToken(ctx);
        var (client, project, scopeErr) = await IngestScopeGuard.ResolveAndGuardAsync(db, token, req.Client, req.Project, ct);
        if (scopeErr is not null) return scopeErr;

        // Case-insensitive Component / Flavor lookup so ingest with
        // a case-variant of an existing name doesn't auto-create a dupe.
        var componentLower = req.Component.ToLower();
        var component = await db.Components
            .FirstOrDefaultAsync(c => c.ProjectId == project!.Id && c.Name.ToLower() == componentLower, ct);
        if (component is null)
        {
            component = new Component
            {
                ProjectId = project!.Id, Name = req.Component, Kind = req.ComponentKind,
                // TFND-183: declared capability profile; default code-package.
                Profile = Tamp.Findings.Domain.Compliance.ComponentProfiles.Parse(req.ComponentProfile),
            };
            db.Components.Add(component);
        }
        else
        {
            if (req.ComponentKind is not null && component.Kind != req.ComponentKind)
                component.Kind = req.ComponentKind;
            // A component may be re-classified by a later ingest that declares it.
            if (req.ComponentProfile is { Length: > 0 })
                component.Profile = Tamp.Findings.Domain.Compliance.ComponentProfiles.Parse(req.ComponentProfile);
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
                // Component-collapse PR1: anchor the build to the project directly and keep the
                // flavor as a string tag, while still dual-writing the legacy Component/Flavor FKs.
                ProjectId = project!.Id,
                Flavor = flavor?.Name,
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

        // TFND-165: stamp the build with the actor that produced this ingest,
        // whether it was just created or already existed.
        version.ApplyActor(req.Actor);

        // Persist parents before processing findings so the FK targets exist
        // when we query existing findings for this version.
        await db.SaveChangesAsync(ct);

        // Scope to (componentVersion, scanner) — auto-close logic below
        // only acts on findings from THIS scanner; we never close a Roslyn
        // finding because Trivy didn't see it.
        var existing = await db.Findings
            .Where(f => f.ComponentVersionId == version.Id && f.Scanner == req.Scanner)
            .ToDictionaryAsync(f => f.Hash, ct);

        // Load the active suppression pool once. The table is small (n
        // suppressions per project, not per finding) so a single load and
        // in-memory match is simpler than per-finding queries.
        var now = DateTimeOffset.UtcNow;
        var activeSuppressions = await db.Suppressions
            .AsNoTracking()
            .Where(s => s.ExpiresAt == null || s.ExpiresAt > now)
            .ToListAsync(ct);

        // The finding's full position in the tree, not just its component
        // (TFND-132). Rule-scoped suppressions are bounded by client and
        // project, and the matcher cannot apply that bound without being told
        // where the finding is.
        var suppressionTarget = new SuppressionTarget(client!.Id, project!.Id, version!.ComponentId);

        bool CoveredBySuppression(Guid? findingId, string ruleId, string? filePath)
            => SuppressionMatcher.AnyCovers(activeSuppressions, suppressionTarget, ruleId, filePath, findingId, now);

        // In-batch dedup: a single scanner run may emit the same effective
        // finding twice (e.g., overlapping OpenGrep rule patterns). Collapse
        // them so the unique index doesn't reject the SaveChanges.
        var pendingInsert = new Dictionary<string, Finding>(StringComparer.Ordinal);
        var incomingHashes = new HashSet<string>(StringComparer.Ordinal);

        var inserted = 0;
        var updated = 0;
        var reopened = 0;
        var closed = 0;
        var suppressed = 0;

        foreach (var f in req.Findings)
        {
            // TFND-38: a dynamic scanner reports the request it made, not a
            // place in the source tree, so it needs the route-based hash.
            // Using the file/line hasher here would key on the raw URI —
            // which for a dynamic scan carries the attack payload — and mint
            // a fresh identity on every scan: nothing would ever dedup and
            // FirstSeen would reset each run.
            var hash = ScannerKinds.IsDynamic(req.Scanner)
                ? FindingHasher.ComputeForDynamic(req.Scanner, f.RuleId, f.FilePath)
                : FindingHasher.Compute(req.Scanner, f.RuleId, f.FilePath, f.Snippet, f.Line);
            incomingHashes.Add(hash);

            if (existing.TryGetValue(hash, out var current))
            {
                var prev = current.Status;
                current.LastSeen = now;
                current.Severity = f.Severity;
                current.Title = f.Title;
                current.Description = f.Description;
                current.Line = f.Line;
                current.Snippet = f.Snippet;
                current.SubCategory = f.SubCategory;
                current.Purl = f.Purl;

                if (prev == FindingStatus.Accepted)
                {
                    // Untouchable — explicit "we know, accepting risk" decision.
                }
                else if (CoveredBySuppression(current.Id, current.RuleId, current.FilePath))
                {
                    current.Status = FindingStatus.Suppressed;
                    if (prev != FindingStatus.Suppressed) suppressed++;
                }
                else
                {
                    // No active suppression covers it — it's Open.
                    // Note: this also handles Suppression-expired (was
                    // Suppressed, no longer covered → Open) and Fixed-reappeared
                    // (was Fixed, now seen again → Open).
                    current.Status = FindingStatus.Open;
                    if (prev is FindingStatus.Fixed or FindingStatus.Suppressed) reopened++;
                }
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
                queued.SubCategory = f.SubCategory;
                queued.Purl = f.Purl;
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
                    SubCategory = f.SubCategory,
                    Purl = f.Purl,
                    FirstSeen = now,
                    LastSeen = now,
                };
                if (CoveredBySuppression(null, f.RuleId, f.FilePath))
                {
                    finding.Status = FindingStatus.Suppressed;
                    suppressed++;
                }
                db.Findings.Add(finding);
                pendingInsert[hash] = finding;
                inserted++;
            }
        }

        // TFND-155: an empty findings batch only auto-closes prior Open findings
        // when a scan-run receipt shows the scanner actually SUCCEEDED. Without
        // that corroboration an empty post — accidental, or forged by someone
        // holding the ingest token — would silently retire real findings. A
        // non-empty batch is itself proof the scanner ran. (Clean runs must post
        // the scan-run receipt before/with the empty findings batch.)
        var scannerRan = req.Findings.Count > 0
            || await db.ScanRunReceipts.AsNoTracking().AnyAsync(
                r => r.ComponentVersionId == version.Id
                  && r.Scanner == req.Scanner
                  && r.Status == ScanRunStatus.Succeeded, ct);

        // TFND-162: an untrusted contributor's token may add findings but never
        // auto-close existing ones — it cannot make findings disappear by
        // omitting them, so it cannot silently produce a clean result.
        var untrusted = token?.Untrusted ?? false;

        // Auto-close: any existing Open finding for this (componentVersion,
        // scanner) whose hash wasn't in the incoming batch is now Fixed.
        // LastSeen is left untouched so consumers can see when it last
        // appeared. Suppressed/Accepted are deliberately skipped — their
        // status carries human intent we don't auto-override here.
        foreach (var (hash, current) in existing)
        {
            if (current.Status == FindingStatus.Open && !incomingHashes.Contains(hash))
            {
                // Fail-safe: don't close a finding without corroboration the
                // scanner ran (TFND-155), and never on an untrusted token (TFND-162).
                if (!scannerRan || untrusted) continue;
                current.Status = FindingStatus.Fixed;
                closed++;
            }
        }

        // TFND-158 + TFND-161: per-ingest audit, in the same transaction as the
        // findings write so the trail can never diverge from what was stored,
        // attributed to the token's minting user (identity-bound ingest). The
        // auto-close count is called out because an empty/partial batch can
        // silently retire real findings.
        var flavorPart = string.IsNullOrWhiteSpace(req.Flavor) ? "" : $"/{req.Flavor}";
        var shaPart = string.IsNullOrWhiteSpace(req.CommitSha) ? "" : $" ({req.CommitSha})";
        var actorLogin = await db.Users.AsNoTracking()
            .Where(u => u.Id == token!.CreatedByUserId).Select(u => u.Login).FirstOrDefaultAsync(ct);
        audit.RecordIngest(token!.Id, token.Name, actorLogin is null ? null : token.CreatedByUserId, actorLogin,
            AuditActions.IngestReceived,
            new ScopeTarget(client!.Id, project!.Id, version!.ComponentId),
            $"{req.Scanner}: {inserted} new, {updated} updated, {reopened} reopened, " +
            $"{closed} auto-closed, {suppressed} suppressed — {req.Component}{flavorPart}@{req.Version}{shaPart}"
            + (untrusted ? " [untrusted contributor — auto-close suppressed]" : ""));

        await db.SaveChangesAsync(ct);
        // TFND-16: dependency scanners report CVEs as findings, while Grype
        // reports them as Vulnerability rows through the SBOM path. Reconciling
        // here gives each (component, advisory) pair one source of truth
        // instead of a count that depends on which scanner happened to see it.
        //
        // Runs on BOTH ingest paths because the order is not guaranteed — this
        // batch may arrive before the SBOM that gives it something to attach to.
        var reconciled = await reconciler.ReconcileAsync([version.Id], ct);

        // TFND-23: tell GitHub what this build's gates say. Queued rather than
        // awaited — the findings are stored, and an ingest must not fail
        // because api.github.com was slow.
        if (version.CommitSha is { Length: > 0 } sha)
        {
            checks.Enqueue(await ProjectIdForAsync(db, version.Id, ct), sha);
        }

        // TFND-176: freeze this build's score now that its evidence (findings + reconciled CVEs)
        // is stored, so the portfolio/history trends read it back instead of re-scoring on view.
        await snapshots.RecordForBuildAsync(version.Id, ct);

        return Results.Ok(new IngestResponse(
            version.Id, inserted, updated, reopened, closed, suppressed,
            reconciled.Attached, reconciled.Unattached));
    }

    /// <summary>
    /// Which project a component version belongs to (TFND-23).
    ///
    /// The check publisher needs the project because a project is what carries
    /// the GitHub repository mapping — a commit sha says nothing about which
    /// repository it came from, and the same sha exists in every fork.
    /// </summary>
    private static async Task<Guid> ProjectIdForAsync(
        FindingsDbContext db, Guid componentVersionId, CancellationToken ct) =>
        await db.ComponentVersions.AsNoTracking()
            .Where(v => v.Id == componentVersionId)
            .Select(v => v.ProjectId)
            .SingleAsync(ct);
}
