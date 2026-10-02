using Microsoft.EntityFrameworkCore;
using Tamp.Findings.Api.Authentication;
using Tamp.Findings.Api.Contracts;
using Tamp.Findings.Application.Auditing;
using Tamp.Findings.Application.Authorization;
using Tamp.Findings.Application.Projects;
using Tamp.Findings.Data;
using Tamp.Findings.Domain.Entities;
using Tamp.Findings.Domain.Risk;
using Tamp.Findings.Domain.Values;

namespace Tamp.Findings.Api.Endpoints;

// Producer-reported control posture (TFND-212). The producer states what it observed about a repo/org
// setting; findings owns which checks exist, which gate each feeds and which controls it evidences. The
// latest observation per (project, check) is the current posture; a stale one is treated as unassessed by
// the gate. Replace-on-ingest, so re-posting the full set is the normal producer pattern.
public static class PostureIngestEndpoints
{
    public static IEndpointRouteBuilder MapPostureIngest(this IEndpointRouteBuilder app)
    {
        app.MapPost("/ingest/posture", IngestAsync)
           .WithName("IngestPosture")
           .WithTags("Ingest")
           .WithSummary("Report repo/org control posture (branch protection, PR reviews, signed commits, org 2FA, CODEOWNERS) for a project. Check ids are defined by findings. Requires Authorization: Bearer cli_… or prj_…")
           .AllowAnonymous()
           .AddEndpointFilter<IngestAuthFilter>();
        return app;
    }

    private static async Task<IResult> IngestAsync(
        PostureIngestRequest req, HttpContext ctx, FindingsDbContext db, AuditLog audit,
        BuildUpdateNotifier notifier, CancellationToken ct)
    {
        if (string.IsNullOrWhiteSpace(req.Client)) return Results.BadRequest("client required");
        if (string.IsNullOrWhiteSpace(req.Project)) return Results.BadRequest("project required");
        if (req.Observations is null || req.Observations.Count == 0) return Results.BadRequest("observations required");

        // Validate the whole batch before writing any of it: the check set is findings-defined, so an
        // unknown id or status is a producer bug to surface, not something to drop silently.
        var parsed = new List<(PostureCheck Check, PostureStatus Status, PostureObservationDto Dto)>();
        var errors = new List<string>();
        foreach (var o in req.Observations)
        {
            var check = PostureChecks.ById(o.CheckId ?? "");
            if (check is null) { errors.Add($"unknown checkId '{o.CheckId}'"); continue; }
            var status = (o.Status ?? "").Trim().ToLowerInvariant() switch
            {
                "pass" or "passed" or "ok" => PostureStatus.Pass,
                "fail" or "failed" => PostureStatus.Fail,
                "not-applicable" or "na" or "n/a" => PostureStatus.NotApplicable,
                "unknown" => PostureStatus.Unknown,
                _ => (PostureStatus?)null,
            };
            if (status is null) { errors.Add($"checkId '{check.Id}': status must be pass, fail, not-applicable or unknown"); continue; }
            parsed.Add((check, status.Value, o));
        }
        if (errors.Count > 0)
            return Results.BadRequest(new { error = "invalid observations", details = errors, knownChecks = PostureChecks.All.Select(c => c.Id) });

        var token = IngestAuthFilter.CurrentToken(ctx);
        var (client, project, scopeErr) = await IngestScopeGuard.ResolveAndGuardAsync(db, token, req.Client, req.Project, ct);
        if (scopeErr is not null) return scopeErr;

        var existing = await db.PostureObservations.Where(o => o.ProjectId == project!.Id).ToListAsync(ct);
        int created = 0, updated = 0;
        var now = DateTimeOffset.UtcNow;
        foreach (var (check, status, dto) in parsed)
        {
            var row = existing.FirstOrDefault(o => string.Equals(o.CheckId, check.Id, StringComparison.OrdinalIgnoreCase));
            if (row is null)
            {
                row = new PostureObservation { ProjectId = project!.Id, CheckId = check.Id };
                db.PostureObservations.Add(row);
                existing.Add(row);
                created++;
            }
            else updated++;
            row.Status = status;
            row.Detail = Truncate(dto.Detail, 512);
            row.Source = Truncate(req.Source, 128);
            // The producer's own clock, but never from the future: a far-future timestamp must not keep a
            // stale observation looking fresh forever.
            row.ObservedAt = dto.ObservedAt is { } t && t <= now ? t : now;
            row.IngestedAt = now;
        }

        if (token is not null)
        {
            var login = await db.Users.AsNoTracking().Where(u => u.Id == token.CreatedByUserId)
                .Select(u => u.Login).FirstOrDefaultAsync(ct);
            audit.RecordIngest(token.Id, token.Name, login is null ? null : token.CreatedByUserId, login,
                AuditActions.IngestReceived, new ScopeTarget(project!.ClientId, project.Id),
                $"posture: {parsed.Count} checks — {req.Project}");
        }

        await db.SaveChangesAsync(ct);
        notifier.Publish(project!.Id);   // open views re-load so the gate rail reflects the new posture
        return Results.Ok(new PostureIngestResponse(project.Id, parsed.Count, created, updated));
    }

    private static string? Truncate(string? s, int max) =>
        string.IsNullOrWhiteSpace(s) ? null : (s.Length <= max ? s : s[..max]);
}
