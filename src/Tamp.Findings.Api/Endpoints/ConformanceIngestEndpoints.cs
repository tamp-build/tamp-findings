using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using Tamp.Findings.Api.Authentication;
using Tamp.Findings.Application.Auditing;
using Tamp.Findings.Application.Authorization;
using Tamp.Findings.Application.Compliance;
using Tamp.Findings.Data;
using Tamp.Findings.Domain.Entities;

namespace Tamp.Findings.Api.Endpoints;

// TFND: ADR-conformance evidence ingest (ADR 0006, core ADR 0023). tamp.findings
// is the SINK — the tamp-conformance producer POSTs the canonical BuildEvent
// stream here and we keep the conformance.evaluated events. Transport is
// findings-owned (0023 defines only the event shape); the shape is matched
// byte-for-byte. Auth mirrors /ingest/findings (cli_/prj_ Bearer).
public static class ConformanceIngestEndpoints
{
    private static readonly JsonSerializerOptions Json = new(JsonSerializerDefaults.Web);

    public static IEndpointRouteBuilder MapConformanceIngest(this IEndpointRouteBuilder app)
    {
        app.MapPost("/ingest/conformance", IngestAsync)
           .WithName("IngestConformance")
           .WithTags("Ingest")
           .WithSummary("Ingest conformance.evaluated verdicts (core ADR 0023). Accepts a JSON array or NDJSON of canonical BuildEvent envelopes; non-conformance events are ignored. Requires Authorization: Bearer cli_… or prj_… ingest token.")
           .AllowAnonymous()
           .AddEndpointFilter<IngestAuthFilter>();
        return app;
    }

    private static async Task<IResult> IngestAsync(
        HttpContext ctx,
        FindingsDbContext db,
        ConformanceIngestService ingest,
        Tamp.Findings.Application.Zt.MandatePoamReconciler mandatePoams,
        AuditLog audit,
        CancellationToken ct)
    {
        var token = IngestAuthFilter.CurrentToken(ctx);
        if (token is null) return Results.Unauthorized();

        // The token's project(s) are the only builds a verdict may bind to. A
        // project token scopes to itself; a client token to its projects.
        Guid[] candidateProjectIds = token.Scope == IngestTokenScope.Project
            ? (token.ProjectId is { } pid ? [pid] : [])
            : await db.Projects.AsNoTracking()
                .Where(p => p.ClientId == token.ClientId)
                .Select(p => p.Id).ToArrayAsync(ct);
        if (candidateProjectIds.Length == 0)
            return Results.NotFound("no project in scope for this token");

        List<ConformanceEventDto> events;
        try
        {
            events = await ReadEventsAsync(ctx.Request, ct);
        }
        catch (JsonException ex)
        {
            return Results.BadRequest($"malformed body: {ex.Message}");
        }
        if (events.Count == 0) return Results.BadRequest("no events in body");

        var result = await ingest.IngestAsync(candidateProjectIds, events, ct);

        // Wire mandate failures into the shared POA&M model (TFND-189): a failing/unproven
        // operational or supply-chain mandate becomes a dated POA&M, idempotently.
        var poamsRaised = 0;
        if (result.Accepted > 0)
            foreach (var projectId in candidateProjectIds)
                poamsRaised += (await mandatePoams.ReconcileAsync(projectId, token.CreatedByUserId, ct)).Count;

        var actorLogin = await db.Users.AsNoTracking()
            .Where(u => u.Id == token.CreatedByUserId).Select(u => u.Login).FirstOrDefaultAsync(ct);
        audit.RecordIngest(token.Id, token.Name, actorLogin is null ? null : token.CreatedByUserId, actorLogin,
            AuditActions.ConformanceIngested,
            new ScopeTarget(token.ClientId, token.Scope == IngestTokenScope.Project ? token.ProjectId : null, null),
            detail: $"conformance: {result.Accepted} accepted, {result.Skipped} skipped across {result.Builds.Count} build(s); {poamsRaised} mandate POA&M(s) raised");
        await db.SaveChangesAsync(ct);

        return Results.Ok(new ConformanceIngestResponse(result.Accepted, result.Skipped, result.Builds));
    }

    // Accept either a JSON array of BuildEvents or NDJSON (one per line). We sniff
    // the first non-whitespace byte rather than trusting Content-Type, so a
    // producer that mislabels the stream still ingests.
    private static async Task<List<ConformanceEventDto>> ReadEventsAsync(HttpRequest req, CancellationToken ct)
    {
        using var reader = new StreamReader(req.Body);
        var body = (await reader.ReadToEndAsync(ct)).Trim();
        if (body.Length == 0) return [];

        if (body[0] == '[')
            return JsonSerializer.Deserialize<List<ConformanceEventDto>>(body, Json) ?? [];

        // NDJSON: one JSON object per line, blank lines ignored.
        var list = new List<ConformanceEventDto>();
        foreach (var line in body.Split('\n'))
        {
            var trimmed = line.Trim();
            if (trimmed.Length == 0) continue;
            var ev = JsonSerializer.Deserialize<ConformanceEventDto>(trimmed, Json);
            if (ev is not null) list.Add(ev);
        }
        return list;
    }
}

public sealed record ConformanceIngestResponse(int Accepted, int Skipped, IReadOnlyList<string> Builds);
