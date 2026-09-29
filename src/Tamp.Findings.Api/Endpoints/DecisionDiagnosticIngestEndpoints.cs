using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using Tamp.Findings.Api.Authentication;
using Tamp.Findings.Application.Auditing;
using Tamp.Findings.Application.Authorization;
using Tamp.Findings.Application.Compliance;
using Tamp.Findings.Data;
using Tamp.Findings.Domain.Entities;

namespace Tamp.Findings.Api.Endpoints;

// Reverse-examination advisory ingest (ADR 0013). tamp-conformance's reverse-examination emits
// diagnostic.emitted notes (ruleId undocumented-decision:<kind>) for decisions the code made
// that no ADR records — a CM-3 change-control drift signal. tamp.findings is the SINK; a
// distinct endpoint from /ingest/conformance so the advisory counts never muddy the conformance
// verdict counts. Advisory-only: nothing ingested here ever gates. Auth mirrors /ingest/conformance.
public static class DecisionDiagnosticIngestEndpoints
{
    private static readonly JsonSerializerOptions Json = new(JsonSerializerDefaults.Web);

    public static IEndpointRouteBuilder MapDecisionDiagnosticIngest(this IEndpointRouteBuilder app)
    {
        app.MapPost("/ingest/diagnostics", IngestAsync)
           .WithName("IngestDiagnostics")
           .WithTags("Ingest")
           .WithSummary("Ingest reverse-examination advisories (ADR 0013): diagnostic.emitted notes with ruleId undocumented-decision:<kind>. Accepts a JSON array or NDJSON of canonical BuildEvent envelopes; other events are ignored. Advisory-only — never gates. Requires Authorization: Bearer cli_… or prj_… ingest token.")
           .AllowAnonymous()
           .AddEndpointFilter<IngestAuthFilter>();
        return app;
    }

    private static async Task<IResult> IngestAsync(
        HttpContext ctx,
        FindingsDbContext db,
        DecisionDiagnosticIngestService ingest,
        AuditLog audit,
        CancellationToken ct)
    {
        var token = IngestAuthFilter.CurrentToken(ctx);
        if (token is null) return Results.Unauthorized();

        Guid[] candidateProjectIds = token.Scope == IngestTokenScope.Project
            ? (token.ProjectId is { } pid ? [pid] : [])
            : await db.Projects.AsNoTracking()
                .Where(p => p.ClientId == token.ClientId)
                .Select(p => p.Id).ToArrayAsync(ct);
        if (candidateProjectIds.Length == 0)
            return Results.NotFound("no project in scope for this token");

        List<DiagnosticEventDto> events;
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

        var actorLogin = await db.Users.AsNoTracking()
            .Where(u => u.Id == token.CreatedByUserId).Select(u => u.Login).FirstOrDefaultAsync(ct);
        audit.RecordIngest(token.Id, token.Name, actorLogin is null ? null : token.CreatedByUserId, actorLogin,
            AuditActions.DiagnosticsIngested,
            new ScopeTarget(token.ClientId, token.Scope == IngestTokenScope.Project ? token.ProjectId : null, null),
            detail: $"decision advisories: {result.Accepted} accepted, {result.Skipped} skipped across {result.Builds.Count} build(s)");
        await db.SaveChangesAsync(ct);

        return Results.Ok(new DiagnosticIngestResponse(result.Accepted, result.Skipped, result.Builds));
    }

    // Accept either a JSON array of BuildEvents or NDJSON (one per line), sniffing the first
    // non-whitespace byte rather than trusting Content-Type — same discipline as /ingest/conformance.
    private static async Task<List<DiagnosticEventDto>> ReadEventsAsync(HttpRequest req, CancellationToken ct)
    {
        using var reader = new StreamReader(req.Body);
        var body = (await reader.ReadToEndAsync(ct)).Trim();
        if (body.Length == 0) return [];

        if (body[0] == '[')
            return JsonSerializer.Deserialize<List<DiagnosticEventDto>>(body, Json) ?? [];

        var list = new List<DiagnosticEventDto>();
        foreach (var line in body.Split('\n'))
        {
            var trimmed = line.Trim();
            if (trimmed.Length == 0) continue;
            var ev = JsonSerializer.Deserialize<DiagnosticEventDto>(trimmed, Json);
            if (ev is not null) list.Add(ev);
        }
        return list;
    }
}

public sealed record DiagnosticIngestResponse(int Accepted, int Skipped, IReadOnlyList<string> Builds);
