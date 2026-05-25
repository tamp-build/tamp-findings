using System.Text.Json;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Tamp.Findings.Api.Authentication;
using Tamp.Findings.Data;

namespace Tamp.Findings.Api.Endpoints;

// TFND-29 phase 1: attach a SLSA / in-toto / DSSE-wrapped provenance
// attestation to an existing SbomSnapshot. CI pushes after building
// the SBOM, e.g. via cosign attest or slsa-github-generator.
//
// Storage is opaque — we don't crack open DSSE envelopes here. The
// SSDF attestation surface only needs to know "is there a payload"
// and what _type/predicateType it claims to be.
public static class SbomProvenanceEndpoints
{
    public static IEndpointRouteBuilder MapSbomProvenance(this IEndpointRouteBuilder app)
    {
        // Ingest-token gated (cli_ or prj_), same posture as the SBOM
        // ingest itself — provenance pairs with a build, so CI auth
        // is the right shape.
        var g = app.MapGroup("/ingest").AddEndpointFilter<IngestAuthFilter>().AllowAnonymous();
        g.MapPost("/sbom-snapshots/{snapshotId:guid}/provenance", IngestAsync)
         .WithName("IngestSbomProvenance")
         .WithTags("Ingest")
         .WithSummary("Attach a SLSA / in-toto / DSSE provenance attestation to an existing SBOM snapshot.");

        // Read path is cookie-gated alongside the other dashboard endpoints.
        app.MapGet("/sbom-snapshots/{snapshotId:guid}/provenance", GetAsync)
           .WithTags("SBOM")
           .WithSummary("Read the provenance attestation attached to an SBOM snapshot. Empty when none on file.");
        return app;
    }

    private static async Task<IResult> IngestAsync(
        Guid snapshotId,
        HttpRequest httpReq,
        FindingsDbContext db,
        CancellationToken ct)
    {
        var snap = await db.SbomSnapshots.FirstOrDefaultAsync(s => s.Id == snapshotId, ct);
        if (snap is null) return Results.NotFound("snapshot not found");

        JsonDocument doc;
        try { doc = await JsonDocument.ParseAsync(httpReq.Body, cancellationToken: ct); }
        catch (JsonException ex) { return Results.BadRequest("invalid JSON: " + ex.Message); }

        using (doc)
        {
            // Identify type. Three common shapes:
            //   1. DSSE envelope:    { "payloadType": "...", "payload": "<base64>", "signatures": [...] }
            //   2. in-toto Statement:{ "_type": "https://in-toto.io/Statement/v1", "predicateType": "...", ... }
            //   3. SLSA Provenance:  { "predicateType": "https://slsa.dev/provenance/v1", ... }
            // We just pull the most-specific identifier we can find.
            var root = doc.RootElement;
            string? type = null;
            if (root.TryGetProperty("payloadType", out var pt) && pt.ValueKind == JsonValueKind.String)
                type = pt.GetString();
            if (string.IsNullOrEmpty(type) && root.TryGetProperty("predicateType", out var prt) && prt.ValueKind == JsonValueKind.String)
                type = prt.GetString();
            if (string.IsNullOrEmpty(type) && root.TryGetProperty("_type", out var t) && t.ValueKind == JsonValueKind.String)
                type = t.GetString();
            type ??= "unknown";

            // Materialise the root element into a Dictionary so Npgsql's
            // jsonb mapper round-trips cleanly. (We could persist the raw
            // string, but jsonb gives us indexability + cheap re-emit.)
            snap.ProvenanceJson = JsonSerializer.Deserialize<Dictionary<string, object?>>(root.GetRawText());
            snap.ProvenanceType = type;
            snap.ProvenanceUploadedAt = DateTimeOffset.UtcNow;
            await db.SaveChangesAsync(ct);
        }
        return Results.Ok(new
        {
            snapshotId,
            provenanceType = snap.ProvenanceType,
            uploadedAt = snap.ProvenanceUploadedAt,
        });
    }

    private static async Task<IResult> GetAsync(
        Guid snapshotId,
        FindingsDbContext db,
        CancellationToken ct)
    {
        var snap = await db.SbomSnapshots.AsNoTracking()
            .Where(s => s.Id == snapshotId)
            .Select(s => new { s.Id, s.ProvenanceJson, s.ProvenanceType, s.ProvenanceUploadedAt })
            .FirstOrDefaultAsync(ct);
        if (snap is null) return Results.NotFound();
        return Results.Ok(new
        {
            snapshotId = snap.Id,
            provenanceType = snap.ProvenanceType,
            uploadedAt = snap.ProvenanceUploadedAt,
            payload = snap.ProvenanceJson,
        });
    }
}
