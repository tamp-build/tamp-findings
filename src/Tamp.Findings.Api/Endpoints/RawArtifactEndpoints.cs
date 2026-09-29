using Microsoft.EntityFrameworkCore;
using Tamp.Findings.Api.Ingest.Raw;
using Tamp.Findings.Data;

namespace Tamp.Findings.Api.Endpoints;

// Read side of the raw evidence store (TFND-209). Both endpoints key on componentVersionId so the
// shared VisibilityFilter enforces the tenant boundary; the download additionally scopes the artifact
// to that build, so an id from another tenant is a 404, not a cross-tenant read.
public static class RawArtifactEndpoints
{
    public static IEndpointRouteBuilder MapRawArtifacts(this IEndpointRouteBuilder app)
    {
        app.MapGet("/raw-artifacts", ListAsync)
           .WithName("ListRawArtifacts")
           .WithSummary("List the raw report files stored for a build (componentVersionId) — metadata only, newest first.");
        app.MapGet("/raw-artifacts/{id:guid}", DownloadAsync)
           .WithName("DownloadRawArtifact")
           .WithSummary("Download one stored raw report file (the original .trx/cobertura/opencover/junit) by id. Requires componentVersionId for the visibility boundary.");
        return app;
    }

    private static async Task<IResult> ListAsync(FindingsDbContext db, Guid componentVersionId, CancellationToken ct)
    {
        var rows = await db.RawReportArtifacts.AsNoTracking()
            .Where(a => a.ComponentVersionId == componentVersionId)
            .OrderByDescending(a => a.IngestedAt)
            .Select(a => new RawArtifactListItem(
                a.Id, a.Kind.ToString(), a.Format, a.FileName,
                a.SizeBytes, a.CompressedBytes.Length, a.Sha256, a.ToolName, a.IngestedAt))
            .ToListAsync(ct);
        return Results.Ok(rows);
    }

    private static async Task<IResult> DownloadAsync(Guid id, FindingsDbContext db, Guid componentVersionId, CancellationToken ct)
    {
        var a = await db.RawReportArtifacts.AsNoTracking()
            .FirstOrDefaultAsync(x => x.Id == id && x.ComponentVersionId == componentVersionId, ct);
        if (a is null) return Results.NotFound();
        var raw = RawArtifactStore.Gunzip(a.CompressedBytes);
        var name = a.FileName ?? $"{a.Kind}-{a.Format}.xml".ToLowerInvariant();
        return Results.File(raw, "application/xml", fileDownloadName: name);
    }
}

public sealed record RawArtifactListItem(
    Guid Id,
    string Kind,
    string Format,
    string? FileName,
    long SizeBytes,
    int CompressedBytes,
    string Sha256,
    string? ToolName,
    DateTimeOffset IngestedAt);
