using Microsoft.EntityFrameworkCore;
using Tamp.Findings.Application.Auditing;
using Tamp.Findings.Application.Authorization;
using Tamp.Findings.Data;
using Tamp.Findings.Domain.Entities;

namespace Tamp.Findings.Api.Endpoints;

// TFND-158: per-ingest audit for the ingest endpoints that resolve only a
// ComponentVersion (or a snapshot) and discard the client/project during scope
// resolution. Derives the full client/project/component scope from the version
// so the trail is filterable by tenant, and adds the entry to the context —
// the caller persists it in its own SaveChangesAsync.
//
// The /ingest/findings path does not use this: it keeps client + project local
// and records inline, avoiding the extra projection on the hottest path.
internal static class IngestAudit
{
    public static async Task RecordAsync(
        AuditLog audit, FindingsDbContext db, IngestToken? token,
        Guid componentVersionId, string detail, CancellationToken ct)
    {
        // The route was authenticated by IngestAuthFilter, so a null token here
        // is not expected; guard defensively rather than throw on the hot path.
        if (token is null) return;

        var scope = await db.ComponentVersions.AsNoTracking()
            .Where(v => v.Id == componentVersionId)
            .Select(v => new { v.ComponentId, v.Component!.ProjectId, v.Component.Project!.ClientId })
            .FirstOrDefaultAsync(ct);

        var target = scope is null
            ? default
            : new ScopeTarget(scope.ClientId, scope.ProjectId, scope.ComponentId);

        // TFND-161: attribute the ingest to the token's minting user.
        var login = await LoginForAsync(db, token, ct);
        audit.RecordIngest(token.Id, token.Name, login is null ? null : token.CreatedByUserId, login,
            AuditActions.IngestReceived, target, detail);
    }

    // Snapshot-addressed ingest (provenance, sbom-vulnerabilities): resolve the
    // snapshot's ComponentVersion, then record against its scope.
    public static async Task RecordForSnapshotAsync(
        AuditLog audit, FindingsDbContext db, IngestToken? token,
        Guid snapshotId, string detail, CancellationToken ct)
    {
        if (token is null) return;

        var cvId = await db.SbomSnapshots.AsNoTracking()
            .Where(s => s.Id == snapshotId)
            .Select(s => (Guid?)s.ComponentVersionId)
            .FirstOrDefaultAsync(ct);

        if (cvId is null)
        {
            var login = await LoginForAsync(db, token, ct);
            audit.RecordIngest(token.Id, token.Name, login is null ? null : token.CreatedByUserId, login,
                AuditActions.IngestReceived, default, detail);
            return;
        }

        await RecordAsync(audit, db, token, cvId.Value, detail, ct);
    }

    // The login of the user who minted the token — the contributor the ingest
    // is attributed to (TFND-161). Null when that user no longer exists.
    private static async Task<string?> LoginForAsync(FindingsDbContext db, IngestToken token, CancellationToken ct) =>
        await db.Users.AsNoTracking()
            .Where(u => u.Id == token.CreatedByUserId)
            .Select(u => u.Login)
            .FirstOrDefaultAsync(ct);
}
