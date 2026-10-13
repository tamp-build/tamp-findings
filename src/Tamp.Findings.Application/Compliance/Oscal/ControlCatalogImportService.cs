using Microsoft.EntityFrameworkCore;
using Tamp.Findings.Application.Auditing;
using Tamp.Findings.Application.Authorization;
using Tamp.Findings.Application.Projects;
using Tamp.Findings.Data;
using Tamp.Findings.Domain.Compliance;
using Tamp.Findings.Domain.Entities;
using Tamp.Findings.Domain.Values;

namespace Tamp.Findings.Application.Compliance.Oscal;

/// <summary>What an import did, so the caller can report it instead of saying "ok".</summary>
public sealed record CatalogImportOutcome(
    string Name,
    string Version,
    string? OscalVersion,
    string Sha,
    int Controls,
    int Parameters,
    int Low,
    int Moderate,
    int High,
    /// <summary>
    /// True when the uploaded catalog is byte-identical to the current one and nothing
    /// was written. Reported rather than silently treated as success: an operator who
    /// has just uploaded a file to fix something needs to know it changed nothing.
    /// </summary>
    bool Unchanged);

/// <summary>
/// Importing a control catalog, and the ONE place that decides how a catalog becomes
/// the current one (TFND-180, v3 §6).
///
/// Two callers, deliberately sharing this: startup ingests the catalog that ships in
/// Content/oscal, and an operator uploads one. They need identical behaviour —
/// idempotent by content hash, retire-then-add, prior versions retained — and when
/// that logic lived inline in Program.cs there was nowhere for the second caller to
/// get it. The upload path existed only as two disabled buttons promising this ticket.
///
/// Why retain prior catalogs: an attestation cites the catalog version it was signed
/// against, so deleting an old catalog would make a signed attestation unreproducible.
/// Importing is additive; only IsCurrent moves.
/// </summary>
public sealed class ControlCatalogImportService(
    FindingsDbContext db,
    OscalImportService oscal,
    CapabilityEvaluator capabilities,
    AuditLog audit)
{
    /// <summary>
    /// Refuse anything larger than this. The import buffers the whole upload in memory —
    /// it has to hash it and parse it — so an unbounded upload would be an easy way to
    /// exhaust a server, and the cap is what stops that.
    ///
    /// The number is sized on the real artifact, not picked round: the NIST 800-53 Rev 5
    /// catalog that ships in Content/oscal is ~10.4 MB, and this is a little over twice
    /// that. It started at 64 MB, which was generosity with nothing behind it; every byte
    /// of headroom above what a real catalog needs is memory an administrator can make
    /// the server allocate for no reason.
    ///
    /// Sonar's S5693 fires on any limit above its 8 MB default and will keep firing here:
    /// the catalog this product exists to import is larger than that default, so the rule
    /// cannot be satisfied by lowering the number. Streaming to a temp file would move
    /// the bound from memory to disk and make the rule moot — worth doing if catalogs ever
    /// get much bigger, not worth the temp-file lifecycle for 10 MB behind an
    /// instance-administrator capability.
    /// </summary>
    public const long MaxBytes = 24L * 1024 * 1024;

    /// <summary>
    /// Import a catalog an operator supplied. Needs EditPolicyWeights at the instance —
    /// the same authority that applies a policy pack, because both replace instance-wide
    /// reference content that every client and project resolves against.
    /// </summary>
    public async Task<Result<CatalogImportOutcome>> ImportAsync(
        Principal actor,
        Stream catalog,
        IReadOnlyDictionary<BaselineLevel, Stream> profiles,
        string source,
        CancellationToken ct = default)
    {
        var decision = capabilities.Evaluate(actor, Capability.EditPolicyWeights);
        if (!decision.Allowed) return Result<CatalogImportOutcome>.Denied(decision.Reason!);

        return await RunAsync(actor, catalog, profiles, source, ct);
    }

    /// <summary>
    /// Import the catalog that ships with the product, at startup. No actor and no
    /// capability check, because there is no operator in the loop — and no audit row for
    /// the same reason: AuditEntry records who did something, and inventing a principal
    /// to satisfy it would put a fiction in the audit log. A deploy-time import is
    /// evidenced by the catalog row's own Source and ImportedAt.
    /// </summary>
    public Task<Result<CatalogImportOutcome>> ImportShippedAsync(
        Stream catalog,
        IReadOnlyDictionary<BaselineLevel, Stream> profiles,
        string source,
        CancellationToken ct = default) =>
        RunAsync(actor: null, catalog, profiles, source, ct);

    private async Task<Result<CatalogImportOutcome>> RunAsync(
        Principal? actor,
        Stream catalog,
        IReadOnlyDictionary<BaselineLevel, Stream> profiles,
        string source,
        CancellationToken ct)
    {
        // Buffered because the content has to be hashed AND parsed, and a request body
        // is forward-only. Capped above.
        var bytes = await ReadCappedAsync(catalog, ct);
        if (bytes is null)
        {
            return Result<CatalogImportOutcome>.Invalid(
                $"That file is larger than the {MaxBytes / (1024 * 1024)} MB limit.");
        }
        if (bytes.Length == 0) return Result<CatalogImportOutcome>.Invalid("That file is empty.");

        var sha = Convert.ToHexString(System.Security.Cryptography.SHA256.HashData(bytes));
        var current = await db.ControlCatalogs.FirstOrDefaultAsync(c => c.IsCurrent, ct);

        if (current?.ImportedSha == sha)
        {
            return Result<CatalogImportOutcome>.Ok(Describe(current, sha, unchanged: true));
        }

        ControlCatalog built;
        try
        {
            using var stream = new MemoryStream(bytes, writable: false);
            built = oscal.BuildCatalog(stream, profiles, source, sha);
        }
        catch (Exception ex) when (ex is System.Text.Json.JsonException or InvalidDataException)
        {
            // The parser's complaint is more useful than "import failed", and an operator
            // who has just picked the wrong file needs to be told which thing it was not.
            return Result<CatalogImportOutcome>.Invalid(
                $"That does not read as an OSCAL catalog: {ex.Message}");
        }

        if (built.Controls.Count == 0)
        {
            // A catalog with no controls would parse, replace the current one, and quietly
            // empty every framework and control-coverage view on the instance.
            return Result<CatalogImportOutcome>.Invalid(
                "That catalog contains no controls, so importing it would empty every framework.");
        }

        // Retire first and save: the partial unique index permits only one IsCurrent, and
        // the insert of the new row may be ordered before the update of the old one.
        if (current is not null)
        {
            current.IsCurrent = false;
            await db.SaveChangesAsync(ct);
        }

        db.ControlCatalogs.Add(built);

        var outcome = Describe(built, sha, unchanged: false);
        if (actor is not null)
        {
            audit.Record(actor, "controlcatalog.imported", AuditClass.Other, ScopeTarget.Instance,
                subjectId: built.Id, subjectKind: nameof(ControlCatalog),
                detail: $"{outcome.Name} · {outcome.Controls} controls · {outcome.Parameters} parameters · sha {sha[..12]} · {source}");
        }

        await db.SaveChangesAsync(ct);
        return Result<CatalogImportOutcome>.Ok(outcome);
    }

    private static CatalogImportOutcome Describe(ControlCatalog c, string sha, bool unchanged) =>
        new(c.Name,
            c.Version,
            c.OscalVersion,
            sha,
            c.Controls.Count,
            c.Controls.Sum(x => ControlStatementParser.CountParameters(x.StatementLines)),
            c.Controls.Count(x => x.InBaseline(BaselineLevel.Low)),
            c.Controls.Count(x => x.InBaseline(BaselineLevel.Moderate)),
            c.Controls.Count(x => x.InBaseline(BaselineLevel.High)),
            unchanged);

    /// <summary>Read the whole stream, or null if it exceeds <see cref="MaxBytes"/>.</summary>
    private static async Task<byte[]?> ReadCappedAsync(Stream source, CancellationToken ct)
    {
        using var buffer = new MemoryStream();
        var chunk = new byte[81920];
        int read;
        while ((read = await source.ReadAsync(chunk, ct)) > 0)
        {
            if (buffer.Length + read > MaxBytes) return null;
            buffer.Write(chunk, 0, read);
        }
        return buffer.ToArray();
    }
}
