using System.Text;
using System.Text.Json;
using Tamp.Findings.Application.Auditing;
using Tamp.Findings.Application.Authorization;
using Tamp.Findings.Application.Projects;
using Tamp.Findings.Data;
using Tamp.Findings.Domain.Values;

namespace Tamp.Findings.Application.Attestation;

/// <summary>
/// Exporting the attestation (TFND-101 / TFND-102).
///
/// Three formats, and the difference between them is who reads them: OSCAL is
/// for a machine in a FedRAMP pipeline, the PDF is for a human who signs it,
/// and the raw JSON is for this product's own schema.
///
/// Every export is audited. An attestation leaving the building is the moment
/// the evidence becomes someone's claim, and "who exported what, when" is a
/// question that gets asked afterwards.
/// </summary>
public sealed class AttestationExporter
{
    private readonly FindingsDbContext _db;
    private readonly CapabilityEvaluator _capabilities;
    private readonly AuditLog _audit;

    public AttestationExporter(FindingsDbContext db, CapabilityEvaluator capabilities, AuditLog audit)
    {
        _db = db;
        _capabilities = capabilities;
        _audit = audit;
    }

    public static readonly IReadOnlyList<FormatCard> Formats =
    [
        new(AttestationFormat.Oscal, "OSCAL",
            "NIST OSCAL 1.1.2 JSON. What a FedRAMP pipeline ingests."),
        new(AttestationFormat.Pdf, "Generated PDF",
            "Letter, with the signatory block. What someone actually signs."),
        new(AttestationFormat.Json, "Raw JSON",
            "The tamp.findings schema, including the gate evaluation and category breakdown."),
    ];

    public async Task<Result<ExportPayload>> ExportAsync(
        Principal actor, ScopeTarget scope, SsdfAttestationDoc doc,
        AttestationFormat format, OscalModel model = OscalModel.Bundle,
        CancellationToken ct = default)
    {
        var decision = _capabilities.Evaluate(actor, Capability.ExportAttestation);
        if (!decision.Allowed) return Result<ExportPayload>.Denied(decision.Reason!);

        // An attestation with no build has nothing to attest. Exporting it
        // would produce a document that looks official and says nothing, which
        // is worse than refusing.
        if (doc.Build is null)
            return Result<ExportPayload>.Invalid(
                "There is no canonical build to attest. Ingest one first.");

        var fileName = FileName(format, model, doc.Project.Name, doc.Build.CommitSha);

        var payload = format switch
        {
            AttestationFormat.Oscal => new ExportPayload(
                fileName, "application/json", Encoding.UTF8.GetBytes(OscalJson(doc, model))),
            AttestationFormat.Pdf => new ExportPayload(
                fileName, "application/pdf", PdfWriter.Render(doc)),
            _ => new ExportPayload(
                fileName, "application/json",
                Encoding.UTF8.GetBytes(JsonSerializer.Serialize(doc, JsonOptions))),
        };

        _audit.Record(actor, AuditActions.AttestationExported, AuditClass.Other, scope,
            subjectKind: nameof(SsdfAttestationDoc),
            detail: $"{format}{(format == AttestationFormat.Oscal ? $" ({model})" : "")}"
                  + $" for build {doc.Build.CommitSha ?? doc.Build.VersionString}");

        // AuditLog.Record deliberately does not save — it expects to ride along
        // with the change it describes. An export changes nothing else, so this
        // is the one place that has to commit the entry itself.
        await _db.SaveChangesAsync(ct);
        return Result<ExportPayload>.Ok(payload);
    }

    /// <summary>
    /// The exact output filename, shown in the dialog before the export runs.
    ///
    /// Shown because a reader about to attach a file to a contract package
    /// should know what it will be called, and because the name encodes the
    /// build — two exports of the same project on different commits must not
    /// collide in someone's downloads folder.
    /// </summary>
    public string FileName(AttestationFormat format, OscalModel model, string project, string? commitSha)
    {
        var slug = Slug(project);
        var build = commitSha is { Length: > 0 } sha ? sha[..Math.Min(12, sha.Length)] : "no-build";

        return format switch
        {
            AttestationFormat.Oscal => $"{slug}-{build}-oscal-{model.ToString().ToLowerInvariant()}.json",
            AttestationFormat.Pdf => $"{slug}-{build}-ssdf-attestation.pdf",
            _ => $"{slug}-{build}-attestation.json",
        };
    }

    // ---- OSCAL ------------------------------------------------------------

    /// <summary>
    /// OSCAL 1.1.2, in <see cref="OscalWriter"/>.
    ///
    /// Kept as a one-line delegation rather than folded in: FedRAMP RFC-0024
    /// makes this the format that decides whether a package gets a 30-day
    /// review or a 90-day queue, and it has grown three models and a shared
    /// UUID graph. That is a file, not a method on an exporter whose other job
    /// is picking filenames.
    /// </summary>
    internal static string OscalJson(SsdfAttestationDoc doc, OscalModel model) =>
        OscalWriter.Write(doc, model);

    /// <summary>
    /// Re-exposed for the tests that assert identifier stability across
    /// exports. The property matters more than the algorithm: a POA&amp;M
    /// submitted in March has to resolve against the assessment resubmitted in
    /// September.
    /// </summary>
    internal static string DeterministicUuid(string seed) => OscalWriter.Uuid(seed);

    private static string Slug(string name)
    {
        var slug = new string(name.Select(c => char.IsLetterOrDigit(c) ? char.ToLowerInvariant(c) : '-').ToArray());
        while (slug.Contains("--")) slug = slug.Replace("--", "-");
        return slug.Trim('-') is { Length: > 0 } trimmed ? trimmed : "project";
    }

    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        WriteIndented = true,
        // The wire shape is a contract with FedRAMP tooling; a UTF-8 em dash in
        // an evidence string must survive rather than becoming —.
        Encoder = System.Text.Encodings.Web.JavaScriptEncoder.UnsafeRelaxedJsonEscaping,
    };
}

public enum AttestationFormat { Oscal, Pdf, Json }

public enum OscalModel { AssessmentResults, Poam, Bundle }

public sealed record FormatCard(AttestationFormat Key, string Title, string Description);

/// <summary>
/// A finished export.
///
/// Bytes, not a string: a PDF is binary, and round-tripping it through a string
/// is how a file arrives on someone's disk subtly corrupted and unopenable.
/// </summary>
public sealed record ExportPayload(string FileName, string MediaType, byte[] Content);
