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
    /// OSCAL 1.1.2. Assessment results, POA&amp;M, or a bundle of both.
    ///
    /// The bundle shares UUIDs across the two models on purpose: OSCAL POA&amp;M
    /// items reference the findings an assessment cites, and emitting the two
    /// models separately produces documents whose cross-references do not
    /// resolve. That reads as a valid package right up until an assessor's
    /// tooling tries to follow one.
    /// </summary>
    internal static string OscalJson(SsdfAttestationDoc doc, OscalModel model)
    {
        // Deterministic UUIDs derived from the document's own identity, so
        // re-exporting the same build twice produces the same references
        // rather than a package that looks like a different assessment.
        var root = DeterministicUuid($"{doc.Project.Id}:{doc.Build?.CommitSha}");

        var metadata = new Dictionary<string, object?>
        {
            ["title"] = $"SSDF attestation — {doc.Project.Name}",
            ["last-modified"] = doc.Generated,
            ["version"] = doc.Build?.VersionString ?? "0",
            ["oscal-version"] = "1.1.2",
            ["props"] = new object[]
            {
                new Dictionary<string, object?> { ["name"] = "commit", ["value"] = doc.Build?.CommitSha ?? "" },
                new Dictionary<string, object?> { ["name"] = "risk-score", ["value"] = doc.Risk?.Score.ToString("0.0") ?? "" },
                new Dictionary<string, object?> { ["name"] = "risk-policy", ["value"] = doc.Risk?.PolicyName ?? "" },
            },
        };

        // One observation per practice. The Manual ones are included, marked as
        // such: an assessment that silently omitted them would understate how
        // much of the attestation rests on the signatory rather than on
        // measurement.
        var observations = doc.Practices.Select((p, i) => new Dictionary<string, object?>
        {
            ["uuid"] = DeterministicUuid($"{root}:obs:{p.Id}"),
            ["title"] = $"{p.Id} — {p.Label}",
            ["description"] = p.Intent,
            ["methods"] = new[] { p.Status == "Manual" ? "INTERVIEW" : "TEST" },
            ["collected"] = doc.Generated,
            ["props"] = new object[]
            {
                new Dictionary<string, object?> { ["name"] = "ssdf-practice", ["value"] = p.Id },
                new Dictionary<string, object?> { ["name"] = "attestation-status", ["value"] = p.Status },
            },
            ["remarks"] = p.Evidence,
        }).ToArray();

        // Findings: only the practices automated evidence CONTRADICTS. A
        // Partial is not a finding — it is an incomplete measurement — and a
        // Manual is not a finding either.
        var findings = doc.Practices
            .Where(p => p.Status == "No")
            .Select(p => new Dictionary<string, object?>
            {
                ["uuid"] = DeterministicUuid($"{root}:finding:{p.Id}"),
                ["title"] = $"{p.Id} not satisfied",
                ["description"] = p.Evidence,
                ["target"] = new Dictionary<string, object?>
                {
                    ["type"] = "objective-id",
                    ["target-id"] = p.Id,
                    ["status"] = new Dictionary<string, object?> { ["state"] = "not-satisfied" },
                },
                ["related-observations"] = new object[]
                {
                    new Dictionary<string, object?>
                    {
                        ["observation-uuid"] = DeterministicUuid($"{root}:obs:{p.Id}"),
                    },
                },
            })
            .ToArray();

        var assessment = new Dictionary<string, object?>
        {
            ["uuid"] = root,
            ["metadata"] = metadata,
            ["import-ap"] = new Dictionary<string, object?> { ["href"] = "#ssdf-800-218" },
            ["results"] = new object[]
            {
                new Dictionary<string, object?>
                {
                    ["uuid"] = DeterministicUuid($"{root}:result"),
                    ["title"] = "Automated evidence",
                    ["description"] = doc.Summary.Headline,
                    ["start"] = doc.Generated,
                    ["reviewed-controls"] = new Dictionary<string, object?>
                    {
                        ["control-selections"] = new object[]
                        {
                            new Dictionary<string, object?> { ["include-all"] = new Dictionary<string, object?>() },
                        },
                    },
                    ["observations"] = observations,
                    ["findings"] = findings,
                },
            },
        };

        var poam = new Dictionary<string, object?>
        {
            ["uuid"] = DeterministicUuid($"{root}:poam"),
            ["metadata"] = metadata,
            // Points at the assessment above. In a bundle this resolves; in a
            // standalone POA&M export the consumer supplies the counterpart.
            ["import-ssp"] = new Dictionary<string, object?> { ["href"] = $"#{root}" },
            ["poam-items"] = doc.Practices
                .Where(p => p.Status is "No" or "Partial")
                .Select(p => new Dictionary<string, object?>
                {
                    ["uuid"] = DeterministicUuid($"{root}:poam-item:{p.Id}"),
                    ["title"] = $"{p.Id} — {p.Label}",
                    ["description"] = p.Evidence,
                    ["related-findings"] = p.Status == "No"
                        ? new object[]
                        {
                            new Dictionary<string, object?>
                            {
                                ["finding-uuid"] = DeterministicUuid($"{root}:finding:{p.Id}"),
                            },
                        }
                        : Array.Empty<object>(),
                    ["related-observations"] = new object[]
                    {
                        new Dictionary<string, object?>
                        {
                            ["observation-uuid"] = DeterministicUuid($"{root}:obs:{p.Id}"),
                        },
                    },
                })
                .ToArray(),
        };

        object payload = model switch
        {
            OscalModel.AssessmentResults => new Dictionary<string, object?> { ["assessment-results"] = assessment },
            OscalModel.Poam => new Dictionary<string, object?> { ["plan-of-action-and-milestones"] = poam },
            _ => new Dictionary<string, object?>
            {
                ["assessment-results"] = assessment,
                ["plan-of-action-and-milestones"] = poam,
            },
        };

        return JsonSerializer.Serialize(payload, JsonOptions);
    }

    /// <summary>
    /// A UUID derived from the seed rather than drawn at random.
    ///
    /// Re-exporting the same build must produce the same identifiers, or every
    /// export looks to a downstream tool like a brand new assessment of the
    /// same software.
    /// </summary>
    internal static string DeterministicUuid(string seed)
    {
        var hash = System.Security.Cryptography.SHA256.HashData(Encoding.UTF8.GetBytes(seed));
        var bytes = hash.AsSpan(0, 16).ToArray();

        // Stamp version 8 (RFC 9562, name-based custom) and the RFC 4122
        // variant, so the value is a well-formed UUID rather than 16 bytes
        // wearing a UUID's shape.
        bytes[6] = (byte)((bytes[6] & 0x0F) | 0x80);
        bytes[8] = (byte)((bytes[8] & 0x3F) | 0x80);

        // Formatted from the bytes in RFC order rather than through
        // new Guid(byte[]), which reads the first three fields as little-endian
        // and would move the version nibble somewhere a reader does not look.
        var hex = Convert.ToHexStringLower(bytes);
        return $"{hex[..8]}-{hex[8..12]}-{hex[12..16]}-{hex[16..20]}-{hex[20..]}";
    }

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
