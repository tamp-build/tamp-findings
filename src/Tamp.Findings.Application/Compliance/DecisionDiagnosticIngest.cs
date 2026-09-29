using System.Text.Json.Serialization;

namespace Tamp.Findings.Application.Compliance;

/// <summary>
/// The subset of the canonical Tamp.Core <c>BuildEvent</c> envelope the decision-diagnostic
/// ingest consumes (ADR 0013). Reverse-examination emits <c>diagnostic.emitted</c> events
/// (SARIF level "note") whose ruleId is <c>undocumented-decision:&lt;kind&gt;</c>. Lenient by
/// design: the producer can fire-hose the whole stream and we keep only the undocumented-decision
/// notes, skipping conformance verdicts and everything else. Wire is camelCase; the payload
/// discriminator is <c>$type</c>.
/// </summary>
public sealed class DiagnosticEventDto
{
    public string? Type { get; set; }              // "diagnostic.emitted"
    public string? BuildId { get; set; }
    public string? RunId { get; set; }
    public long Seq { get; set; }
    public string? WorkerId { get; set; }
    public DateTimeOffset? Ts { get; set; }
    public DiagnosticPayloadDto? Payload { get; set; }
}

public sealed class DiagnosticPayloadDto
{
    [JsonPropertyName("$type")] public string? Type { get; set; }   // "diagnostic.emitted"
    public string? RuleId { get; set; }            // "undocumented-decision:new-dependency"
    public string? Level { get; set; }             // SARIF level — "note" for advisories
    public string? Message { get; set; }           // the decision summary
    public DiagnosticLocationDto? Location { get; set; }
    public DiagnosticProvenanceDto? Provenance { get; set; }
    public List<string>? ControlRefs { get; set; }
}

public sealed class DiagnosticLocationDto
{
    public string? File { get; set; }
    public int? Line { get; set; }
}

public sealed class DiagnosticProvenanceDto
{
    public string? CommitSha { get; set; }
    public string? ModelId { get; set; }
}

/// <summary>The outcome of a decision-diagnostic ingest: how many advisories attached to a
/// build, how many were skipped (not an undocumented-decision note, malformed, or no build to
/// bind to), and the commit shas touched.</summary>
public sealed record DiagnosticIngestResult(int Accepted, int Skipped, IReadOnlyList<string> Builds);
