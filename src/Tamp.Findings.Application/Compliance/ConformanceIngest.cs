using System.Text.Json.Serialization;

namespace Tamp.Findings.Application.Compliance;

/// <summary>
/// The subset of the canonical Tamp.Core <c>BuildEvent</c> envelope the
/// conformance ingest consumes (core ADR 0023). Lenient by design: the producer
/// can fire-hose the whole <c>TAMP_EVENTS</c> stream at us and we keep only the
/// <c>conformance.evaluated</c> events, skipping the rest. Wire is camelCase,
/// nulls dropped; the payload discriminator is <c>$type</c>.
/// </summary>
public sealed class ConformanceEventDto
{
    public string? Type { get; set; }              // "conformance.evaluated"
    public string? BuildId { get; set; }
    public string? RunId { get; set; }
    public long Seq { get; set; }
    public string? WorkerId { get; set; }
    public DateTimeOffset? Ts { get; set; }
    public ConformancePayloadDto? Payload { get; set; }
}

public sealed class ConformancePayloadDto
{
    [JsonPropertyName("$type")] public string? Type { get; set; }   // "conformance.evaluated"
    public string? AdrRef { get; set; }
    public string? RuleId { get; set; }
    public string? Verdict { get; set; }           // pass | fail | unknown | error
    public string? AdrQuote { get; set; }
    public string? CodeEvidence { get; set; }
    public ConformanceLocationDto? Location { get; set; }
    public string? Method { get; set; }            // deterministic | semantic | verify
    public bool Blocks { get; set; }
    public ConformanceProvenanceDto? Provenance { get; set; }
    public List<string>? ControlRefs { get; set; }
}

public sealed class ConformanceLocationDto
{
    public string? File { get; set; }
    public int? Line { get; set; }
}

public sealed class ConformanceProvenanceDto
{
    public string? CommitSha { get; set; }
    public string? RulesSha { get; set; }
    public string? Method { get; set; }
    public string? ModelId { get; set; }
    public string? VerifyVerdict { get; set; }
}

/// <summary>The outcome of a conformance ingest: how many verdicts attached to a
/// build, how many were skipped (not conformance, malformed, or no build to bind
/// to), and the commit shas touched.</summary>
public sealed record ConformanceIngestResult(int Accepted, int Skipped, IReadOnlyList<string> Builds);
