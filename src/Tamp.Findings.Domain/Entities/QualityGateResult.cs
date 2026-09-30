namespace Tamp.Findings.Domain.Entities;

/// <summary>
/// An attested code-quality gate verdict for a build (TFND-175): the producer
/// (e.g. SonarQube) attests pass/fail/warn + the failing conditions; findings
/// decides whether it blocks. This is the process half of the quality ship-gate
/// (SA-15) — distinct from the quality SCORE, which counts findings. Recorded as
/// an external control result, kept verbatim for the evidence panel. Replace-on-
/// ingest per build.
/// </summary>
public sealed class QualityGateResult
{
    public Guid Id { get; set; } = Guid.NewGuid();
    public Guid ComponentVersionId { get; set; }

    /// <summary>"pass" | "fail" | "warn" — from the tool's alert_status.</summary>
    public string Status { get; set; } = "";

    /// <summary>The failing/measured conditions as JSON: [{metric, op, threshold, actual, status}].</summary>
    public string? ConditionsJson { get; set; }

    /// <summary>Headline measures as JSON (ncloc, code_smells, …) for the panel.</summary>
    public string? MeasuresJson { get; set; }

    public string? AnalysisId { get; set; }
    public string? Source { get; set; }        // "sonarcloud", "sonarqube:<server>", …

    public DateTimeOffset ObservedAt { get; set; }
    public DateTimeOffset IngestedAt { get; set; } = DateTimeOffset.UtcNow;

    public ComponentVersion? ComponentVersion { get; set; }
}
