namespace Tamp.Findings.Domain.Entities;

/// <summary>
/// One LLM usage observation from a scan (TFND-204) — tokens, model, latency for a single adapter
/// call on a build. Emitted by the producer (tamp-conformance reports usage per adapter: input/output
/// tokens, model id, capability, latency). Cost is NOT stored here — it is computed at read time from
/// the dated <see cref="ModelPrice"/> table, so a pricing correction re-flows without re-ingesting.
///
/// This is evidence ABOUT the scan (what it cost to produce), deliberately separate from the scan's
/// findings/verdicts — overloading the conformance evidence with cost would conflate "is the code
/// compliant" with "what did checking it cost".
/// </summary>
public sealed class ScanUsageObservation
{
    public Guid Id { get; set; } = Guid.NewGuid();
    public Guid ComponentVersionId { get; set; }

    /// <summary>The scan adapter that produced this usage, e.g. "adr-conformance", "reverse-exam".</summary>
    public string Adapter { get; set; } = "";
    /// <summary>The check capability/class, when the adapter reports one (optional).</summary>
    public string? Capability { get; set; }

    public string ModelId { get; set; } = "";
    public string? Provider { get; set; }

    public long InputTokens { get; set; }
    public long OutputTokens { get; set; }
    public double LatencyMs { get; set; }

    public DateTimeOffset ObservedAt { get; set; }
    public DateTimeOffset IngestedAt { get; set; } = DateTimeOffset.UtcNow;

    public ComponentVersion? ComponentVersion { get; set; }
}
