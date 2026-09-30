namespace Tamp.Findings.Domain.Entities;

/// <summary>
/// A dated price for an LLM model's tokens (TFND-204). Findings owns the pricing table — the FACT of
/// "how many tokens" comes from the producer (tamp-conformance emits usage per adapter), the POLICY of
/// "what a token costs" is ours, so a price correction re-flows through every historical scan's cost
/// without re-ingesting. Cost is never stored on the usage row; it is computed against the price in
/// effect at the observation's timestamp.
/// </summary>
public sealed class ModelPrice
{
    public Guid Id { get; set; } = Guid.NewGuid();

    /// <summary>The model identifier the producer reports, e.g. "claude-opus-4-8", "gpt-4o".</summary>
    public required string ModelId { get; set; }
    public string? Provider { get; set; }                 // "anthropic" | "openai" | "bedrock" | …

    /// <summary>USD (or <see cref="Currency"/>) per 1,000,000 tokens.</summary>
    public decimal InputPerMillion { get; set; }
    public decimal OutputPerMillion { get; set; }
    public string Currency { get; set; } = "USD";

    /// <summary>Dated: this price applies to observations at/after EffectiveFrom, until a newer row
    /// supersedes it. A scan is costed against the price that was in effect when it ran.</summary>
    public DateTimeOffset EffectiveFrom { get; set; }

    public bool IsSeeded { get; set; }
    public DateTimeOffset CreatedAt { get; set; } = DateTimeOffset.UtcNow;
}
