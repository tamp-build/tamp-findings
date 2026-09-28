using Tamp.Findings.Domain.Compliance;

namespace Tamp.Findings.Domain.Entities;

/// <summary>
/// One ADR-conformance verdict for a build (ADR 0006, core ADR 0023): does the
/// code still honour what an ADR decided? tamp.findings is the SINK — these rows
/// are produced by CI tooling in the governed repo and ingested here, then
/// scored, gated and attested like any other evidence. tamp.findings never calls
/// a model; a non-deterministic verdict is FROZEN at the snapshot so an
/// attestation stays reproducible.
/// </summary>
public sealed class ConformanceFinding
{
    public Guid Id { get; set; } = Guid.NewGuid();

    /// <summary>The build this verdict was computed against.</summary>
    public Guid ComponentVersionId { get; set; }

    public required string AdrRef { get; set; }        // "ADR 0002"
    public required string RuleId { get; set; }        // "auth-boundary-single"
    public required string Claim { get; set; }         // the finding heading

    public ConformanceVerdict Verdict { get; set; }
    public ConformanceMethod Method { get; set; }

    /// <summary>The ADR text the rule anchors to — shown beside the code on a
    /// fail or dispositioned finding.</summary>
    public string? AdrQuote { get; set; }

    /// <summary>The conflicting (fail) or satisfying (pass) code.</summary>
    public string? CodeEvidence { get; set; }

    /// <summary>file:line the finding anchors to.</summary>
    public string? Location { get; set; }

    // --- Provenance, frozen at the snapshot ---
    public string? CommitSha { get; set; }
    public string? RulesSha { get; set; }
    /// <summary>The semantic model that judged it, if Method is Semantic.</summary>
    public string? ModelId { get; set; }
    public VerifyOutcome VerifyVerdict { get; set; }

    /// <summary>800-53 controls this rule maps to ("CM-6", …). Drives the
    /// control filter chips.</summary>
    public List<string> ControlRefs { get; set; } = [];

    // --- Disposition (accepted deviation) — the finding stays listed ---
    public bool Dispositioned { get; set; }
    public string? DispositionJustification { get; set; }
    public string? DispositionedByLogin { get; set; }
    public DateTimeOffset? DispositionExpiry { get; set; }

    /// <summary>When the verdict was frozen (the snapshot time).</summary>
    public DateTimeOffset EvaluatedAt { get; set; } = DateTimeOffset.UtcNow;

    /// <summary>Whether this verdict blocks a build: Fail/Unknown/Error block,
    /// unless dispositioned with an unexpired justification (a fail stays listed
    /// but no longer blocks). Pass never blocks.</summary>
    public bool Blocks(DateTimeOffset asOf) =>
        Verdict is not ConformanceVerdict.Pass
        && !(Dispositioned && (DispositionExpiry is null || DispositionExpiry > asOf));
}
