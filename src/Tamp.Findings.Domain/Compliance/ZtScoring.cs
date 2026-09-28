using Tamp.Findings.Domain.Entities;

namespace Tamp.Findings.Domain.Compliance;

// The Zero Trust maturity derivation (TFND-188 / ADR 0010 §4, §8). Pure and
// deterministic like GateEvaluator, ControlDispositionResolver and PolicyLayerMerge:
// every pillar-function resolves to exactly one disposition + a stage, computed from
// (owned evidence ∩ inheritance edges ∩ owner picks ∩ the model), and the pinned
// equal-weight scoring contract folds it up. Conservative-by-construction: undetermined
// floors at 1, inherited caps at the provider, and N/A leaves the denominator entirely.

public enum ZtDisposition
{
    OwnedVerified,      // repo evidence proves it — the derived stage, trusted
    OwnedCommitted,     // asserted, not yet conformance-verified — flagged, routes to spot-check
    OwnedContradicted,  // claimed, and the code violates it — the case only the tool catches
    InheritedAttested,  // declared edge + attester + evidence, unexpired — provider's stage, capped
    InheritedCommitted, // bare edge (or stale attestation) — provider's stage, flagged
    NotApplicable,      // off the denominator (a role declaration), NEVER a 1
    Undetermined,       // couldn't derive / inherit / N/A → the floor
}

// Mirrors ConformanceVerdict, decoupled so the resolver stays pure Domain.
public enum ZtOwnedVerdict { Pass = 0, Fail = 1, Unknown = 2, Error = 3 }

// Inputs (assembled by the Application query from DB rows; kept as plain records so the
// resolver has no I/O). Pillar/Function match the model case-insensitively on Id or Name.
public sealed record ZtOwnedEvidence(string Pillar, string Function, int Stage, ZtOwnedVerdict Verdict);
public sealed record ZtEdgeInput(string Pillar, string Function, int? ProviderStage, bool HasStatement, DateTimeOffset? ExpiresAt);
public sealed record ZtPickInput(string Pillar, string Function, ZtPickKind Kind);

public sealed record ZtFunctionResult(
    string Pillar, string Function, bool CrossCutting,
    ZtDisposition Disposition, int Stage, bool InDenominator, string? Detail);

public sealed record ZtPillarScore(string Pillar, double? Score, int Applicable, int Total);

public sealed record ZtCoverage(
    IReadOnlyList<ZtFunctionResult> Functions,
    IReadOnlyList<ZtPillarScore> Pillars,
    // Mean of the scored pillars (equal weights); null when the whole system is N/A.
    double? SystemScore)
{
    public int Undetermined => Functions.Count(f => f.Disposition == ZtDisposition.Undetermined);
    public int NotApplicable => Functions.Count(f => f.Disposition == ZtDisposition.NotApplicable);
    public int Owned => Functions.Count(f => f.Disposition is ZtDisposition.OwnedVerified
        or ZtDisposition.OwnedCommitted or ZtDisposition.OwnedContradicted);
    public int Inherited => Functions.Count(f => f.Disposition is ZtDisposition.InheritedAttested
        or ZtDisposition.InheritedCommitted);
    public int Contradicted => Functions.Count(f => f.Disposition == ZtDisposition.OwnedContradicted);
}

public static class ZtDispositionResolver
{
    public const int Floor = 1; // Traditional. There is no zero (ADR 0010 §2).

    public static ZtCoverage Resolve(
        MaturityModelCatalog model,
        IReadOnlyList<ZtOwnedEvidence> owned,
        IReadOnlyList<ZtEdgeInput> edges,
        IReadOnlyList<ZtPickInput> picks,
        DateTimeOffset asOf)
    {
        var results = new List<ZtFunctionResult>();
        foreach (var pillar in model.Pillars)
        foreach (var fn in pillar.Functions)
        {
            var o = owned.Where(x => Match(pillar, x.Pillar) && Match(fn, x.Function)).ToList();
            var e = edges.FirstOrDefault(x => Match(pillar, x.Pillar) && Match(fn, x.Function));
            var p = picks.FirstOrDefault(x => Match(pillar, x.Pillar) && Match(fn, x.Function));
            results.Add(ResolveOne(pillar.Name, fn, o, e, p, asOf));
        }
        return ZtmmScoringContract.Score(results);
    }

    private static ZtFunctionResult ResolveOne(
        string pillar, ZtFunctionDef fn,
        IReadOnlyList<ZtOwnedEvidence> owned, ZtEdgeInput? edge, ZtPickInput? pick,
        DateTimeOffset asOf)
    {
        // 1. An N/A role declaration removes the function from the denominator. This
        //    guard runs FIRST and never collapses into a 1 (the scale-poisoning bug).
        if (pick is { Kind: ZtPickKind.NotApplicable })
            return new(pillar, fn.Name, fn.CrossCutting, ZtDisposition.NotApplicable, Floor, false, "not applicable");

        // 2. A declared inheritance edge is the enterprise source for a function the repo
        //    cannot see; it wins over owned derivation. Capped at the provider's stage.
        if (edge is not null)
        {
            var stage = edge.ProviderStage ?? Floor;
            var attested = edge.HasStatement && edge.ExpiresAt is { } exp && exp > asOf;
            var disp = attested ? ZtDisposition.InheritedAttested : ZtDisposition.InheritedCommitted;
            var detail = edge.ProviderStage is null
                ? "inherited — provider has no score for this function"
                : $"inherited stage {stage}" + (attested ? " (attested)" : " (unattested / stale)");
            return new(pillar, fn.Name, fn.CrossCutting, disp, stage, true, detail);
        }

        // 3. Owned maturity evidence. A contradiction (code breaks a claim) is the
        //    signal only the tool catches, so it wins; then Pass, then Unknown.
        if (owned.Count > 0)
        {
            if (owned.Any(x => x.Verdict == ZtOwnedVerdict.Fail))
                return new(pillar, fn.Name, fn.CrossCutting, ZtDisposition.OwnedContradicted, Floor, true,
                    "ADR claims this; the code contradicts it");
            var passes = owned.Where(x => x.Verdict == ZtOwnedVerdict.Pass).ToList();
            if (passes.Count > 0)
                return new(pillar, fn.Name, fn.CrossCutting, ZtDisposition.OwnedVerified, MaxStage(passes), true, "verified");
            var unknowns = owned.Where(x => x.Verdict == ZtOwnedVerdict.Unknown).ToList();
            if (unknowns.Count > 0)
                return new(pillar, fn.Name, fn.CrossCutting, ZtDisposition.OwnedCommitted, MaxStage(unknowns), true,
                    "asserted, not yet verified");
            // Only Error(s) → a data-quality hole; treat as undetermined for scoring.
            return new(pillar, fn.Name, fn.CrossCutting, ZtDisposition.Undetermined, Floor, true, "evaluation error");
        }

        // 4. A committed owner pick with no evidence: claimed, routes to spot-check,
        //    but scores the floor until evidence raises it (conservative).
        if (pick is { Kind: ZtPickKind.Committed })
            return new(pillar, fn.Name, fn.CrossCutting, ZtDisposition.OwnedCommitted, Floor, true, "owner-asserted, unverified");

        // 5. Nothing derived, inherited or dispositioned → the floor (never blank/zero).
        return new(pillar, fn.Name, fn.CrossCutting, ZtDisposition.Undetermined, Floor, true, "no evidence — defaults to Traditional");
    }

    private static int MaxStage(IEnumerable<ZtOwnedEvidence> xs) => Math.Clamp(xs.Max(x => x.Stage), 1, 4);

    private static bool Match(ZtPillar p, string key) =>
        string.Equals(p.Id, key, StringComparison.OrdinalIgnoreCase)
        || string.Equals(p.Name, key, StringComparison.OrdinalIgnoreCase);

    private static bool Match(ZtFunctionDef f, string key) =>
        string.Equals(f.Id, key, StringComparison.OrdinalIgnoreCase)
        || string.Equals(f.Name, key, StringComparison.OrdinalIgnoreCase);
}

// The pinned scoring contract (ADR 0010 §8): EQUAL WEIGHTS. Every function weighs
// equally inside its pillar, so a pillar score is the arithmetic mean of its in-scope
// function stages (cross-cutting functions folded in at the same weight); N/A functions
// are excluded from the denominator; undetermined counts as its floor of 1. The system
// score is the equal-weight mean of the scored pillars. Pure/deterministic — one
// implementation so no two producers fold differently.
public static class ZtmmScoringContract
{
    public static ZtCoverage Score(IReadOnlyList<ZtFunctionResult> functions)
    {
        var pillars = new List<ZtPillarScore>();
        foreach (var group in functions.GroupBy(f => f.Pillar))
        {
            var applicable = group.Where(f => f.InDenominator).ToList();
            double? score = applicable.Count > 0 ? applicable.Average(f => f.Stage) : null;
            pillars.Add(new ZtPillarScore(group.Key, score, applicable.Count, group.Count()));
        }

        var scored = pillars.Where(p => p.Score is not null).Select(p => p.Score!.Value).ToList();
        double? systemScore = scored.Count > 0 ? scored.Average() : null;

        return new ZtCoverage(functions, pillars, systemScore);
    }
}
