using System.Text;
using Tamp.Findings.Domain.Risk;

namespace Tamp.Findings.Application.GitHub;

/// <summary>
/// Turning a gate evaluation into a GitHub check run (TFND-23).
///
/// Pure, and separated from the HTTP client on purpose: the mapping from a
/// four-valued verdict to a GitHub conclusion is the only genuinely interesting
/// decision in this feature, and it should be testable without a network.
///
/// The ticket's acceptance says "the check name + summary matches what the SPA
/// shows for that scan run". So this composes from the SAME
/// <see cref="GateEvaluation"/> the gate rail renders, rather than counting
/// findings again — two counts of the same thing eventually disagree, and the
/// one on GitHub is the one somebody merges against.
/// </summary>
public static class CheckRunComposer
{
    public static CheckRun Compose(
        string checkName, GateEvaluation gates, double score, string band,
        string policyName, string? detailsUrl)
    {
        var blocking = gates.Results.Where(r => r.Blocks).ToArray();

        return new CheckRun(
            checkName,
            Conclusion(blocking),
            Title(blocking, gates),
            Summary(gates, score, band, policyName, blocking),
            detailsUrl);
    }

    /// <summary>
    /// The four-valued verdict, mapped onto GitHub's vocabulary.
    ///
    /// THE DECISION THIS FEATURE TURNS ON. Under ADR 0001 a gate is Pass, Fail,
    /// Unknown or Error, and all three of the last block. GitHub has no
    /// "unknown", so the mapping has to preserve the distinction that matters
    /// while still blocking a merge:
    ///
    ///   any Fail            → failure          "we measured, and it is bad"
    ///   only Unknown/Error  → action_required  "we could not measure"
    ///   nothing blocking    → success
    ///
    /// action_required rather than neutral, deliberately. NEUTRAL DOES NOT
    /// BLOCK BRANCH PROTECTION — a gate that could not be answered would let a
    /// merge through, which is precisely the defect the four-valued model was
    /// introduced to remove. Reporting "we did not look" as a green check would
    /// be this product lying on somebody else's screen.
    /// </summary>
    public static string Conclusion(IReadOnlyCollection<GateResult> blocking)
    {
        if (blocking.Count == 0) return "success";
        return blocking.Any(r => r.Verdict == GateVerdict.Fail) ? "failure" : "action_required";
    }

    private static string Title(IReadOnlyCollection<GateResult> blocking, GateEvaluation gates)
    {
        if (blocking.Count == 0)
        {
            return gates.Enabled == 0
                // No gates configured is not the same as passing them. Saying
                // "clear to ship" here would credit a project for a contract it
                // never wrote.
                ? "No acceptance gates configured"
                : $"Clear to ship — {gates.Enabled} gate{(gates.Enabled == 1 ? "" : "s")} passed";
        }

        var failed = blocking.Count(r => r.Verdict == GateVerdict.Fail);
        var unknown = blocking.Count - failed;

        if (failed > 0 && unknown > 0)
            return $"{failed} gate{(failed == 1 ? "" : "s")} failing, {unknown} unanswerable";

        return failed > 0
            ? $"{failed} gate{(failed == 1 ? "" : "s")} failing"
            : $"{unknown} gate{(unknown == 1 ? "" : "s")} could not be answered";
    }

    private static string Summary(
        GateEvaluation gates, double score, string band, string policyName,
        IReadOnlyCollection<GateResult> blocking)
    {
        var sb = new StringBuilder();

        // The score never appears without the policy that produced it. Same
        // rule as the screen, the PDF and the OSCAL package — a number without
        // its policy is not evidence, and on a pull request it is a number
        // somebody will argue with.
        sb.Append("**Risk score ").Append(score.ToString("0.0"))
          .Append("** (").Append(band).Append(") under policy `").Append(policyName).Append("`.\n\n");

        if (gates.Enabled == 0)
        {
            sb.Append("No acceptance gates are configured for this project, so this check has ")
              .Append("nothing to assert. That is not the same as passing.\n");
            return sb.ToString();
        }

        sb.Append(gates.Passed).Append(" of ").Append(gates.Enabled).Append(" enabled gates pass");
        if (gates.Unknown > 0) sb.Append(", ").Append(gates.Unknown).Append(" unanswerable");
        if (gates.Failed > 0) sb.Append(", ").Append(gates.Failed).Append(" failing");
        sb.Append(".\n");

        if (blocking.Count == 0) return sb.ToString();

        sb.Append("\n| Gate | Verdict | Observed |\n|---|---|---|\n");
        foreach (var gate in blocking)
        {
            sb.Append("| `").Append(gate.Key).Append("` | ")
              .Append(gate.Verdict).Append(" | ")
              // The observed value, not a restatement of the verdict. "0 KEV
              // CVEs — no SBOM scan on this build" is what tells a developer
              // what to do next; "Unknown" on its own tells them nothing.
              .Append(Escape(gate.Observed)).Append(" |\n");
        }

        if (blocking.Any(r => r.Verdict != GateVerdict.Fail))
        {
            sb.Append("\nGates marked **Unknown** could not be evaluated — usually because the ")
              .Append("scanner that produces their input did not run on this build. A count of ")
              .Append("zero from a scan that never happened is not a clean result, so they block ")
              .Append("rather than pass.\n");
        }

        return sb.ToString();
    }

    /// <summary>
    /// GitHub renders the summary as Markdown, and an observed value can carry
    /// a pipe — a DAST route with a query string, a path with an alternation.
    /// An unescaped one breaks the table row it lands in.
    /// </summary>
    private static string Escape(string value) => value.Replace("|", "\\|");
}

/// <summary>A composed check run, ready to post.</summary>
public sealed record CheckRun(
    string Name, string Conclusion, string Title, string Summary, string? DetailsUrl);
