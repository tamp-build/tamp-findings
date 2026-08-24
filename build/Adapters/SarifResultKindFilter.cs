using System.Text.Json;
using System.Text.Json.Nodes;

namespace Tamp.Findings.Build.Adapters;

/// <summary>
/// Loads a SARIF log with non-failure results removed.
///
/// SARIF 2.1.0 §3.27.9: every result carries a <c>kind</c> — notApplicable |
/// pass | fail | review | open | informational — defaulting to <c>fail</c> when
/// absent. Only failures are findings. A tool that reports what it CHECKED as
/// well as what it found puts both in the same array, distinguished by nothing
/// else.
///
/// TODO(TAM-285): drop this once Tamp.Sarif models result.kind and parse
/// directly again. SarifResult exposes Level but not Kind, so a consumer
/// working from the parsed object has no property to filter on.
///
/// Level is NOT a substitute. Passing results do carry level "none", but the
/// converse does not hold — "none" is legal on a genuine failure — so
/// filtering on level would silently drop real findings from any scanner that
/// reports them that way.
/// </summary>
public static partial class SarifResultKindFilter
{
    /// <summary>
    /// Remove every result whose <c>kind</c> is present and not "fail".
    /// </summary>
    /// <remarks>
    /// Deliberately conservative. A result with no <c>kind</c> is kept, because
    /// the spec default is "fail" and the overwhelming majority of scanners
    /// never write the property at all — treating absent as anything else
    /// would discard almost every real finding we ingest.
    ///
    /// Malformed input is returned unchanged rather than throwing: this sits in
    /// front of every SARIF the pipeline reads, and a filter that cannot parse
    /// something must not be the reason a scan reports nothing. The parser
    /// downstream will produce the better error.
    /// </remarks>
    public static string RemoveNonFailures(string json, out int dropped)
    {
        dropped = 0;

        JsonNode? root;
        try { root = JsonNode.Parse(json); }
        catch (JsonException) { return json; }

        if (root is not JsonObject obj || obj["runs"] is not JsonArray runs) return json;

        var removed = 0;
        foreach (var run in runs)
        {
            if (run is not JsonObject runObj || runObj["results"] is not JsonArray results) continue;

            // Backwards, removing in place. A JsonNode belongs to exactly one
            // parent, so moving survivors into a new array would mean
            // detaching each one first; deleting the rest avoids the question
            // entirely, and iterating from the end keeps the indices valid.
            for (var i = results.Count - 1; i >= 0; i--)
            {
                if (IsFailure(results[i])) continue;
                results.RemoveAt(i);
                removed++;
            }
        }

        dropped = removed;
        return removed == 0 ? json : obj.ToJsonString();
    }

    private static bool IsFailure(JsonNode? result)
    {
        if (result is not JsonObject r) return true;
        if (!r.TryGetPropertyValue("kind", out var kind)) return true;   // absent ⇒ "fail"
        if (kind is null) return true;

        var value = kind.GetValueKind() == JsonValueKind.String ? kind.GetValue<string>() : null;
        // Unrecognised or non-string: keep it. Discarding a result we do not
        // understand is the one outcome that loses a finding silently.
        return value is null || string.Equals(value, "fail", StringComparison.OrdinalIgnoreCase);
    }
}
