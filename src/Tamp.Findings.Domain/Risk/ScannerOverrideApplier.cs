using Tamp.Findings.Domain.Entities;
using Tamp.Findings.Domain.Values;

namespace Tamp.Findings.Domain.Risk;

// Applies per-scanner severity ceilings to a stream of
// (Scanner, Severity, Count) tuples — collapsing buckets that the
// policy caps. Used by both /aggregates and the per-build evaluator so
// the score reflects the policy's view of which scanners earn full
// severity weight vs which ones are "informational only".
//
// Display data (the per-scanner detail surfaced on the SPA) stays at
// the ingested severity — only score inputs are downgraded.
public static class ScannerOverrideApplier
{
    public static IReadOnlyList<(ScannerKind Scanner, Severity Severity, int Count)> Apply(
        IEnumerable<(ScannerKind Scanner, Severity Severity, int Count)> raw,
        IReadOnlyDictionary<string, ScannerOverride> overrides)
    {
        var rebucketed = new Dictionary<(ScannerKind, Severity), int>();
        foreach (var row in raw)
        {
            var effective = row.Severity;
            if (overrides.TryGetValue(row.Scanner.ToString(), out var ov)
                && ov.SeverityCeiling is { } ceiling
                && row.Severity > ceiling)
            {
                effective = ceiling;
            }
            var key = (row.Scanner, effective);
            rebucketed[key] = rebucketed.GetValueOrDefault(key) + row.Count;
        }
        return rebucketed
            .Select(kv => (kv.Key.Item1, kv.Key.Item2, kv.Value))
            .ToList();
    }
}
