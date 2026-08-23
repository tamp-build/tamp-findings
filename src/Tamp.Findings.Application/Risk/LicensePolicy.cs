using Tamp.Findings.Domain.Entities;
namespace Tamp.Findings.Application.Risk;

// Classifies a license string (SPDX-id or short expression) into a
// permissiveness tier.
//
// The built-in table below is the DEFAULT, not the rule (TFND-10 / F9.3).
// Which licences an organisation can live with is a legal position rather than
// a fact about software — two adopters can hold opposite views about the same
// licence and both be right — so a policy's allow- and denylist is layered
// over this and wins. Pass RiskPolicyConfig.Licenses to Classify to apply it;
// the parameterless overload is the built-in default and is what the product
// falls back to when no policy applies.
//
// Composite SPDX expressions ("MIT OR Apache-2.0", "(GPL-2.0 WITH
// Classpath-exception-2.0) AND MIT") are evaluated by the loosest
// matching atom: if any token is Permissive, the whole is Permissive.
// That's the right default — composite OR-licenses let the adopter
// pick the most permissive option. AND-composites with a denied
// atom should arguably stay Denied; treat that as a known gap.
public static class LicensePolicy
{
    public enum Tier { Permissive, WeakCopyleft, StrongCopyleft, Denied, Unknown }

    private static readonly IReadOnlyDictionary<string, Tier> Atoms = new Dictionary<string, Tier>(StringComparer.OrdinalIgnoreCase)
    {
        // Highly permissive
        ["MIT"] = Tier.Permissive,
        ["MIT-0"] = Tier.Permissive,
        ["Apache-2.0"] = Tier.Permissive,
        ["BSD-2-Clause"] = Tier.Permissive,
        ["BSD-3-Clause"] = Tier.Permissive,
        ["BSD-3-Clause-Clear"] = Tier.Permissive,
        ["ISC"] = Tier.Permissive,
        ["0BSD"] = Tier.Permissive,
        ["Unlicense"] = Tier.Permissive,
        ["CC0-1.0"] = Tier.Permissive,
        ["CC-BY-4.0"] = Tier.Permissive,
        ["CC-BY-3.0"] = Tier.Permissive,
        ["PostgreSQL"] = Tier.Permissive,
        ["BlueOak-1.0.0"] = Tier.Permissive,
        ["Zlib"] = Tier.Permissive,
        ["WTFPL"] = Tier.Permissive,
        ["Python-2.0"] = Tier.Permissive,
        ["MS-PL"] = Tier.Permissive,
        ["MS-RL"] = Tier.WeakCopyleft,   // Reciprocal — file-level

        // Weak copyleft
        ["MPL-2.0"] = Tier.WeakCopyleft,
        ["MPL-1.1"] = Tier.WeakCopyleft,
        ["EPL-1.0"] = Tier.WeakCopyleft,
        ["EPL-2.0"] = Tier.WeakCopyleft,
        ["LGPL-2.1"] = Tier.WeakCopyleft,
        ["LGPL-2.1-only"] = Tier.WeakCopyleft,
        ["LGPL-2.1-or-later"] = Tier.WeakCopyleft,
        ["CDDL-1.0"] = Tier.WeakCopyleft,
        ["CDDL-1.1"] = Tier.WeakCopyleft,

        // Strong copyleft
        ["GPL-2.0"] = Tier.StrongCopyleft,
        ["GPL-2.0-only"] = Tier.StrongCopyleft,
        ["GPL-2.0-or-later"] = Tier.StrongCopyleft,
        ["LGPL-3.0"] = Tier.StrongCopyleft,
        ["LGPL-3.0-only"] = Tier.StrongCopyleft,
        ["LGPL-3.0-or-later"] = Tier.StrongCopyleft,

        // Denied — network copyleft / source-disclosure that breaks
        // commercial SaaS by default.
        ["GPL-3.0"] = Tier.Denied,
        ["GPL-3.0-only"] = Tier.Denied,
        ["GPL-3.0-or-later"] = Tier.Denied,
        ["AGPL-3.0"] = Tier.Denied,
        ["AGPL-3.0-only"] = Tier.Denied,
        ["AGPL-3.0-or-later"] = Tier.Denied,
        ["SSPL-1.0"] = Tier.Denied,
        ["Commons-Clause"] = Tier.Denied,
    };

    /// <summary>
    /// Classify under a policy's allow- and denylist (F9.3).
    ///
    /// Deny is checked FIRST and wins over Allow. A licence named in both is a
    /// configuration mistake, and the safe reading of a mistake on this
    /// question is the strict one.
    /// </summary>
    public static Tier Classify(string? license, LicenseRules? rules)
    {
        if (rules is null) return Classify(license);

        if (!string.IsNullOrWhiteSpace(license))
        {
            // Whole-expression match first, then per-atom: an adopter denying
            // "AGPL-3.0" means it wherever it appears, including inside
            // "MIT OR AGPL-3.0" — which the loosest-atom default would let
            // through as permissive.
            var atoms = Atomise(license).ToArray();

            if (Names(rules.Deny).Overlaps(atoms) || Names(rules.Deny).Contains(license.Trim()))
                return Tier.Denied;

            if (Names(rules.Allow).Contains(license.Trim()) || Names(rules.Allow).Overlaps(atoms))
                return Tier.Permissive;
        }

        var tier = Classify(license);

        return tier == Tier.Unknown && rules.DenyUnknown ? Tier.Denied : tier;
    }

    private static HashSet<string> Names(IEnumerable<string> values) =>
        values.Where(v => !string.IsNullOrWhiteSpace(v))
              .Select(v => v.Trim())
              .ToHashSet(StringComparer.OrdinalIgnoreCase);

    private static IEnumerable<string> Atomise(string license) =>
        license
            .Replace("(", " ").Replace(")", " ")
            .Split([" OR ", " AND ", " WITH ", ","],
                StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);

    public static Tier Classify(string? license)
    {
        if (string.IsNullOrWhiteSpace(license)) return Tier.Unknown;

        // Fast path — exact SPDX-id match (covers ~all rows on this repo).
        if (Atoms.TryGetValue(license.Trim(), out var t)) return t;

        // Composite SPDX expression: take the loosest atom found. Strip
        // parens, split on the usual delimiters, look each atom up.
        var atoms = license
            .Replace("(", " ").Replace(")", " ")
            .Split([" OR ", " AND ", " WITH ", ","], StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);

        var best = Tier.Unknown;
        var anyKnown = false;
        foreach (var atom in atoms)
        {
            if (!Atoms.TryGetValue(atom, out var tier)) continue;
            anyKnown = true;
            // Loosest wins: Permissive < WeakCopyleft < StrongCopyleft < Denied
            if (tier < best || best == Tier.Unknown) best = tier;
        }
        return anyKnown ? best : Tier.Unknown;
    }
}
