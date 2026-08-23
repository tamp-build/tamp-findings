using Tamp.Findings.Application.Risk;
using Tamp.Findings.Domain.Entities;

namespace Tamp.Findings.Application.Tests;

// Policy-driven licence classification (TFND-10 / F9.3).
//
// The built-in table used to be the rule. It is now the DEFAULT, because which
// licences an organisation can live with is a legal position rather than a fact
// about software — two adopters can hold opposite views about the same licence
// and both be right.
public class LicensePolicyRulesTests
{
    private static LicenseRules Rules(
        string[]? allow = null, string[]? deny = null, bool denyUnknown = false) => new()
    {
        Allow = [.. allow ?? []],
        Deny = [.. deny ?? []],
        DenyUnknown = denyUnknown,
    };

    [Fact]
    public void With_no_rules_the_built_in_classification_applies()
    {
        // Most adopters will never touch these lists, and the default has to
        // keep working exactly as it did.
        Assert.Equal(LicensePolicy.Tier.Permissive, LicensePolicy.Classify("MIT", Rules()));
        Assert.Equal(LicensePolicy.Tier.Denied, LicensePolicy.Classify("AGPL-3.0", Rules()));
    }

    [Fact]
    public void A_null_rule_set_is_the_built_in_classification()
    {
        // Call sites with no policy in hand — a brand-new instance with no
        // default policy — must not crash or silently permit everything.
        Assert.Equal(LicensePolicy.Tier.Denied, LicensePolicy.Classify("AGPL-3.0", null));
    }

    [Fact]
    public void An_allowed_licence_becomes_permissive()
    {
        // The point of the feature: an organisation whose counsel has cleared
        // AGPL should not be scored as though it had not.
        Assert.Equal(
            LicensePolicy.Tier.Permissive,
            LicensePolicy.Classify("AGPL-3.0", Rules(allow: ["AGPL-3.0"])));
    }

    [Fact]
    public void A_denied_licence_becomes_denied_even_if_the_table_calls_it_permissive()
    {
        // The other direction, and the one that actually gets used: plenty of
        // organisations refuse licences nobody would call risky.
        Assert.Equal(
            LicensePolicy.Tier.Denied,
            LicensePolicy.Classify("MIT", Rules(deny: ["MIT"])));
    }

    [Fact]
    public void Deny_wins_over_allow()
    {
        // A licence in both lists is a configuration mistake, and the safe
        // reading of a mistake on this question is the strict one.
        Assert.Equal(
            LicensePolicy.Tier.Denied,
            LicensePolicy.Classify("MPL-2.0", Rules(allow: ["MPL-2.0"], deny: ["MPL-2.0"])));
    }

    [Fact]
    public void Matching_is_case_insensitive()
    {
        // SBOM producers disagree about SPDX casing, and an adopter typing
        // "agpl-3.0" means the licence, not a different one.
        Assert.Equal(
            LicensePolicy.Tier.Denied,
            LicensePolicy.Classify("AGPL-3.0", Rules(deny: ["agpl-3.0"])));
    }

    [Fact]
    public void A_denied_atom_inside_a_composite_denies_the_whole()
    {
        // THE case the default gets wrong for a denylist. The built-in rule
        // takes the LOOSEST atom, so "MIT OR AGPL-3.0" is permissive — which is
        // right by default, since an OR lets you pick. But an adopter who has
        // written AGPL into their denylist means it wherever it appears, and
        // silently permitting it because there was an alternative would defeat
        // the point of writing it down.
        Assert.Equal(
            LicensePolicy.Tier.Permissive,
            LicensePolicy.Classify("MIT OR AGPL-3.0", Rules()));

        Assert.Equal(
            LicensePolicy.Tier.Denied,
            LicensePolicy.Classify("MIT OR AGPL-3.0", Rules(deny: ["AGPL-3.0"])));
    }

    [Fact]
    public void An_allowed_atom_inside_a_composite_permits_the_whole()
    {
        Assert.Equal(
            LicensePolicy.Tier.Permissive,
            LicensePolicy.Classify("SSPL-1.0 OR Contoso-Internal", Rules(allow: ["Contoso-Internal"])));
    }

    [Fact]
    public void An_unknown_licence_stays_unknown_by_default()
    {
        // On a real SBOM the unknown pile is large and mostly benign. Denying
        // it by default would make every policy fail on day one, and a policy
        // that always fails is one people learn to ignore.
        Assert.Equal(
            LicensePolicy.Tier.Unknown,
            LicensePolicy.Classify("Contoso-Proprietary-1.0", Rules()));
    }

    [Fact]
    public void An_unknown_licence_can_be_denied_by_policy()
    {
        Assert.Equal(
            LicensePolicy.Tier.Denied,
            LicensePolicy.Classify("Contoso-Proprietary-1.0", Rules(denyUnknown: true)));
    }

    [Fact]
    public void A_blank_licence_is_unknown_and_can_also_be_denied()
    {
        // A missing licence field is "nobody looked", which is the same
        // question DenyUnknown answers.
        Assert.Equal(LicensePolicy.Tier.Unknown, LicensePolicy.Classify(null, Rules()));
        Assert.Equal(LicensePolicy.Tier.Denied, LicensePolicy.Classify(null, Rules(denyUnknown: true)));
        Assert.Equal(LicensePolicy.Tier.Denied, LicensePolicy.Classify("  ", Rules(denyUnknown: true)));
    }

    [Fact]
    public void Deny_unknown_does_not_touch_a_licence_the_table_already_knows()
    {
        // It denies the UNIDENTIFIED, not the merely-not-permissive. Sweeping
        // up weak copyleft too would make the switch mean something other than
        // what it says.
        Assert.Equal(
            LicensePolicy.Tier.WeakCopyleft,
            LicensePolicy.Classify("MPL-2.0", Rules(denyUnknown: true)));
    }

    [Fact]
    public void Blank_and_whitespace_entries_in_a_list_are_ignored()
    {
        // The editor is a comma-separated text box, so trailing commas and
        // stray newlines are normal input rather than an error — and an empty
        // entry that matched everything would be catastrophic on a denylist.
        var rules = Rules(deny: ["", "   ", "AGPL-3.0"]);

        Assert.Equal(LicensePolicy.Tier.Permissive, LicensePolicy.Classify("MIT", rules));
        Assert.Equal(LicensePolicy.Tier.Denied, LicensePolicy.Classify("AGPL-3.0", rules));
    }

    [Fact]
    public void Entries_are_trimmed()
    {
        Assert.Equal(
            LicensePolicy.Tier.Denied,
            LicensePolicy.Classify("MIT", Rules(deny: ["  MIT  "])));
    }
}
