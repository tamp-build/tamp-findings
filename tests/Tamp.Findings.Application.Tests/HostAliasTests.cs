using Tamp.Findings.Application.Explorer;

namespace Tamp.Findings.Application.Tests;

// Host aliasing (TFND-91) — "one app appearing as two hosts", problem 7 on the
// brief's list.
//
// The suggestion heuristic is the part worth pinning: it must be eager enough
// to be useful and never automatic, because whether two addresses are one
// deployment is a fact about someone's infrastructure this product cannot know.
public class HostAliasTests
{
    private static HostAliasMap Empty() => new(new Dictionary<string, string>());

    private static HostAliasMap With(params (string Alias, string Canonical)[] aliases) =>
        new(aliases.ToDictionary(a => a.Alias, a => a.Canonical, StringComparer.OrdinalIgnoreCase));

    [Fact]
    public void An_unaliased_host_resolves_to_itself()
    {
        Assert.Equal("app.example.com", Empty().Canonical("app.example.com"));
    }

    [Fact]
    public void An_aliased_host_resolves_to_its_canonical()
    {
        var map = With(("app.internal", "app.example.com"));

        Assert.Equal("app.example.com", map.Canonical("app.internal"));
    }

    [Fact]
    public void Alias_lookup_ignores_case()
    {
        var map = With(("App.Internal", "app.example.com"));

        Assert.Equal("app.example.com", map.Canonical("app.internal"));
    }

    [Fact]
    public void The_same_host_on_two_ports_is_suspected()
    {
        // Almost always one deployment behind two listeners.
        var suspicions = Empty().SuspectedDuplicates(["app.test", "app.test:8443"]);

        Assert.Single(suspicions);
        Assert.Contains("port", suspicions[0].Reason, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void Hosts_sharing_a_leftmost_label_are_suspected()
    {
        var suspicions = Empty().SuspectedDuplicates(["juice.internal", "juice.example.com"]);

        Assert.Single(suspicions);
        Assert.Contains("juice", suspicions[0].Reason, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void A_local_and_a_public_address_are_suspected()
    {
        // A scan run from inside the deployment and one run from outside.
        var suspicions = Empty().SuspectedDuplicates(["localhost:5099", "staging.example.com"]);

        Assert.Single(suspicions);
    }

    [Fact]
    public void Genuinely_unrelated_hosts_are_not_suspected()
    {
        // The heuristic has to stay quiet on real estates, or people learn to
        // ignore the callout — which is worse than not having it.
        var suspicions = Empty().SuspectedDuplicates(["billing.example.com", "search.example.net"]);

        Assert.Empty(suspicions);
    }

    [Fact]
    public void Short_shared_labels_do_not_trigger_a_suspicion()
    {
        // "api.a.com" and "api.b.com" really can be two services. Requiring a
        // label longer than two characters keeps the noise down.
        var suspicions = Empty().SuspectedDuplicates(["ci.alpha.com", "ci.beta.com"]);

        Assert.Empty(suspicions);
    }

    [Fact]
    public void Placeholder_hosts_are_never_suggested_for_merging()
    {
        // "(relative)" and "(unknown host)" are what DastRoute returns when
        // there was no parseable host at all. Merging them would assert
        // something about infrastructure from an absence of data.
        var suspicions = Empty().SuspectedDuplicates(["(relative)", "(unknown host)", "app.test"]);

        Assert.Empty(suspicions);
    }

    [Fact]
    public void Every_pair_is_considered_not_just_adjacent_ones()
    {
        // A three-host estate where the match is between the first and last.
        var suspicions = Empty().SuspectedDuplicates(
            ["app.internal", "unrelated.example.net", "app.example.com"]);

        Assert.Single(suspicions);
    }
}
