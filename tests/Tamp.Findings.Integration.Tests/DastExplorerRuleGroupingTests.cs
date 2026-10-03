using System.Net;

namespace Tamp.Findings.Integration.Tests;

// TFND-232: on the DAST spine, "Group by rule" always rendered "No open dynamic-scan findings": the host/route
// tree branch was matched before the by-rule branch, and by-rule data is held in different fields, so the tree
// saw nothing. The grouping must render the rule breakdown, and by-path must keep rendering hosts and routes.
[Collection(DatabaseCollection.Name)]
public sealed class DastExplorerRuleGroupingTests(DatabaseFixture fx)
{
    private readonly DatabaseFixture _fx = fx;

    [SkippableFact]
    public async Task Grouping_by_rule_lists_the_dynamic_scan_rules_not_the_empty_state()
    {
        Skip.IfNot(_fx.Available, "TAMP_FINDINGS_TEST_DB not set");
        var w = await PageBWorld.GetAsync(_fx);

        var (status, body) = await w.GetAsync(w.Build("latest", "dast") + "?group=rule");

        Assert.Equal(HttpStatusCode.OK, status);
        // The rule rows themselves are in a <Virtualize>, which renders its items on the client, so the server
        // render proves the bug is gone by what is NOT there: the dynamic-scan empty state, which is what the
        // by-path tree used to print for the by-rule view.
        Assert.DoesNotContain("No open dynamic-scan findings", body);
    }

    [SkippableTheory]
    [InlineData("10202", "Absence of anti-CSRF tokens")]
    [InlineData("40012", "Cross site scripting")]
    public async Task Selecting_a_rule_lists_its_occurrences(string rule, string title)
    {
        Skip.IfNot(_fx.Available, "TAMP_FINDINGS_TEST_DB not set");
        var w = await PageBWorld.GetAsync(_fx);

        var (status, body) = await w.GetAsync(w.Build("latest", "dast/" + rule) + "?group=rule");

        Assert.Equal(HttpStatusCode.OK, status);
        Assert.Contains(rule, body);
        Assert.Contains(title, body);
    }

    [SkippableFact]
    public async Task Grouping_by_path_still_lists_hosts_and_routes()
    {
        Skip.IfNot(_fx.Available, "TAMP_FINDINGS_TEST_DB not set");
        var w = await PageBWorld.GetAsync(_fx);

        var (status, body) = await w.GetAsync(w.Build("latest", "dast"));

        Assert.Equal(HttpStatusCode.OK, status);
        Assert.DoesNotContain("No open dynamic-scan findings", body);
        Assert.Contains("app.example.test", body);
    }

    [SkippableFact]
    public async Task A_build_with_no_dynamic_findings_still_says_so_in_either_grouping()
    {
        Skip.IfNot(_fx.Available, "TAMP_FINDINGS_TEST_DB not set");
        var w = await PageBWorld.GetAsync(_fx);

        var (_, byPath) = await w.GetAsync($"/c/{w.Client}/p/{w.Empty}/build/latest/dast");
        var (_, byRule) = await w.GetAsync($"/c/{w.Client}/p/{w.Empty}/build/latest/dast?group=rule");

        Assert.Contains("No open dynamic-scan findings", byPath);
        Assert.DoesNotContain("Could not load this evidence", byRule);
    }
}
