using Tamp.Findings.Domain.Risk;
using Tamp.Findings.Domain.Values;

namespace Tamp.Findings.Domain.Tests;

// The three-layer merge (ADR 0007) is what an assessor's effective policy is
// computed from, so every rule here is harden-only and reproducible: strictest
// value wins, and the winning layer is recorded.
public class PolicyLayerMergeTests
{
    private static (PolicyLayer, string) L(string source, Action<PolicyLayer> build)
    {
        var l = new PolicyLayer();
        build(l);
        return (l, source);
    }

    [Fact]
    public void A_single_layer_passes_through_with_its_own_attribution()
    {
        var eff = PolicyLayerMerge.Resolve([
            L("Tamp Standard v1", l => {
                l.Mode = EnforcementMode.Advisory;
                l.RequiredScanners.Add("Static analysis");
                l.DeniedLicenses.Add("SSPL-1.0");
                l.Gates["kevExposure"] = new GateConfig { Enabled = true, Threshold = 0 };
                l.PoamDeadlineDays["Critical"] = 30;
            }),
        ]);

        Assert.Equal(EnforcementMode.Advisory, eff.Mode!.Value);
        Assert.Equal("Tamp Standard v1", eff.Mode.Source);
        Assert.Equal("Tamp Standard v1", eff.RequiredScanners.Single(s => s.Value == "Static analysis").Source);
        Assert.True(eff.Gates["kevExposure"].Enabled);
        Assert.Equal("Tamp Standard v1", eff.Gates["kevExposure"].Source);
        Assert.Equal(30, eff.PoamDeadlineDays["Critical"].Value);
    }

    [Fact]
    public void Mode_takes_the_stricter_and_records_the_layer_that_tightened_it()
    {
        var eff = PolicyLayerMerge.Resolve([
            L("template", l => l.Mode = EnforcementMode.Advisory),
            L("client", l => l.Mode = EnforcementMode.Enforcing),
            L("project", l => l.Mode = null), // says nothing
        ]);

        Assert.Equal(EnforcementMode.Enforcing, eff.Mode!.Value);
        Assert.Equal("client", eff.Mode.Source);
    }

    [Fact]
    public void A_lower_layer_cannot_loosen_the_mode()
    {
        // Project asks for Advisory but the template is Enforcing: strictest wins.
        var eff = PolicyLayerMerge.Resolve([
            L("template", l => l.Mode = EnforcementMode.Enforcing),
            L("project", l => l.Mode = EnforcementMode.Advisory),
        ]);

        Assert.Equal(EnforcementMode.Enforcing, eff.Mode!.Value);
        Assert.Equal("template", eff.Mode.Source);
    }

    [Fact]
    public void Scanners_and_denied_licences_union_with_first_owner_attribution()
    {
        var eff = PolicyLayerMerge.Resolve([
            L("template", l => { l.RequiredScanners.Add("Static analysis"); l.DeniedLicenses.Add("AGPL-*"); }),
            L("client", l => { l.RequiredScanners.Add("Dynamic scan"); l.DeniedLicenses.Add("AGPL-*"); l.DeniedLicenses.Add("BUSL-1.1"); }),
        ]);

        Assert.Equal(2, eff.RequiredScanners.Count);
        Assert.Equal("template", eff.RequiredScanners.Single(s => s.Value == "Static analysis").Source);
        Assert.Equal("client", eff.RequiredScanners.Single(s => s.Value == "Dynamic scan").Source);
        // AGPL was first denied by the template — the client repeating it does not steal attribution.
        Assert.Equal("template", eff.DeniedLicenses.Single(d => d.Value == "AGPL-*").Source);
        Assert.Equal("client", eff.DeniedLicenses.Single(d => d.Value == "BUSL-1.1").Source);
    }

    [Fact]
    public void An_off_gate_becomes_on_when_a_lower_layer_enables_it()
    {
        var eff = PolicyLayerMerge.Resolve([
            L("template", l => l.Gates["criticalSast"] = new GateConfig { Enabled = false }),
            L("project", l => l.Gates["criticalSast"] = new GateConfig { Enabled = true }),
        ]);

        Assert.True(eff.Gates["criticalSast"].Enabled);
        Assert.Equal("project", eff.Gates["criticalSast"].Source);
    }

    [Fact]
    public void A_gate_threshold_tightens_to_the_lowest_value_and_records_that_layer()
    {
        var eff = PolicyLayerMerge.Resolve([
            L("template", l => l.Gates["highCves"] = new GateConfig { Enabled = true, Threshold = 5 }),
            L("client", l => l.Gates["highCves"] = new GateConfig { Enabled = true, Threshold = 2 }),
            L("project", l => l.Gates["highCves"] = new GateConfig { Enabled = true, Threshold = 10 }), // looser — ignored
        ]);

        Assert.True(eff.Gates["highCves"].Enabled);
        Assert.Equal(2, eff.Gates["highCves"].Threshold);
        Assert.Equal("client", eff.Gates["highCves"].Source);
    }

    [Fact]
    public void An_unset_threshold_loses_to_any_real_value()
    {
        var eff = PolicyLayerMerge.Resolve([
            L("template", l => l.Gates["baseImageAge"] = new GateConfig { Enabled = true, Threshold = null }),
            L("client", l => l.Gates["baseImageAge"] = new GateConfig { Enabled = true, Threshold = 90 }),
        ]);

        Assert.Equal(90, eff.Gates["baseImageAge"].Threshold);
    }

    [Fact]
    public void Poam_deadlines_take_the_shortest_days_per_severity()
    {
        var eff = PolicyLayerMerge.Resolve([
            L("template", l => { l.PoamDeadlineDays["Critical"] = 30; l.PoamDeadlineDays["High"] = 90; }),
            L("client", l => l.PoamDeadlineDays["Critical"] = 15),          // tightens
            L("project", l => l.PoamDeadlineDays["High"] = 120),            // looser — ignored
        ]);

        Assert.Equal(15, eff.PoamDeadlineDays["Critical"].Value);
        Assert.Equal("client", eff.PoamDeadlineDays["Critical"].Source);
        Assert.Equal(90, eff.PoamDeadlineDays["High"].Value);
        Assert.Equal("template", eff.PoamDeadlineDays["High"].Source);
    }

    [Fact]
    public void An_empty_layer_list_resolves_to_nothing_set()
    {
        var eff = PolicyLayerMerge.Resolve([]);

        Assert.Null(eff.Mode);
        Assert.Empty(eff.RequiredScanners);
        Assert.Empty(eff.Gates);
        Assert.Empty(eff.DeniedLicenses);
        Assert.Empty(eff.PoamDeadlineDays);
    }

    [Fact]
    public void A_gate_enabled_high_then_tightened_low_keeps_on_and_the_tightening_source()
    {
        // template enables at a loose threshold; project keeps it on but tightens.
        var eff = PolicyLayerMerge.Resolve([
            L("template", l => l.Gates["coverageRegression"] = new GateConfig { Enabled = true, Threshold = 2 }),
            L("project", l => l.Gates["coverageRegression"] = new GateConfig { Enabled = true, Threshold = 0.5 }),
        ]);

        var g = eff.Gates["coverageRegression"];
        Assert.True(g.Enabled);
        Assert.Equal(0.5, g.Threshold);
        Assert.Equal("project", g.Source);
    }
}
