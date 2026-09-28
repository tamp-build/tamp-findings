using Tamp.Findings.Domain.Risk;
using Tamp.Findings.Domain.Values;

namespace Tamp.Findings.Domain.Tests;

// The harden-only guard (ADR 0007). A false negative here lets a lower layer
// silently weaken the baseline it inherits, so every loosening shape is tested.
public class PolicyLayerCompareTests
{
    [Fact]
    public void An_identical_layer_loosens_nothing()
    {
        var l = new PolicyLayer { Mode = EnforcementMode.Enforcing };
        l.Gates["kevExposure"] = new GateConfig { Enabled = true, Threshold = 0 };
        Assert.True(PolicyLayerCompare.HardensOrEqual(l, Clone(l)));
    }

    [Fact]
    public void Weakening_the_mode_loosens()
    {
        var baseline = new PolicyLayer { Mode = EnforcementMode.Enforcing };
        var proposed = new PolicyLayer { Mode = EnforcementMode.Advisory };
        Assert.Contains(PolicyLayerCompare.Loosens(baseline, proposed), s => s.Contains("enforcement mode"));
    }

    [Fact]
    public void Tightening_the_mode_does_not_loosen()
    {
        var baseline = new PolicyLayer { Mode = EnforcementMode.Advisory };
        var proposed = new PolicyLayer { Mode = EnforcementMode.Enforcing };
        Assert.True(PolicyLayerCompare.HardensOrEqual(baseline, proposed));
    }

    [Fact]
    public void Removing_a_required_scanner_or_denied_licence_loosens()
    {
        var baseline = new PolicyLayer { RequiredScanners = { "Static analysis" }, DeniedLicenses = { "AGPL-*" } };
        var proposed = new PolicyLayer(); // dropped both
        var loosened = PolicyLayerCompare.Loosens(baseline, proposed);
        Assert.Contains(loosened, s => s.Contains("Static analysis"));
        Assert.Contains(loosened, s => s.Contains("AGPL-*"));
    }

    [Fact]
    public void Adding_a_scanner_or_licence_does_not_loosen()
    {
        var baseline = new PolicyLayer { RequiredScanners = { "Static analysis" } };
        var proposed = new PolicyLayer { RequiredScanners = { "Static analysis", "Dynamic scan" }, DeniedLicenses = { "SSPL-1.0" } };
        Assert.True(PolicyLayerCompare.HardensOrEqual(baseline, proposed));
    }

    [Fact]
    public void Turning_off_an_enabled_gate_loosens()
    {
        var baseline = new PolicyLayer();
        baseline.Gates["criticalSast"] = new GateConfig { Enabled = true };
        var proposed = new PolicyLayer();
        proposed.Gates["criticalSast"] = new GateConfig { Enabled = false };
        Assert.Contains(PolicyLayerCompare.Loosens(baseline, proposed), s => s.Contains("criticalSast"));
    }

    [Fact]
    public void Raising_a_gate_threshold_loosens_lowering_does_not()
    {
        var baseline = new PolicyLayer();
        baseline.Gates["highCves"] = new GateConfig { Enabled = true, Threshold = 5 };

        var raised = new PolicyLayer();
        raised.Gates["highCves"] = new GateConfig { Enabled = true, Threshold = 10 };
        Assert.Contains(PolicyLayerCompare.Loosens(baseline, raised), s => s.Contains("highCves"));

        var lowered = new PolicyLayer();
        lowered.Gates["highCves"] = new GateConfig { Enabled = true, Threshold = 2 };
        Assert.True(PolicyLayerCompare.HardensOrEqual(baseline, lowered));
    }

    [Fact]
    public void Lengthening_or_dropping_a_poam_deadline_loosens()
    {
        var baseline = new PolicyLayer { PoamDeadlineDays = { ["Critical"] = 30, ["High"] = 90 } };

        var lengthened = new PolicyLayer { PoamDeadlineDays = { ["Critical"] = 45, ["High"] = 90 } };
        Assert.Contains(PolicyLayerCompare.Loosens(baseline, lengthened), s => s.Contains("Critical"));

        var dropped = new PolicyLayer { PoamDeadlineDays = { ["Critical"] = 30 } }; // High removed
        Assert.Contains(PolicyLayerCompare.Loosens(baseline, dropped), s => s.Contains("High"));

        var shortened = new PolicyLayer { PoamDeadlineDays = { ["Critical"] = 15, ["High"] = 60 } };
        Assert.True(PolicyLayerCompare.HardensOrEqual(baseline, shortened));
    }

    private static PolicyLayer Clone(PolicyLayer l) => new()
    {
        Mode = l.Mode,
        RequiredScanners = [.. l.RequiredScanners],
        DeniedLicenses = [.. l.DeniedLicenses],
        Gates = l.Gates.ToDictionary(k => k.Key, v => new GateConfig { Enabled = v.Value.Enabled, Threshold = v.Value.Threshold }),
        PoamDeadlineDays = new(l.PoamDeadlineDays),
    };
}
