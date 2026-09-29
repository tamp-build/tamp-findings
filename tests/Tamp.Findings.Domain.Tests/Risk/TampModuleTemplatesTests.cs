using Tamp.Findings.Domain.Risk;
using Tamp.Findings.Domain.Values;

namespace Tamp.Findings.Domain.Tests.Risk;

// The tamp-ecosystem module archetype templates (non-federal). A module is a
// component, not an authorized system: it carries a supply-chain posture, never a
// control baseline. These pin that distinction so a refactor can't quietly turn a
// module template into a federal one (control assertions / no-unmapped) or relax it
// below the enforcing supply-chain floor.
public class TampModuleTemplatesTests
{
    public static IEnumerable<object[]> AllThree() =>
    [
        [PolicyTemplateDefaults.BuildTampModuleLibrary()],
        [PolicyTemplateDefaults.BuildTampModuleContainer()],
        [PolicyTemplateDefaults.BuildTampModuleService()],
    ];

    [Theory]
    [MemberData(nameof(AllThree))]
    public void Every_module_template_is_enforcing_supply_chain_and_carries_no_control_baseline(PolicyLayer layer)
    {
        Assert.Equal(EnforcementMode.Enforcing, layer.Mode);

        // The "don't ship" floor is present on all three.
        Assert.True(layer.Gates[GateKeys.KevExposure].Enabled);
        Assert.True(layer.Gates[GateKeys.CriticalCves].Enabled);
        Assert.True(layer.Gates[GateKeys.CriticalSast].Enabled);
        Assert.True(layer.Gates[GateKeys.VerifiedSecrets].Enabled);
        Assert.True(layer.Gates[GateKeys.SbomAge].Enabled);
        Assert.Contains("SSPL-1.0", layer.DeniedLicenses);

        // Non-federal: no control-disposition assertions and no no-unmapped meta-gate.
        Assert.Empty(layer.Assertions);
        Assert.False(layer.Gates.ContainsKey(GateKeys.NoUnmapped));

        // Coverage is collected/scored, never a release blocker for a module.
        Assert.False(layer.Gates.ContainsKey(GateKeys.CoverageFloor));
    }

    [Fact]
    public void Library_requires_only_the_source_and_deps_scanner_floor_no_web_or_iac()
    {
        var lib = PolicyTemplateDefaults.BuildTampModuleLibrary();
        Assert.Contains(PolicyTemplateDefaults.ScannerClasses.StaticAnalysis, lib.RequiredScanners);
        Assert.Contains(PolicyTemplateDefaults.ScannerClasses.Secrets, lib.RequiredScanners);
        Assert.Contains(PolicyTemplateDefaults.ScannerClasses.Sbom, lib.RequiredScanners);
        Assert.Contains(PolicyTemplateDefaults.ScannerClasses.Coverage, lib.RequiredScanners);
        // A library is never expected to run a dynamic scan or IaC scan.
        Assert.DoesNotContain(PolicyTemplateDefaults.ScannerClasses.DynamicScan, lib.RequiredScanners);
        Assert.DoesNotContain(PolicyTemplateDefaults.ScannerClasses.Iac, lib.RequiredScanners);
        // And no image / web / iac gates.
        Assert.False(lib.Gates.ContainsKey(GateKeys.BaseImageAge));
        Assert.False(lib.Gates.ContainsKey(GateKeys.CriticalDast));
        Assert.False(lib.Gates.ContainsKey(GateKeys.CriticalIac));
    }

    [Fact]
    public void Container_adds_base_image_freshness_over_the_library_floor()
    {
        var c = PolicyTemplateDefaults.BuildTampModuleContainer();
        Assert.True(c.Gates[GateKeys.BaseImageAge].Enabled);
        // Still not web-facing: no DAST required or gated.
        Assert.DoesNotContain(PolicyTemplateDefaults.ScannerClasses.DynamicScan, c.RequiredScanners);
        Assert.False(c.Gates.ContainsKey(GateKeys.CriticalDast));
    }

    [Fact]
    public void Service_requires_and_gates_dast_and_iac_plus_base_image()
    {
        var s = PolicyTemplateDefaults.BuildTampModuleService();
        Assert.Contains(PolicyTemplateDefaults.ScannerClasses.DynamicScan, s.RequiredScanners);
        Assert.Contains(PolicyTemplateDefaults.ScannerClasses.Iac, s.RequiredScanners);
        Assert.True(s.Gates[GateKeys.CriticalDast].Enabled);
        Assert.True(s.Gates[GateKeys.CriticalIac].Enabled);
        Assert.True(s.Gates[GateKeys.BaseImageAge].Enabled);
    }
}
