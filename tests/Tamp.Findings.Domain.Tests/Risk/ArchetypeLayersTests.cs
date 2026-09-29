using Tamp.Findings.Domain.Risk;
using Tamp.Findings.Domain.Values;

namespace Tamp.Findings.Domain.Tests.Risk;

// The archetype obligation layers (TFND-203). These pin the two properties the whole design
// rests on: (1) the layer is ADDITIVE — it never sets a mode, denies a licence, or asserts a
// control, so under the strictest-wins merge it can only ADD obligations, never subtract one
// (downgrade-proof); (2) an unclassified project fails UPWARD to the strictest archetype.
public class ArchetypeLayersTests
{
    [Fact]
    public void Library_adds_nothing_over_the_baseline()
    {
        var lib = ArchetypeLayers.For(ProjectArchetype.Library);
        Assert.Empty(lib.Gates);
        Assert.Empty(lib.RequiredScanners);
    }

    [Fact]
    public void Container_adds_base_image_only()
    {
        var c = ArchetypeLayers.For(ProjectArchetype.ContainerAction);
        Assert.True(c.Gates[GateKeys.BaseImageAge].Enabled);
        Assert.False(c.Gates.ContainsKey(GateKeys.CriticalDast));
        Assert.Empty(c.RequiredScanners);
    }

    [Fact]
    public void Service_adds_dast_iac_and_base_image_required_and_gated()
    {
        var s = ArchetypeLayers.For(ProjectArchetype.ServiceApp);
        Assert.Contains(PolicyTemplateDefaults.ScannerClasses.DynamicScan, s.RequiredScanners);
        Assert.Contains(PolicyTemplateDefaults.ScannerClasses.Iac, s.RequiredScanners);
        Assert.True(s.Gates[GateKeys.CriticalDast].Enabled);
        Assert.True(s.Gates[GateKeys.CriticalIac].Enabled);
        Assert.True(s.Gates[GateKeys.BaseImageAge].Enabled);
    }

    [Fact]
    public void Unclassified_fails_upward_to_service()
    {
        var unset = ArchetypeLayers.For(null);
        var service = ArchetypeLayers.For(ProjectArchetype.ServiceApp);
        // Same obligations as an explicit Service — the strictest posture.
        Assert.True(unset.Gates[GateKeys.CriticalDast].Enabled);
        Assert.Equal(service.Gates.Count, unset.Gates.Count);
        Assert.Equal(service.RequiredScanners.Count, unset.RequiredScanners.Count);
    }

    [Theory]
    [InlineData(null)]
    [InlineData(ProjectArchetype.Library)]
    [InlineData(ProjectArchetype.ContainerAction)]
    [InlineData(ProjectArchetype.ServiceApp)]
    public void Every_archetype_layer_is_additive_only_never_loosens(ProjectArchetype? archetype)
    {
        var layer = ArchetypeLayers.For(archetype);
        // Additive-only: it carries no mode, no licence denials, no control assertions, no POA&M
        // windows — only gate/required-scanner ADDITIONS. So a merge can never use it to loosen.
        Assert.Null(layer.Mode);
        Assert.Empty(layer.DeniedLicenses);
        Assert.Empty(layer.Assertions);
        Assert.Empty(layer.PoamDeadlineDays);
    }
}
