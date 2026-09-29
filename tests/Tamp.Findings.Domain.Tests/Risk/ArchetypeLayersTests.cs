using Tamp.Findings.Domain.Compliance;
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
    public void Library_adds_no_gates_but_asserts_control_applicability()
    {
        var lib = ArchetypeLayers.For(ProjectArchetype.Library);
        // A library owes no extra GATES or scanners over the baseline.
        Assert.Empty(lib.Gates);
        Assert.Empty(lib.RequiredScanners);
        // But it does declare the runtime control families it inherits and the ones that don't apply.
        var inherited = lib.Assertions.Where(a => a.Kind == ControlDispositionKind.Inherited).SelectMany(a => a.ControlIds).ToHashSet();
        var na = lib.Assertions.Where(a => a.Kind == ControlDispositionKind.NotApplicable).SelectMany(a => a.ControlIds).ToHashSet();
        Assert.Contains("AC-2", inherited);     // access control — the deploying system's
        Assert.Contains("AU-2", inherited);     // audit logging — the deploying system's
        Assert.Contains("IA-2", inherited);     // user authentication — the deploying system's
        Assert.Contains("AC-18", na);           // wireless — no applicable surface
        // A library never GATES via the archetype layer (that would claim it owns + proves the control).
        Assert.DoesNotContain("SA-11", inherited);   // developer testing is OWNED (template-gated), not inherited
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

    // The trust fix: gate applicability comes from the human-assigned archetype's capability,
    // not the caller-declared component profile. Library can't produce web/iac, Service can.
    [Fact]
    public void Library_capability_excludes_web_iac_and_image()
    {
        var cap = ArchetypeLayers.Capability(ProjectArchetype.Library);
        Assert.True(cap.HasFlag(ComponentCapability.Source));
        Assert.True(cap.HasFlag(ComponentCapability.Deps));
        Assert.False(cap.HasFlag(ComponentCapability.Web));
        Assert.False(cap.HasFlag(ComponentCapability.Iac));
        Assert.False(cap.HasFlag(ComponentCapability.Image));
    }

    [Fact]
    public void Container_capability_adds_image_but_not_web()
    {
        var cap = ArchetypeLayers.Capability(ProjectArchetype.ContainerAction);
        Assert.True(cap.HasFlag(ComponentCapability.Image));
        Assert.False(cap.HasFlag(ComponentCapability.Web));
    }

    [Fact]
    public void Service_capability_includes_web_iac_and_image()
    {
        var cap = ArchetypeLayers.Capability(ProjectArchetype.ServiceApp);
        Assert.True(cap.HasFlag(ComponentCapability.Web));
        Assert.True(cap.HasFlag(ComponentCapability.Iac));
        Assert.True(cap.HasFlag(ComponentCapability.Image));
    }

    [Fact]
    public void Unclassified_capability_fails_upward_to_service()
    {
        Assert.Equal(ArchetypeLayers.Capability(ProjectArchetype.ServiceApp), ArchetypeLayers.Capability(null));
    }

    [Theory]
    [InlineData(null)]
    [InlineData(ProjectArchetype.Library)]
    [InlineData(ProjectArchetype.ContainerAction)]
    [InlineData(ProjectArchetype.ServiceApp)]
    public void Every_archetype_layer_is_additive_only_never_loosens(ProjectArchetype? archetype)
    {
        var layer = ArchetypeLayers.For(archetype);
        // Additive-only: no mode override, no licence denials, no POA&M windows — only gate/scanner
        // ADDITIONS and control-APPLICABILITY assertions, so a merge can never use it to loosen.
        Assert.Null(layer.Mode);
        Assert.Empty(layer.DeniedLicenses);
        Assert.Empty(layer.PoamDeadlineDays);
        // Any assertions it carries are applicability only (Inherited / NotApplicable) — never a Gated
        // ownership claim, which under strictest-wins is the one kind that could displace a stricter
        // upper-layer disposition.
        Assert.All(layer.Assertions, a =>
            Assert.True(a.Kind is ControlDispositionKind.Inherited or ControlDispositionKind.NotApplicable,
                $"archetype assertions must be applicability-only, found {a.Kind}"));
    }
}
