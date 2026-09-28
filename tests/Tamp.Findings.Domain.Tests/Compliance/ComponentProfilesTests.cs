using Tamp.Findings.Domain.Compliance;
using Tamp.Findings.Domain.Risk;

namespace Tamp.Findings.Domain.Tests;

// The capability axis (TFND-183). A library cannot produce DAST/IaC; a service
// can. Getting this wrong is the false-pass class the whole feature exists to
// prevent, so the applicability of the conditional scanners is pinned.
public class ComponentProfilesTests
{
    [Theory]
    [InlineData(ComponentProfile.CodePackage, false, false)]
    [InlineData(ComponentProfile.Container, false, false)]
    [InlineData(ComponentProfile.Service, true, true)]
    public void Conditional_scanners_apply_only_where_the_capability_exists(
        ComponentProfile profile, bool dastApplies, bool iacApplies)
    {
        Assert.Equal(dastApplies, ComponentProfiles.ScannerApplies(profile, PolicyTemplateDefaults.ScannerClasses.DynamicScan));
        Assert.Equal(iacApplies, ComponentProfiles.ScannerApplies(profile, PolicyTemplateDefaults.ScannerClasses.Iac));
    }

    [Theory]
    [InlineData(ComponentProfile.CodePackage)]
    [InlineData(ComponentProfile.Container)]
    [InlineData(ComponentProfile.Service)]
    public void Always_on_scanners_apply_to_every_profile(ComponentProfile profile)
    {
        Assert.True(ComponentProfiles.ScannerApplies(profile, PolicyTemplateDefaults.ScannerClasses.StaticAnalysis));
        Assert.True(ComponentProfiles.ScannerApplies(profile, PolicyTemplateDefaults.ScannerClasses.Secrets));
        Assert.True(ComponentProfiles.ScannerApplies(profile, PolicyTemplateDefaults.ScannerClasses.Sbom));
        Assert.True(ComponentProfiles.ScannerApplies(profile, PolicyTemplateDefaults.ScannerClasses.Coverage));
    }

    [Fact]
    public void Image_capability_climbs_with_the_profile()
    {
        Assert.False(ComponentProfiles.Has(ComponentProfile.CodePackage, ComponentCapability.Image));
        Assert.True(ComponentProfiles.Has(ComponentProfile.Container, ComponentCapability.Image));
        Assert.True(ComponentProfiles.Has(ComponentProfile.Service, ComponentCapability.Image));
        Assert.True(ComponentProfiles.Has(ComponentProfile.Service, ComponentCapability.Web));
        Assert.False(ComponentProfiles.Has(ComponentProfile.Container, ComponentCapability.Web));
    }

    [Theory]
    [InlineData("service", ComponentProfile.Service)]
    [InlineData("web-service", ComponentProfile.Service)]
    [InlineData("container", ComponentProfile.Container)]
    [InlineData("image", ComponentProfile.Container)]
    [InlineData("code-package", ComponentProfile.CodePackage)]
    [InlineData("library", ComponentProfile.CodePackage)]
    [InlineData("", ComponentProfile.CodePackage)]
    [InlineData(null, ComponentProfile.CodePackage)]
    [InlineData("nonsense", ComponentProfile.CodePackage)]
    public void Declared_profile_parses_leniently_defaulting_to_code_package(string? declared, ComponentProfile expected)
    {
        Assert.Equal(expected, ComponentProfiles.Parse(declared));
    }
}
