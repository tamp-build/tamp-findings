using System.Text;
using Tamp.Findings.Application.Compliance.Oscal;
using Tamp.Findings.Domain.Compliance;

namespace Tamp.Findings.Application.Tests;

// The baseline-profile parse + catalog import (TFND-180): a control's baseline
// membership comes from the profiles, not a guess.
public class OscalImportTests
{
    private const string Catalog = """
    {"catalog":{"metadata":{"version":"5.2.0","oscal-version":"1.2.2"},"groups":[
      {"id":"cm","title":"Configuration Management","controls":[
        {"id":"cm-6","title":"Configuration Settings","parts":[{"name":"statement","prose":"Establish settings."}],
         "controls":[{"id":"cm-6.1","title":"Automated","parts":[{"name":"statement","prose":"Automate."}]}]}
      ]},
      {"id":"sc","title":"System and Communications Protection","controls":[
        {"id":"sc-7","title":"Boundary Protection","parts":[{"name":"statement","prose":"Protect the boundary."}]}
      ]}
    ]}}
    """;

    private const string LowProfile = """
    {"profile":{"imports":[{"href":"catalog.json","include-controls":[{"with-ids":["cm-6","sc-7"]}]}]}}
    """;
    private const string ModerateProfile = """
    {"profile":{"imports":[{"href":"catalog.json","include-controls":[{"with-ids":["cm-6","cm-6.1","sc-7"]}]}]}}
    """;

    [Fact]
    public void A_profile_yields_its_control_ids()
    {
        var ids = OscalProfileParser.Parse(ModerateProfile);
        Assert.Equal(3, ids.Count);
        Assert.Contains("cm-6.1", ids);
    }

    [Fact]
    public void Baseline_membership_is_set_from_the_profiles()
    {
        var import = new OscalImportService();
        var profiles = new Dictionary<BaselineLevel, Stream>
        {
            [BaselineLevel.Low] = S(LowProfile),
            [BaselineLevel.Moderate] = S(ModerateProfile),
        };
        var catalog = import.BuildCatalog(S(Catalog), profiles, "test", "sha1");

        Assert.Equal("NIST SP 800-53 Rev 5 5.2.0", catalog.Name);
        Assert.Equal("1.2.2", catalog.OscalVersion);
        Assert.True(catalog.IsCurrent);
        Assert.Equal("sha1", catalog.ImportedSha);

        var cm6 = catalog.Controls.Single(c => c.Id == "CM-6");
        // In both Low and Moderate.
        Assert.True(cm6.InBaseline(BaselineLevel.Low));
        Assert.True(cm6.InBaseline(BaselineLevel.Moderate));
        Assert.False(cm6.InBaseline(BaselineLevel.High));

        var enh = catalog.Controls.Single(c => c.Id == "CM-6(1)");
        // Only in Moderate (with-ids "cm-6.1"), not Low.
        Assert.False(enh.InBaseline(BaselineLevel.Low));
        Assert.True(enh.InBaseline(BaselineLevel.Moderate));
    }

    private static Stream S(string s) => new MemoryStream(Encoding.UTF8.GetBytes(s));
}
