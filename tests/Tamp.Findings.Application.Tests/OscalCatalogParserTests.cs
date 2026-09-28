using Tamp.Findings.Application.Compliance.Oscal;
using Tamp.Findings.Domain.Compliance;

namespace Tamp.Findings.Application.Tests;

// The OSCAL catalog import (TFND-180). The hard part is turning OSCAL's
// {{ insert: param, id }} markers back into the [Assignment]/[Selection] bracket
// form the statement panel already reads — so these pin that resolution,
// including a nested selection.
public class OscalCatalogParserTests
{
    private const string Catalog = """
    {
      "catalog": {
        "metadata": { "version": "5.2.0", "oscal-version": "1.2.2" },
        "groups": [
          { "id": "cm", "title": "Configuration Management", "controls": [
            { "id": "cm-6", "title": "Configuration Settings",
              "params": [
                { "id": "cm-6_prm_1", "label": "organization-defined common secure configurations" },
                { "id": "cm-6_prm_2", "label": "organization-defined system components" }
              ],
              "parts": [
                { "id": "cm-6_smt", "name": "statement", "parts": [
                  { "name": "item", "props": [{ "name": "label", "value": "a." }],
                    "prose": "Establish settings using {{ insert: param, cm-6_prm_1 }};" },
                  { "name": "item", "props": [{ "name": "label", "value": "b." }],
                    "prose": "Implement the configuration settings;" }
                ]}
              ],
              "controls": [
                { "id": "cm-6.1", "title": "Automated Management", "parts": [
                  { "name": "statement", "prose": "Manage settings for {{ insert: param, cm-6_prm_2 }}." }
                ]}
              ]}
          ]},
          { "id": "sc", "title": "System and Communications Protection", "controls": [
            { "id": "sc-7", "title": "Boundary Protection",
              "params": [{ "id": "sc-7_prm_1", "select": { "how-many": "one-or-more", "choice": ["physically", "logically"] } }],
              "parts": [{ "id": "sc-7_smt", "name": "statement",
                "prose": "Implement subnetworks that are {{ insert: param, sc-7_prm_1 }} separated." }]}
          ]}
        ]
      }
    }
    """;

    [Fact]
    public void It_reads_the_catalog_version_and_every_control_including_enhancements()
    {
        var parsed = OscalCatalogParser.Parse(Catalog);

        Assert.Equal("5.2.0", parsed.Version);
        Assert.Equal("1.2.2", parsed.OscalVersion);
        // cm-6, its enhancement cm-6.1, and sc-7.
        Assert.Equal(3, parsed.Controls.Count);
        Assert.Contains(parsed.Controls, c => c.Id == "CM-6");
        Assert.Contains(parsed.Controls, c => c.Id == "CM-6(1)");   // enhancement id form
        Assert.Contains(parsed.Controls, c => c.Id == "SC-7");
    }

    [Fact]
    public void An_assignment_marker_becomes_an_assignment_bracket()
    {
        var cm6 = OscalCatalogParser.Parse(Catalog).Controls.Single(c => c.Id == "CM-6");

        Assert.Equal("Configuration Management", cm6.Family);
        Assert.Contains(cm6.StatementLines, l => l.StartsWith("a. ") && l.Contains("[Assignment: organization-defined common secure configurations]"));
        Assert.Contains(cm6.StatementLines, l => l.StartsWith("b. "));
        // The resolved bracket is parseable as one parameter chip.
        var line = cm6.StatementLines.First(l => l.StartsWith("a. "));
        var param = ControlStatementParser.Parse(line).Single(s => s.IsParameter);
        Assert.Equal(ParameterKind.Assignment, param.Kind);
    }

    [Fact]
    public void A_selection_marker_becomes_a_selection_bracket()
    {
        var sc7 = OscalCatalogParser.Parse(Catalog).Controls.Single(c => c.Id == "SC-7");

        var line = Assert.Single(sc7.StatementLines);
        Assert.Contains("[Selection (one or more): physically; logically]", line);
        var param = ControlStatementParser.Parse(line).Single(s => s.IsParameter);
        Assert.Equal(ParameterKind.Selection, param.Kind);
    }

    [Fact]
    public void An_enhancement_resolves_its_own_parameter()
    {
        var enh = OscalCatalogParser.Parse(Catalog).Controls.Single(c => c.Id == "CM-6(1)");
        var line = Assert.Single(enh.StatementLines);
        Assert.Contains("[Assignment: organization-defined system components]", line);
    }
}
