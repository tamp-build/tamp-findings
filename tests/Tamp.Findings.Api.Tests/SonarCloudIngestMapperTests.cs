using System.Text.Json;
using Tamp.Findings.Build.Adapters;
using Tamp.Findings.Domain.Values;

namespace Tamp.Findings.Api.Tests;

// TFND-227: SonarQube Cloud API responses mapped onto findings ingest. Findings does the type routing; the
// mapper's job is to carry the Sonar issue TYPE on SubCategory and map severity honestly.
public class SonarCloudIngestMapperTests
{
    private const string Key = "tamp-build_tamp-findings";

    private static JsonElement Json(string json) => JsonDocument.Parse(json).RootElement.Clone();

    [Theory]
    [InlineData("BUG", FindingTypes.Bug)]
    [InlineData("CODE_SMELL", FindingTypes.CodeSmell)]
    [InlineData("VULNERABILITY", FindingTypes.Vulnerability)]
    [InlineData("SECURITY_HOTSPOT", FindingTypes.SecurityHotspot)]
    public void The_sonar_issue_type_becomes_the_sub_category(string sonarType, string expected)
    {
        var issue = Json($$"""{"rule":"csharpsquid:S2325","severity":"MAJOR","type":"{{sonarType}}","message":"m","component":"{{Key}}:src/A.cs","line":7}""");

        var f = SonarCloudIngestMapper.MapIssues([issue], Key).Single();

        Assert.Equal(expected, f.SubCategory);
    }

    [Fact]
    public void An_issue_carries_rule_message_path_and_line_and_the_project_prefix_is_stripped()
    {
        var issue = Json($$"""{"rule":"csharpsquid:S1118","severity":"CRITICAL","type":"CODE_SMELL","message":"Add a protected constructor","component":"{{Key}}:src/Tamp.Findings.Api/Program.cs","line":42}""");

        var f = SonarCloudIngestMapper.MapIssues([issue], Key).Single();

        Assert.Equal("csharpsquid:S1118", f.RuleId);
        Assert.Equal("Add a protected constructor", f.Title);
        Assert.Equal("src/Tamp.Findings.Api/Program.cs", f.FilePath);
        Assert.Equal(42, f.Line);
        Assert.Equal(Severity.High, f.Severity);
    }

    [Theory]
    [InlineData("BLOCKER", Severity.Critical)]
    [InlineData("CRITICAL", Severity.High)]
    [InlineData("MAJOR", Severity.Medium)]
    [InlineData("MINOR", Severity.Low)]
    [InlineData("INFO", Severity.Info)]
    [InlineData("SOMETHING_NEW", Severity.Medium)]
    [InlineData(null, Severity.Medium)]
    public void Sonar_severity_maps_onto_ours_and_an_unknown_one_is_not_dropped_or_inflated(string? sonar, Severity expected) =>
        Assert.Equal(expected, SonarCloudIngestMapper.IssueSeverity(sonar));

    [Fact]
    public void An_issue_without_a_rule_is_skipped_and_a_project_level_issue_has_no_file()
    {
        var noRule = Json("""{"severity":"MAJOR","type":"BUG","message":"x"}""");
        var projectLevel = Json($$"""{"rule":"r","severity":"MINOR","type":"BUG","message":"x","component":"{{Key}}"}""");

        var mapped = SonarCloudIngestMapper.MapIssues([noRule, projectLevel], Key);

        Assert.Single(mapped);
        Assert.Null(mapped[0].FilePath);
        Assert.Null(mapped[0].Line);
    }

    [Fact]
    public void A_hotspot_is_a_security_hotspot_with_severity_from_its_vulnerability_probability()
    {
        var high = Json($$"""{"ruleKey":"csharpsquid:S5122","vulnerabilityProbability":"HIGH","message":"CORS","securityCategory":"cors","component":"{{Key}}:src/P.cs","line":3}""");
        var low = Json($$"""{"ruleKey":"csharpsquid:S2077","vulnerabilityProbability":"LOW","message":"sql","component":"{{Key}}:src/Q.cs"}""");

        var mapped = SonarCloudIngestMapper.MapHotspots([high, low], Key);

        Assert.All(mapped, f => Assert.Equal(FindingTypes.SecurityHotspot, f.SubCategory));
        Assert.Equal(Severity.High, mapped[0].Severity);
        Assert.Equal(Severity.Low, mapped[1].Severity);
        Assert.Contains("cors", mapped[0].Description);
    }

    [Theory]
    [InlineData("OK", "pass")]
    [InlineData("ERROR", "fail")]
    [InlineData("WARN", "warn")]
    [InlineData("NONE", "warn")]
    public void The_quality_gate_status_maps_and_an_unrecognised_one_is_never_a_pass(string sonar, string expected)
    {
        var (status, _) = SonarCloudIngestMapper.MapQualityGate(Json($$"""{"status":"{{sonar}}","conditions":[]}"""));

        Assert.Equal(expected, status);
    }

    [Fact]
    public void Quality_gate_conditions_keep_the_metric_threshold_actual_and_their_own_status()
    {
        var (status, conditions) = SonarCloudIngestMapper.MapQualityGate(Json("""
            {"status":"ERROR","conditions":[
              {"status":"OK","metricKey":"new_reliability_rating","comparator":"GT","errorThreshold":"1","actualValue":"1"},
              {"status":"ERROR","metricKey":"new_coverage","comparator":"LT","errorThreshold":"80","actualValue":"42.5"}]}
            """));

        Assert.Equal("fail", status);
        Assert.Equal(2, conditions.Count);
        var failed = conditions.Single(c => c.Status == "fail");
        Assert.Equal(("new_coverage", "LT", "80", "42.5"), (failed.Metric, failed.Op, failed.Threshold, failed.Actual));
        Assert.Equal("pass", conditions.Single(c => c.Metric == "new_reliability_rating").Status);
    }

    [Fact]
    public void Measures_become_a_flat_metric_to_value_map()
    {
        var m = SonarCloudIngestMapper.MapMeasures(Json("""
            {"component":{"measures":[{"metric":"coverage","value":"90.5"},{"metric":"bugs","value":"47"},{"metric":"no_value"}]}}
            """));

        Assert.Equal("90.5", m["coverage"]);
        Assert.Equal("47", m["bugs"]);
        Assert.False(m.ContainsKey("no_value"));
        Assert.Empty(SonarCloudIngestMapper.MapMeasures(Json("{}")));
    }

    [Fact]
    public void A_very_long_message_is_truncated_to_what_findings_stores()
    {
        var issue = Json($$"""{"rule":"r","severity":"MAJOR","type":"BUG","message":"{{new string('x', 900)}}","component":"{{Key}}:a.cs"}""");

        Assert.Equal(500, SonarCloudIngestMapper.MapIssues([issue], Key).Single().Title.Length);
    }
}
