using System.Text.Json;
using Tamp.Findings.Application.Attestation;

namespace Tamp.Findings.Application.Tests;

// The OSCAL package shape (TFND-39).
//
// FedRAMP RFC-0024 requires machine-readable authorization packages from
// 30 September 2026, and a machine-readable package gets a 30-day target review
// against a 90-day queue for everything else. So these assertions are about
// whether the package RESOLVES — a document whose own cross-references dangle
// reads as valid right up until an assessor's tooling follows one.
//
// NOT a substitute for oscal-cli. A passing test is not a passing validator,
// and FedRAMP's own constraint packages impose more than the base metaschema.
public class OscalPackageTests
{
    private static SsdfAttestationDoc Doc(params (string Id, string Family, string Status)[] practices)
    {
        var doc = new SsdfAttestationDoc
        {
            Generated = new DateTimeOffset(2026, 9, 1, 12, 0, 0, TimeSpan.Zero),
            Project = new(Guid.Parse("22222222-2222-2222-2222-222222222222"), "tamp.findings", "BrewingCoder"),
            Build = new("179fe8bdeadbeef", "1.2.3", new DateTimeOffset(2026, 8, 30, 0, 0, 0, TimeSpan.Zero)),
            Risk = new(41.5, "Yellow", "Federal baseline"),
            Gates = new(10, 7, 1, 2, []),
            Practices = practices
                .Select(p => new SsdfPractice(p.Id, p.Family, $"{p.Id} label", $"{p.Id} intent",
                                              p.Status, $"{p.Id} evidence"))
                .ToList(),
        };

        doc.Summary = new(
            practices.Count(p => p.Status == "Yes"),
            practices.Count(p => p.Status == "Partial"),
            practices.Count(p => p.Status == "No"),
            practices.Count(p => p.Status == "Manual"),
            "headline");

        return doc;
    }

    private static JsonElement Package(SsdfAttestationDoc doc, OscalModel model = OscalModel.Bundle) =>
        JsonDocument.Parse(AttestationExporter.OscalJson(doc, model)).RootElement;

    // ---- The bundle --------------------------------------------------------

    [Fact]
    public void A_bundle_carries_all_three_models()
    {
        var root = Package(Doc(("PW.7.1", "PW", "No")));

        Assert.True(root.TryGetProperty("assessment-results", out _));
        Assert.True(root.TryGetProperty("plan-of-action-and-milestones", out _));
        Assert.True(root.TryGetProperty("component-definition", out _));
    }

    [Fact]
    public void Every_reference_in_the_bundle_resolves()
    {
        // The assertion the whole design turns on. A package whose own
        // cross-references dangle reads as valid until something follows one.
        var root = Package(Doc(
            ("PO.1.1", "PO", "Manual"),
            ("PW.5.1", "PW", "Partial"),
            ("PW.7.1", "PW", "No"),
            ("PO.3.1", "PO", "Yes")));

        var declared = new HashSet<string>(StringComparer.Ordinal);
        var referenced = new List<(string Key, string Uuid)>();

        Collect(root, declared, referenced);

        var dangling = referenced.Where(r => !declared.Contains(r.Uuid)).ToArray();

        Assert.True(
            dangling.Length == 0,
            "dangling: " + string.Join(", ", dangling.Select(d => $"{d.Key}={d.Uuid}")));
    }

    /// <summary>
    /// Walks the document collecting every declared <c>uuid</c> and every
    /// <c>*-uuid</c> reference, so the two sets can be compared.
    /// </summary>
    private static void Collect(
        JsonElement element, HashSet<string> declared, List<(string, string)> referenced)
    {
        switch (element.ValueKind)
        {
            case JsonValueKind.Object:
                foreach (var property in element.EnumerateObject())
                {
                    if (property.Value.ValueKind == JsonValueKind.String)
                    {
                        if (property.Name == "uuid") declared.Add(property.Value.GetString()!);
                        else if (property.Name.EndsWith("-uuid", StringComparison.Ordinal))
                            referenced.Add((property.Name, property.Value.GetString()!));
                    }
                    else if (property.Name == "party-uuids")
                    {
                        foreach (var item in property.Value.EnumerateArray())
                            referenced.Add(("party-uuids", item.GetString()!));
                    }
                    else
                    {
                        Collect(property.Value, declared, referenced);
                    }
                }
                break;

            case JsonValueKind.Array:
                foreach (var item in element.EnumerateArray()) Collect(item, declared, referenced);
                break;
        }
    }

    // ---- Risks and findings ------------------------------------------------

    [Fact]
    public void A_contradicted_practice_produces_a_finding_and_a_risk()
    {
        // OSCAL models the FINDING as "this objective is not satisfied" and the
        // RISK as what that exposes. A POA&M item resolves against the risk, so
        // emitting one without the other leaves the package's own references
        // dangling.
        var results = Package(Doc(("PW.7.1", "PW", "No")))
            .GetProperty("assessment-results").GetProperty("results")[0];

        Assert.Equal(1, results.GetProperty("findings").GetArrayLength());
        Assert.Equal(1, results.GetProperty("risks").GetArrayLength());
    }

    [Fact]
    public void A_partial_produces_neither_a_finding_nor_a_risk()
    {
        // Nothing contradicted it — the measurement was incomplete. Emitting a
        // finding would assert something the evidence does not say.
        var results = Package(Doc(("PW.5.1", "PW", "Partial")))
            .GetProperty("assessment-results").GetProperty("results")[0];

        Assert.Equal(0, results.GetProperty("findings").GetArrayLength());
        Assert.Equal(0, results.GetProperty("risks").GetArrayLength());
    }

    [Fact]
    public void A_partial_still_becomes_a_poam_item_with_no_dangling_pointers()
    {
        // A Partial is not a finding but it IS outstanding work. Its related
        // arrays must be EMPTY rather than pointing at a risk that does not
        // exist — a dangling pointer validates and then fails to resolve.
        var item = Package(Doc(("PW.5.1", "PW", "Partial")))
            .GetProperty("plan-of-action-and-milestones")
            .GetProperty("poam-items")[0];

        Assert.Equal(0, item.GetProperty("related-findings").GetArrayLength());
        Assert.Equal(0, item.GetProperty("related-risks").GetArrayLength());
        Assert.Equal(1, item.GetProperty("related-observations").GetArrayLength());
    }

    // ---- Controls ----------------------------------------------------------

    [Fact]
    public void Control_ids_are_lowercase_so_they_join_against_the_nist_catalog()
    {
        // OSCAL control ids are lowercase across NIST's own catalogs. "PW.8.1"
        // would silently fail to join.
        var selection = Package(Doc(("PW.8.1", "PW", "No")))
            .GetProperty("assessment-results").GetProperty("results")[0]
            .GetProperty("reviewed-controls").GetProperty("control-selections")[0];

        Assert.Equal("pw.8.1",
            selection.GetProperty("include-controls")[0].GetProperty("control-id").GetString());
    }

    [Fact]
    public void Reviewed_controls_name_what_was_assessed_rather_than_claiming_everything()
    {
        // include-all would claim a scope of 22 practices covers every control
        // in the catalog.
        var selection = Package(Doc(("PO.1.1", "PO", "Manual"), ("PW.7.1", "PW", "No")))
            .GetProperty("assessment-results").GetProperty("results")[0]
            .GetProperty("reviewed-controls").GetProperty("control-selections")[0];

        Assert.False(selection.TryGetProperty("include-all", out _));
        Assert.Equal(2, selection.GetProperty("include-controls").GetArrayLength());
    }

    // ---- Component definition ----------------------------------------------

    [Fact]
    public void Only_satisfied_practices_are_claimed_as_implemented()
    {
        // A component definition claiming a control the assessment in the same
        // bundle contradicts would make the package disagree with itself.
        var implemented = Package(Doc(
                ("PO.3.1", "PO", "Yes"),
                ("PW.5.1", "PW", "Partial"),
                ("PW.7.1", "PW", "No"),
                ("PO.1.1", "PO", "Manual")))
            .GetProperty("component-definition")
            .GetProperty("components")[0]
            .GetProperty("control-implementations")[0]
            .GetProperty("implemented-requirements");

        Assert.Equal(1, implemented.GetArrayLength());
        Assert.Equal("po.3.1", implemented[0].GetProperty("control-id").GetString());
    }

    [Fact]
    public void A_project_with_nothing_satisfied_claims_no_implementations()
    {
        // An empty control-implementations array rather than one asserting
        // nothing: "we implement no controls" is a true statement, and a
        // fabricated implementation is not.
        var component = Package(Doc(("PW.7.1", "PW", "No")))
            .GetProperty("component-definition")
            .GetProperty("components")[0];

        Assert.Equal(0, component.GetProperty("control-implementations").GetArrayLength());
    }

    // ---- Metadata ----------------------------------------------------------

    [Fact]
    public void Every_model_names_a_responsible_party()
    {
        // The base schema permits a package with no named responsible party;
        // no reviewer accepts one, because there is nobody to route a question
        // about it to.
        var root = Package(Doc(("PO.3.1", "PO", "Yes")));

        foreach (var model in new[]
                 { "assessment-results", "plan-of-action-and-milestones", "component-definition" })
        {
            var metadata = root.GetProperty(model).GetProperty("metadata");

            Assert.True(metadata.GetProperty("parties").GetArrayLength() >= 2);
            Assert.True(metadata.GetProperty("responsible-parties").GetArrayLength() >= 2);
            Assert.Equal("1.1.2", metadata.GetProperty("oscal-version").GetString());
        }
    }

    [Fact]
    public void The_policy_that_produced_the_score_travels_with_it()
    {
        // A number without its policy is not evidence — the same rule the
        // screen and the PDF follow.
        var props = Package(Doc(("PO.3.1", "PO", "Yes")))
            .GetProperty("assessment-results").GetProperty("metadata").GetProperty("props");

        Assert.Contains(props.EnumerateArray(),
            p => p.GetProperty("name").GetString() == "risk-policy"
              && p.GetProperty("value").GetString() == "Federal baseline");
    }

    [Fact]
    public void The_poam_carries_a_system_id_so_it_can_stand_alone()
    {
        var poam = Package(Doc(("PW.7.1", "PW", "No"), ("PW.5.1", "PW", "Partial")), OscalModel.Poam)
            .GetProperty("plan-of-action-and-milestones");

        Assert.Equal("22222222-2222-2222-2222-222222222222",
            poam.GetProperty("system-id").GetProperty("id").GetString());
    }

    [Fact]
    public void A_standalone_poam_carries_its_own_observations()
    {
        // An item whose observation lives only in a document the reader does
        // not have is an item they cannot assess.
        var poam = Package(Doc(("PW.7.1", "PW", "No")), OscalModel.Poam)
            .GetProperty("plan-of-action-and-milestones");

        Assert.Equal(1, poam.GetProperty("observations").GetArrayLength());
        Assert.Equal(1, poam.GetProperty("risks").GetArrayLength());
    }

    // ---- Observations ------------------------------------------------------

    [Fact]
    public void A_manual_practice_is_an_interview_against_a_party()
    {
        // The single most useful thing an assessor learns from this package is
        // how much of it rests on the signatory rather than on measurement.
        var observation = Package(Doc(("PO.1.1", "PO", "Manual")), OscalModel.AssessmentResults)
            .GetProperty("assessment-results").GetProperty("results")[0]
            .GetProperty("observations")[0];

        Assert.Equal("INTERVIEW", observation.GetProperty("methods")[0].GetString());
        Assert.Equal("party", observation.GetProperty("subjects")[0].GetProperty("type").GetString());
    }

    [Fact]
    public void A_measured_practice_is_a_test_against_the_component()
    {
        var observation = Package(Doc(("PW.7.1", "PW", "Yes")), OscalModel.AssessmentResults)
            .GetProperty("assessment-results").GetProperty("results")[0]
            .GetProperty("observations")[0];

        Assert.Equal("TEST", observation.GetProperty("methods")[0].GetString());
        Assert.Equal("component", observation.GetProperty("subjects")[0].GetProperty("type").GetString());
    }

    [Fact]
    public void The_evidence_string_survives_into_the_machine_readable_package()
    {
        // Dropping it would make the signed copy and the OSCAL package disagree
        // about what was found.
        var observation = Package(Doc(("PW.8.1", "PW", "Partial")), OscalModel.AssessmentResults)
            .GetProperty("assessment-results").GetProperty("results")[0]
            .GetProperty("observations")[0];

        Assert.Equal("PW.8.1 evidence", observation.GetProperty("remarks").GetString());
    }

    // ---- Determinism -------------------------------------------------------

    [Fact]
    public void The_same_build_exports_byte_identical_packages()
    {
        // A POA&M submitted in March has to resolve against the assessment
        // resubmitted in September.
        var doc = Doc(("PW.7.1", "PW", "No"), ("PO.3.1", "PO", "Yes"));

        Assert.Equal(
            AttestationExporter.OscalJson(doc, OscalModel.Bundle),
            AttestationExporter.OscalJson(doc, OscalModel.Bundle));
    }

    [Fact]
    public void The_poam_in_a_bundle_and_alone_use_the_same_identifiers()
    {
        // Otherwise submitting the bundle and then a POA&M update would look
        // like two unrelated plans for the same system.
        var doc = Doc(("PW.7.1", "PW", "No"));

        var bundled = Package(doc).GetProperty("plan-of-action-and-milestones")
            .GetProperty("poam-items")[0].GetProperty("uuid").GetString();
        var alone = Package(doc, OscalModel.Poam).GetProperty("plan-of-action-and-milestones")
            .GetProperty("poam-items")[0].GetProperty("uuid").GetString();

        Assert.Equal(bundled, alone);
    }

    [Fact]
    public void A_different_build_of_the_same_project_gets_different_identifiers()
    {
        // Two assessments of two commits are two assessments. Sharing ids would
        // let the second silently overwrite the first in a consumer's store.
        var first = Doc(("PW.7.1", "PW", "No"));
        var second = Doc(("PW.7.1", "PW", "No"));
        second.Build = new("cafebabecafebabe", "1.2.4", second.Build!.LatestCreatedAt);

        Assert.NotEqual(
            Package(first).GetProperty("assessment-results").GetProperty("uuid").GetString(),
            Package(second).GetProperty("assessment-results").GetProperty("uuid").GetString());
    }
}
