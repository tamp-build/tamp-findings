using Tamp.Findings.Domain.Compliance;
using Tamp.Findings.Domain.Risk;
using Tamp.Findings.Domain.Values;

namespace Tamp.Findings.Domain.Tests.Risk;

/// <summary>
/// The dispositions promoted out of one project's prod DB into shared code (TFND-218).
///
/// <para>
/// During the ADR 0015 walk, tamp-core's 229 unmapped controls were worked down to 11 by
/// authoring dispositions through the endpoint — which writes to the PROJECT layer, and
/// therefore to one database. Several of those claims are true of any code library, or of
/// any project at all, so every other repo had to repeat the work and none of it was in
/// git where it could be reviewed in a PR.
/// </para>
/// <para>
/// These tests are about the thing promotion is for: a project that has authored NOTHING
/// now inherits the general claims. They assert on the shipped content rather than on a
/// hand-built layer, so deleting a promoted assertion fails here.
/// </para>
/// </summary>
public class PromotedDispositionTests
{
    /// <summary>The stack a Library project with no dispositions of its own resolves to.</summary>
    private static EffectivePolicyLayer PlainLibrary() => PolicyLayerMerge.Resolve([
        (PolicyTemplateDefaults.BuildFedRampHigh(), "FedRAMP High"),
        (ArchetypeLayers.For(ProjectArchetype.Library), ArchetypeLayers.Label(ProjectArchetype.Library)),
    ]);

    [Theory]
    // The crypto cluster. A library implements no confidentiality cryptography of its
    // own; hashing for build determinism is not confidentiality crypto.
    [InlineData("SC-8")]
    [InlineData("SC-8(1)")]
    [InlineData("SC-12")]
    [InlineData("SC-12(1)")]
    [InlineData("SC-13")]
    [InlineData("SC-17")]
    [InlineData("SC-28")]
    [InlineData("SC-28(1)")]
    [InlineData("IA-7")]
    [InlineData("CM-8(4)")]
    public void A_library_inherits_the_promoted_claims_without_authoring_anything(string controlId)
    {
        var a = PlainLibrary().Assertions[controlId];

        Assert.Equal(ControlDispositionKind.Inherited, a.Kind);
        Assert.Equal(ArchetypeLayers.Label(ProjectArchetype.Library), a.Source);

        // Inherited without naming who provides it is the shape ADR 0009 refuses to
        // count, so the promotion has to carry both halves.
        Assert.False(string.IsNullOrWhiteSpace(a.InheritedFrom));
        Assert.False(string.IsNullOrWhiteSpace(a.Justification));
    }

    [Fact]
    public void A_library_is_not_mobile_code()
    {
        var a = PlainLibrary().Assertions["SC-18"];
        Assert.Equal(ControlDispositionKind.NotApplicable, a.Kind);
        Assert.False(string.IsNullOrWhiteSpace(a.Justification));
    }

    [Theory]
    // The gate mappings. Archetype-independent: the product gates these the same way
    // for a library and a service, which is why they sit on the template.
    [InlineData("CA-5")]
    [InlineData("CA-7")]
    [InlineData("CA-7(4)")]
    [InlineData("SI-2(2)")]
    [InlineData("CM-8(1)")]
    [InlineData("CM-8(2)")]
    [InlineData("RA-3(1)")]
    [InlineData("RA-5(2)")]
    public void A_federal_baseline_now_gates_the_promoted_controls(string controlId)
    {
        var a = PlainLibrary().Assertions[controlId];

        Assert.Equal(ControlDispositionKind.Gated, a.Kind);

        // Gated with no gate is the claim ADR 0009 exists to prevent — "we prove this"
        // with nothing producing the proof.
        Assert.NotEmpty(a.Gates);
    }

    [Theory]
    [InlineData("RA-5(5)")]
    [InlineData("RA-5(11)")]
    [InlineData("SA-10")]
    [InlineData("SA-15(3)")]
    [InlineData("PL-10")]
    [InlineData("PL-11")]
    public void The_org_program_claims_are_inherited_on_every_baseline(string controlId)
    {
        var a = PlainLibrary().Assertions[controlId];
        Assert.Equal(ControlDispositionKind.Inherited, a.Kind);
        Assert.Equal("FedRAMP High", a.Source);
    }

    [Fact]
    public void A_service_does_not_get_the_library_claims()
    {
        // The promotion must not excuse a service from cryptography it may well own.
        // Unclassified fails upward to Service, so this is also the default case.
        var service = PolicyLayerMerge.Resolve([
            (PolicyTemplateDefaults.BuildFedRampHigh(), "FedRAMP High"),
            (ArchetypeLayers.For(ProjectArchetype.ServiceApp), ArchetypeLayers.Label(ProjectArchetype.ServiceApp)),
        ]);

        Assert.False(service.Assertions.ContainsKey("SC-13"));
        Assert.False(service.Assertions.ContainsKey("IA-7"));
        Assert.False(service.Assertions.ContainsKey("SC-18"));

        // But the archetype-independent template claims DO apply to it, which is the
        // distinction that decided where each one went.
        Assert.Equal(ControlDispositionKind.Gated, service.Assertions["CA-5"].Kind);
        Assert.Equal(ControlDispositionKind.Inherited, service.Assertions["PL-10"].Kind);
    }

    [Fact]
    public void A_projects_own_evidence_still_wins_over_the_promoted_default()
    {
        // The reason the tie fix had to land in the same change. tamp-core's authored
        // SC-13 cites the exact call site; the archetype default is deliberately generic.
        // If the generic text won, promoting the default would have destroyed the
        // evidence ADR 0015 §2 says the disposition exists to point at.
        var withProject = PolicyLayerMerge.Resolve([
            (PolicyTemplateDefaults.BuildFedRampHigh(), "FedRAMP High"),
            (ArchetypeLayers.For(ProjectArchetype.Library), ArchetypeLayers.Label(ProjectArchetype.Library)),
            (Project(), "this project"),
        ]);

        Assert.Contains("AbsolutePath.cs:294",
            withProject.Assertions["SC-13"].Justification!, StringComparison.Ordinal);
        Assert.Equal("this project", withProject.Assertions["SC-13"].Source);

        static PolicyLayer Project()
        {
            var l = PolicyLayer.Empty();
            l.Assertions.Add(new ControlAssertion
            {
                Kind = ControlDispositionKind.Inherited,
                ControlIds = ["SC-13"],
                InheritedFrom = "the deploying/hosting system (validated platform crypto module, under its ATO)",
                Justification = "Its only System.Security.Cryptography use is SHA-256 content hashing — src/Tamp.Core/AbsolutePath.cs:294.",
            });
            return l;
        }
    }

    [Fact]
    public void Promotion_moved_nobody_to_Gated_without_a_gate_to_prove_it()
    {
        // The honesty property of the whole mapping (ADR 0009 §4): WithCoverageMapping
        // only emits an assertion for gates the template actually ENABLES, so a baseline
        // cannot claim coverage it has no producer for. Worth asserting across every
        // shipped baseline rather than trusting the mechanism, since this change added
        // eight entries to the map.
        foreach (var (name, layer) in new (string, PolicyLayer)[]
        {
            ("FedRAMP Low", PolicyTemplateDefaults.BuildFedRampLow()),
            ("FedRAMP Moderate", PolicyTemplateDefaults.BuildFedRampModerate()),
            ("FedRAMP High", PolicyTemplateDefaults.BuildFedRampHigh()),
            ("GovRAMP Core", PolicyTemplateDefaults.BuildGovRampCore()),
        })
        {
            var enabled = layer.Gates.Where(g => g.Value.Enabled).Select(g => g.Key).ToHashSet(StringComparer.Ordinal);
            foreach (var a in layer.Assertions.Where(a => a.Kind == ControlDispositionKind.Gated))
            {
                Assert.NotEmpty(a.Gates);
                Assert.All(a.Gates, g => Assert.Contains(g, enabled));
            }
        }
    }
}
