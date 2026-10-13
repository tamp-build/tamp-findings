using Tamp.Findings.Domain.Risk;

namespace Tamp.Findings.Domain.Tests.Risk;

/// <summary>
/// Which layer's EXPLANATION survives when two layers assert the same disposition
/// (TFND-218, the tie-precedence question TFND-219's description raised).
///
/// <para>
/// This is a prerequisite for promoting a library-general default out of a project and
/// into the archetype. ADR 0015 §2 makes the justification carry the concrete code
/// reference that backs the call — "the disposition is not an opinion; it points at the
/// code". The merge used to keep the FIRST layer's text on a tie, so a generic archetype
/// default displaced a project's specific evidence, and promoting a default would have
/// destroyed that evidence on every project that had done the work. The probe for it
/// was written and verified failing before the fix.
/// </para>
/// <para>
/// Nothing here loosens anything: the KIND is identical in every case, and harden-only
/// is a rule about kinds. Only the prose that explains the kind moves.
/// </para>
/// </summary>
public class AssertionTiePrecedenceTests
{
    private static (PolicyLayer, string) Layer(string source, params ControlAssertion[] assertions)
    {
        var l = PolicyLayer.Empty();
        l.Assertions.AddRange(assertions);
        return (l, source);
    }

    private static ControlAssertion Inherited(string controlId, string? from, string? why) => new()
    {
        Kind = ControlDispositionKind.Inherited,
        ControlIds = [controlId],
        InheritedFrom = from,
        Justification = why,
    };

    [Fact]
    public void A_projects_code_reference_beats_a_generic_archetype_justification()
    {
        var merged = PolicyLayerMerge.Resolve([
            Layer("archetype: library", Inherited("SC-13",
                "the deploying system",
                "A code library implements no cryptography of its own.")),
            Layer("this project", Inherited("SC-13",
                "the deploying/hosting system (validated platform crypto module, under its ATO)",
                "Its only System.Security.Cryptography use is SHA-256 content hashing for build determinism — src/Tamp.Core/AbsolutePath.cs:294.")),
        ]);

        var a = merged.Assertions["SC-13"];
        Assert.Equal(ControlDispositionKind.Inherited, a.Kind);
        Assert.Contains("AbsolutePath.cs:294", a.Justification!, StringComparison.Ordinal);
        Assert.Contains("ATO", a.InheritedFrom!, StringComparison.Ordinal);

        // And the winning layer is named as the project, so a reader can tell where the
        // explanation came from.
        Assert.Equal("this project", a.Source);
    }

    [Fact]
    public void A_bare_tie_does_not_blank_out_a_real_explanation()
    {
        // The template's gate mappings carry gates and no prose at all. If a bare
        // assertion took precedence just by being nearer, promoting a control into
        // StarterGatedMap would erase the justification a project had written for it —
        // which is the opposite of what promoting a default is for.
        var merged = PolicyLayerMerge.Resolve([
            Layer("this project", new ControlAssertion
            {
                Kind = ControlDispositionKind.Gated,
                ControlIds = ["CA-5"],
                Gates = ["poamPastDue"],
                Justification = "findings maintains the POA&M board and ENFORCES it via poamPastDue.",
            }),
            Layer("FedRAMP High", new ControlAssertion
            {
                Kind = ControlDispositionKind.Gated,
                ControlIds = ["CA-5"],
                Gates = ["poamPastDue"],
            }),
        ]);

        Assert.Contains("ENFORCES it", merged.Assertions["CA-5"].Justification!, StringComparison.Ordinal);
    }

    [Fact]
    public void A_tie_still_unions_the_gate_lists()
    {
        var merged = PolicyLayerMerge.Resolve([
            Layer("FedRAMP High", new ControlAssertion
            {
                Kind = ControlDispositionKind.Gated, ControlIds = ["RA-3(1)"], Gates = ["criticalCves"],
            }),
            Layer("this project", new ControlAssertion
            {
                Kind = ControlDispositionKind.Gated, ControlIds = ["RA-3(1)"], Gates = ["kevExposure"],
                Justification = "assessed continuously from the SBOM",
            }),
        ]);

        Assert.Equal(["criticalCves", "kevExposure"], merged.Assertions["RA-3(1)"].Gates);
        Assert.Equal("assessed continuously from the SBOM", merged.Assertions["RA-3(1)"].Justification);
    }

    [Fact]
    public void A_tie_cannot_change_the_disposition()
    {
        // The guardrail. Precedence on a tie is about prose only — a weaker kind from a
        // nearer layer still loses, which is the whole harden-only guarantee and is what
        // the review-gated override exists to bypass deliberately.
        var merged = PolicyLayerMerge.Resolve([
            Layer("FedRAMP High", new ControlAssertion
            {
                Kind = ControlDispositionKind.Gated, ControlIds = ["SC-13"], Gates = ["secrets"],
            }),
            Layer("this project", Inherited("SC-13", "the platform", "we do not implement it")),
        ]);

        var a = merged.Assertions["SC-13"];
        Assert.Equal(ControlDispositionKind.Gated, a.Kind);
        Assert.Equal("FedRAMP High", a.Source);
        Assert.Null(a.Justification);
    }

    [Fact]
    public void A_tie_does_not_replace_a_reviewed_overrides_explanation()
    {
        // An override's justification is the text a reviewer actually approved. A
        // generic default arriving later must not rewrite it, or the audit trail would
        // describe a decision nobody made.
        var merged = PolicyLayerMerge.Resolve([
            Layer("this project", new ControlAssertion
            {
                Kind = ControlDispositionKind.NotApplicable,
                ControlIds = ["AC-2"],
                Justification = "Approved: this library holds no accounts.",
                Overrides = true,
            }),
            Layer("archetype: library", new ControlAssertion
            {
                Kind = ControlDispositionKind.NotApplicable,
                ControlIds = ["AC-2"],
                Justification = "generic archetype default",
            }),
        ]);

        var a = merged.Assertions["AC-2"];
        Assert.Contains("Approved:", a.Justification!, StringComparison.Ordinal);
        Assert.True(a.Overridden);
    }
}
