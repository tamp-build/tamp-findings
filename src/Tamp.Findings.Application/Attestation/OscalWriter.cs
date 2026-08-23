using System.Text;
using System.Text.Json;

namespace Tamp.Findings.Application.Attestation;

/// <summary>
/// OSCAL 1.1.2 emission (TFND-39).
///
/// FedRAMP RFC-0024 requires machine-readable authorization packages from
/// 30 September 2026, and names OSCAL as the standard. A machine-readable
/// package gets a 30-day target review; everything else drops to a 90-day
/// queue. So this is not a nice-to-have export format — it is the difference
/// between "we generate an attestation", which stops being a differentiator the
/// moment agencies require OSCAL, and "we emit OSCAL", which is one.
///
/// Three models, and a bundle of all three:
///
///   assessment-results               what was measured, and what it found
///   plan-of-action-and-milestones    what is outstanding and when it closes
///   component-definition             what the software is made of
///
/// THE BUNDLE SHARES UUIDs ACROSS ALL THREE. OSCAL POA&amp;M items reference the
/// findings, risks and observations an assessment cites; emitting the models
/// separately produces documents whose cross-references do not resolve, which
/// reads as a valid package right up until an assessor's tooling tries to follow
/// one.
///
/// NOT YET VALIDATED against <c>oscal-cli</c> or compliance-trestle. The shapes
/// here follow the 1.1.2 metaschema and are asserted by tests, but a passing
/// test is not the same as a passing validator, and FedRAMP's own constraint
/// packages impose more than the base schema does. Stated rather than implied,
/// because "emits OSCAL" and "emits OSCAL that FedRAMP accepts" are different
/// claims and only the first is currently earned.
/// </summary>
internal static class OscalWriter
{
    private const string OscalVersion = "1.1.2";

    /// <summary>
    /// The SSDF practice taxonomy, as an OSCAL control catalog reference.
    ///
    /// Practices are CONTROLS in OSCAL's model, not free text, which is the
    /// substantive difference between this and the prose export: an assessor's
    /// tooling can ask "what is the state of PW.8.1" and get an answer without
    /// parsing a sentence.
    /// </summary>
    private const string SsdfCatalog = "https://csrc.nist.gov/pubs/sp/800/218/final";

    internal static string Write(SsdfAttestationDoc doc, OscalModel model)
    {
        var root = Uuid($"{doc.Project.Id}:{doc.Build?.CommitSha}");

        object payload = model switch
        {
            OscalModel.AssessmentResults => new Dictionary<string, object?>
            {
                ["assessment-results"] = AssessmentResults(doc, root),
            },
            OscalModel.Poam => new Dictionary<string, object?>
            {
                ["plan-of-action-and-milestones"] = Poam(doc, root),
            },
            _ => new Dictionary<string, object?>
            {
                ["assessment-results"] = AssessmentResults(doc, root),
                ["plan-of-action-and-milestones"] = Poam(doc, root),
                ["component-definition"] = ComponentDefinition(doc, root),
            },
        };

        return JsonSerializer.Serialize(payload, Options);
    }

    // ---- Metadata ---------------------------------------------------------

    /// <summary>
    /// The metadata block every OSCAL model requires.
    ///
    /// Carries roles and parties as well as the title: a package with no named
    /// responsible party is one an assessor cannot route a question about, and
    /// the base schema permits it but no reviewer accepts it.
    /// </summary>
    private static Dictionary<string, object?> Metadata(SsdfAttestationDoc doc, string root, string title)
    {
        var orgUuid = Uuid($"{root}:party:{doc.Project.ClientName}");
        var toolUuid = Uuid($"{root}:party:tamp.findings");

        return new Dictionary<string, object?>
        {
            ["title"] = title,
            ["last-modified"] = doc.Generated,
            ["version"] = doc.Build?.VersionString ?? "0",
            ["oscal-version"] = OscalVersion,

            ["roles"] = new object[]
            {
                Role("provider", "Software provider",
                     "The organisation that develops the software this package describes."),
                Role("assessor", "Assessment tool",
                     "The tool that produced the evidence. Named as a party because an assessor is "
                     + "entitled to know what measured this, and to distrust it."),
            },

            ["parties"] = new object[]
            {
                new Dictionary<string, object?>
                {
                    ["uuid"] = orgUuid,
                    ["type"] = "organization",
                    ["name"] = doc.Project.ClientName,
                },
                new Dictionary<string, object?>
                {
                    ["uuid"] = toolUuid,
                    ["type"] = "organization",
                    ["name"] = "tamp.findings",
                    ["remarks"] = "Evidence generated from ingested scanner output. Practices marked "
                                + "Manual are NOT measured by this tool and rest on the signatory.",
                },
            },

            ["responsible-parties"] = new object[]
            {
                new Dictionary<string, object?>
                {
                    ["role-id"] = "provider",
                    ["party-uuids"] = new[] { orgUuid },
                },
                new Dictionary<string, object?>
                {
                    ["role-id"] = "assessor",
                    ["party-uuids"] = new[] { toolUuid },
                },
            },

            ["props"] = Props(
                ("commit", doc.Build?.CommitSha ?? ""),
                ("risk-score", doc.Risk?.Score.ToString("0.0") ?? ""),
                ("risk-band", doc.Risk?.Band ?? ""),
                // The policy that produced the score travels with the score
                // everywhere else in this product; a machine-readable package
                // is no exception. A number without its policy is not evidence.
                ("risk-policy", doc.Risk?.PolicyName ?? "")),
        };
    }

    private static Dictionary<string, object?> Role(string id, string title, string description) => new()
    {
        ["id"] = id,
        ["title"] = title,
        ["description"] = description,
    };

    // ---- assessment-results -----------------------------------------------

    private static Dictionary<string, object?> AssessmentResults(SsdfAttestationDoc doc, string root) => new()
    {
        ["uuid"] = root,
        ["metadata"] = Metadata(doc, root, $"SSDF assessment — {doc.Project.Name}"),
        ["import-ap"] = new Dictionary<string, object?> { ["href"] = SsdfCatalog },

        ["results"] = new object[]
        {
            new Dictionary<string, object?>
            {
                ["uuid"] = Uuid($"{root}:result"),
                ["title"] = "Automated evidence",
                ["description"] = doc.Summary.Headline,
                ["start"] = doc.Generated,

                // The subject of the assessment: one specific build. An
                // assessment that did not say WHICH build could be replayed
                // against any of them.
                ["local-definitions"] = new Dictionary<string, object?>
                {
                    ["components"] = new object[] { SoftwareComponent(doc, root) },
                },

                // Named controls, not include-all. An assessment claiming to
                // have reviewed everything when it measured 22 practices is
                // overstating its own scope.
                ["reviewed-controls"] = new Dictionary<string, object?>
                {
                    ["control-selections"] = new object[]
                    {
                        new Dictionary<string, object?>
                        {
                            ["description"] = "NIST SP 800-218 practices covered by this assessment.",
                            ["include-controls"] = doc.Practices
                                .Select(p => new Dictionary<string, object?> { ["control-id"] = ControlId(p.Id) })
                                .ToArray(),
                        },
                    },
                },

                ["observations"] = doc.Practices.Select(p => Observation(doc, root, p)).ToArray(),
                ["risks"] = doc.Practices.Where(p => p.Status == "No")
                    .Select(p => Risk(doc, root, p)).ToArray(),
                ["findings"] = doc.Practices.Where(p => p.Status == "No")
                    .Select(p => Finding(root, p)).ToArray(),
            },
        },
    };

    /// <summary>
    /// One observation per practice — Manual ones included, marked INTERVIEW.
    ///
    /// Omitting them would understate how much of the attestation rests on the
    /// signatory rather than on measurement, which is the single most useful
    /// thing an assessor can learn from this package.
    /// </summary>
    private static Dictionary<string, object?> Observation(
        SsdfAttestationDoc doc, string root, SsdfPractice practice) => new()
    {
        ["uuid"] = Uuid($"{root}:obs:{practice.Id}"),
        ["title"] = $"{practice.Id} — {practice.Label}",
        ["description"] = practice.Intent,
        ["methods"] = new[] { practice.Status == "Manual" ? "INTERVIEW" : "TEST" },
        ["types"] = new[] { practice.Status == "Manual" ? "control-objective" : "finding" },
        ["collected"] = doc.Generated,

        // What was observed. Named so a reader can tell a practice measured
        // against this build from one asserted about the organisation.
        ["subjects"] = new object[]
        {
            new Dictionary<string, object?>
            {
                ["subject-uuid"] = Uuid($"{root}:component"),
                ["type"] = practice.Status == "Manual" ? "party" : "component",
            },
        },

        ["props"] = Props(
            ("ssdf-practice", practice.Id),
            ("attestation-status", practice.Status)),

        // The evidence string, verbatim. It is prose because it was written for
        // a human to read on the signed copy, and dropping it from the
        // machine-readable package would make the two documents disagree about
        // what was found.
        ["remarks"] = practice.Evidence,
    };

    /// <summary>
    /// A risk for each contradicted practice.
    ///
    /// Distinct from the finding: OSCAL models the FINDING as "this objective
    /// is not satisfied" and the RISK as "here is what that exposes and what is
    /// being done". A POA&amp;M item resolves against the risk, which is why
    /// emitting one without the other leaves the package's own references
    /// dangling.
    /// </summary>
    private static Dictionary<string, object?> Risk(
        SsdfAttestationDoc doc, string root, SsdfPractice practice) => new()
    {
        ["uuid"] = Uuid($"{root}:risk:{practice.Id}"),
        ["title"] = $"{practice.Id} is not satisfied",
        ["description"] = practice.Evidence,
        // OSCAL wants the consequence, not a restatement. The practice intent
        // IS the consequence of not meeting it.
        ["statement"] = practice.Intent,
        ["status"] = "open",
        ["related-observations"] = new object[]
        {
            new Dictionary<string, object?>
            {
                ["observation-uuid"] = Uuid($"{root}:obs:{practice.Id}"),
            },
        },
    };

    private static Dictionary<string, object?> Finding(string root, SsdfPractice practice) => new()
    {
        ["uuid"] = Uuid($"{root}:finding:{practice.Id}"),
        ["title"] = $"{practice.Id} not satisfied",
        ["description"] = practice.Evidence,
        ["target"] = new Dictionary<string, object?>
        {
            ["type"] = "objective-id",
            ["target-id"] = ControlId(practice.Id),
            ["status"] = new Dictionary<string, object?> { ["state"] = "not-satisfied" },
        },
        ["related-observations"] = new object[]
        {
            new Dictionary<string, object?> { ["observation-uuid"] = Uuid($"{root}:obs:{practice.Id}") },
        },
        ["associated-risks"] = new object[]
        {
            new Dictionary<string, object?> { ["risk-uuid"] = Uuid($"{root}:risk:{practice.Id}") },
        },
    };

    // ---- plan-of-action-and-milestones ------------------------------------

    private static Dictionary<string, object?> Poam(SsdfAttestationDoc doc, string root) => new()
    {
        ["uuid"] = Uuid($"{root}:poam"),
        ["metadata"] = Metadata(doc, root, $"Plan of action and milestones — {doc.Project.Name}"),

        // Points at the assessment. In a bundle this resolves; in a standalone
        // POA&M export the consumer supplies the counterpart.
        ["import-ssp"] = new Dictionary<string, object?> { ["href"] = $"#{root}" },

        ["system-id"] = new Dictionary<string, object?>
        {
            ["identifier-type"] = "https://tamp.build/ns/oscal/project-id",
            ["id"] = doc.Project.Id.ToString(),
        },

        ["local-definitions"] = new Dictionary<string, object?>
        {
            ["components"] = new object[] { SoftwareComponent(doc, root) },
        },

        // Repeated here rather than referenced across documents: a standalone
        // POA&M has to stand alone, and an item whose observation lives only in
        // a document the reader does not have is an item they cannot assess.
        ["observations"] = doc.Practices
            .Where(p => p.Status is "No" or "Partial")
            .Select(p => Observation(doc, root, p))
            .ToArray(),

        ["risks"] = doc.Practices.Where(p => p.Status == "No")
            .Select(p => Risk(doc, root, p)).ToArray(),

        // Both No AND Partial. A Partial is not a finding — it is an incomplete
        // measurement — but it IS outstanding work, which is exactly what a
        // POA&M records.
        ["poam-items"] = doc.Practices
            .Where(p => p.Status is "No" or "Partial")
            .Select(p => PoamItem(root, p))
            .ToArray(),
    };

    private static Dictionary<string, object?> PoamItem(string root, SsdfPractice practice) => new()
    {
        ["uuid"] = Uuid($"{root}:poam-item:{practice.Id}"),
        ["title"] = $"{practice.Id} — {practice.Label}",
        ["description"] = practice.Evidence,

        ["props"] = Props(
            ("ssdf-practice", practice.Id),
            ("attestation-status", practice.Status)),

        ["related-observations"] = new object[]
        {
            new Dictionary<string, object?> { ["observation-uuid"] = Uuid($"{root}:obs:{practice.Id}") },
        },

        // A Partial has no finding or risk to point at — nothing contradicted
        // it, the measurement was just incomplete. Emitting an empty array is
        // correct; emitting a reference to a risk that does not exist would be
        // a dangling pointer that validates and then fails to resolve.
        ["related-findings"] = practice.Status == "No"
            ? new object[]
            {
                new Dictionary<string, object?> { ["finding-uuid"] = Uuid($"{root}:finding:{practice.Id}") },
            }
            : Array.Empty<object>(),

        ["related-risks"] = practice.Status == "No"
            ? new object[]
            {
                new Dictionary<string, object?> { ["risk-uuid"] = Uuid($"{root}:risk:{practice.Id}") },
            }
            : Array.Empty<object>(),
    };

    // ---- component-definition ---------------------------------------------

    /// <summary>
    /// What the software is, and which SSDF practices it implements.
    ///
    /// The control-implementation is the part with content: for every practice
    /// automated evidence SATISFIES, this states the implementation and cites
    /// the evidence. Practices that are Manual, Partial or No are deliberately
    /// absent — a component definition claiming to implement a control the
    /// evidence contradicts would be the package asserting something the
    /// assessment in the same bundle denies.
    /// </summary>
    private static Dictionary<string, object?> ComponentDefinition(SsdfAttestationDoc doc, string root)
    {
        var componentUuid = Uuid($"{root}:component");

        var implemented = doc.Practices.Where(p => p.Status == "Yes").ToArray();

        return new Dictionary<string, object?>
        {
            ["uuid"] = Uuid($"{root}:component-definition"),
            ["metadata"] = Metadata(doc, root, $"Component definition — {doc.Project.Name}"),

            ["components"] = new object[]
            {
                new Dictionary<string, object?>
                {
                    ["uuid"] = componentUuid,
                    ["type"] = "software",
                    ["title"] = doc.Project.Name,
                    ["description"] = $"{doc.Project.Name}, built by {doc.Project.ClientName}.",
                    ["props"] = Props(
                        ("commit", doc.Build?.CommitSha ?? ""),
                        ("version", doc.Build?.VersionString ?? "")),

                    ["control-implementations"] = implemented.Length == 0
                        ? Array.Empty<object>()
                        : new object[]
                        {
                            new Dictionary<string, object?>
                            {
                                ["uuid"] = Uuid($"{root}:control-impl"),
                                ["source"] = SsdfCatalog,
                                ["description"] =
                                    "SSDF practices for which automated evidence supports the "
                                    + "attestation. Practices that are Manual, Partial or not "
                                    + "satisfied are absent by design — claiming one here that the "
                                    + "assessment in this bundle contradicts would make the package "
                                    + "disagree with itself.",
                                ["implemented-requirements"] = implemented
                                    .Select(p => new Dictionary<string, object?>
                                    {
                                        ["uuid"] = Uuid($"{root}:impl:{p.Id}"),
                                        ["control-id"] = ControlId(p.Id),
                                        ["description"] = p.Evidence,
                                    })
                                    .ToArray(),
                            },
                        },
                },
            },
        };
    }

    private static Dictionary<string, object?> SoftwareComponent(SsdfAttestationDoc doc, string root) => new()
    {
        ["uuid"] = Uuid($"{root}:component"),
        ["type"] = "software",
        ["title"] = doc.Project.Name,
        ["description"] = $"Build {doc.Build?.CommitSha ?? "(none)"} of {doc.Project.Name}.",
        ["status"] = new Dictionary<string, object?> { ["state"] = "operational" },
    };

    // ---- Shared ------------------------------------------------------------

    /// <summary>
    /// An SSDF practice id as an OSCAL control id.
    ///
    /// OSCAL control ids are lowercase by convention across NIST's own catalogs,
    /// and a consumer joining this package against the SP 800-218 catalog will
    /// be matching against those. "PW.8.1" would silently fail to join.
    /// </summary>
    internal static string ControlId(string practiceId) => practiceId.ToLowerInvariant();

    private static object[] Props(params (string Name, string Value)[] props) =>
        props.Where(p => !string.IsNullOrEmpty(p.Value))
             .Select(p => (object)new Dictionary<string, object?>
             {
                 ["name"] = p.Name,
                 ["value"] = p.Value,
             })
             .ToArray();

    /// <summary>
    /// A UUID derived from the seed rather than drawn at random.
    ///
    /// Re-exporting the same build must produce the same identifiers, or every
    /// export looks to a downstream tool like a brand new assessment of the
    /// same software — and a POA&amp;M submitted in March would not resolve
    /// against the assessment resubmitted in September.
    /// </summary>
    internal static string Uuid(string seed)
    {
        var hash = System.Security.Cryptography.SHA256.HashData(Encoding.UTF8.GetBytes(seed));
        var bytes = hash.AsSpan(0, 16).ToArray();

        // Version 8 (RFC 9562, custom) and the RFC 4122 variant, so the value
        // is a well-formed UUID rather than 16 bytes wearing a UUID's shape.
        bytes[6] = (byte)((bytes[6] & 0x0F) | 0x80);
        bytes[8] = (byte)((bytes[8] & 0x3F) | 0x80);

        // Formatted from the bytes in RFC order rather than through
        // new Guid(byte[]), which reads the first three fields as little-endian
        // and would move the version nibble somewhere a reader does not look.
        var hex = Convert.ToHexStringLower(bytes);
        return $"{hex[..8]}-{hex[8..12]}-{hex[12..16]}-{hex[16..20]}-{hex[20..]}";
    }

    private static readonly JsonSerializerOptions Options = new()
    {
        WriteIndented = true,
        // The wire shape is a contract with FedRAMP tooling; a UTF-8 em dash in
        // an evidence string must survive rather than becoming an escape.
        Encoder = System.Text.Encodings.Web.JavaScriptEncoder.UnsafeRelaxedJsonEscaping,
    };
}
