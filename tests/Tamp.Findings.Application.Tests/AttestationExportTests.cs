using System.Text;
using System.Text.Json;
using Tamp.Findings.Application.Attestation;

namespace Tamp.Findings.Application.Tests;

// The attestation export (TFND-101 / TFND-102).
//
// The OSCAL and PDF writers are pure functions over a built document, so they
// can be tested without a database — which is the right place for them, because
// what matters here is the SHAPE of the output an assessor's tooling consumes.
public class AttestationExportTests
{
    private static SsdfAttestationDoc Doc(params (string Id, string Family, string Status)[] practices)
    {
        var doc = new SsdfAttestationDoc
        {
            Generated = new DateTimeOffset(2026, 6, 1, 12, 0, 0, TimeSpan.Zero),
            Project = new(Guid.Parse("11111111-1111-1111-1111-111111111111"), "tamp.findings", "BrewingCoder"),
            Build = new("179fe8bdeadbeef", "1.2.3", new DateTimeOffset(2026, 5, 30, 0, 0, 0, TimeSpan.Zero)),
            Risk = new(41.5, "Yellow", "Federal baseline"),
            Gates = new(10, 7, 1, 2,
            [
                new("kevExposure", "Pass", false, "0 KEV-listed CVEs"),
                new("criticalSast", "Unknown", true, "no SAST scan on this build"),
            ]),
            Practices = practices
                .Select(p => new SsdfPractice(p.Id, p.Family, $"{p.Id} label", $"{p.Id} intent",
                                              p.Status, $"{p.Id} evidence"))
                .ToList(),
        };

        int yes = practices.Count(p => p.Status == "Yes");
        int partial = practices.Count(p => p.Status == "Partial");
        int no = practices.Count(p => p.Status == "No");
        int manual = practices.Count(p => p.Status == "Manual");
        doc.Summary = new(yes, partial, no, manual, "headline");
        return doc;
    }

    private static JsonElement Oscal(SsdfAttestationDoc doc, OscalModel model) =>
        JsonDocument.Parse(AttestationExporter.OscalJson(doc, model)).RootElement;

    // ---- OSCAL ------------------------------------------------------------

    [Fact]
    public void A_bundle_emits_both_models()
    {
        var root = Oscal(Doc(("PO.3.1", "PO", "Yes")), OscalModel.Bundle);

        Assert.True(root.TryGetProperty("assessment-results", out _));
        Assert.True(root.TryGetProperty("plan-of-action-and-milestones", out _));
    }

    [Fact]
    public void A_single_model_export_emits_only_that_model()
    {
        var root = Oscal(Doc(("PO.3.1", "PO", "Yes")), OscalModel.AssessmentResults);

        Assert.True(root.TryGetProperty("assessment-results", out _));
        Assert.False(root.TryGetProperty("plan-of-action-and-milestones", out _));
    }

    [Fact]
    public void A_bundle_shares_uuids_so_poam_items_resolve_against_the_findings()
    {
        // The whole reason the bundle exists. Emitting the two models
        // separately produces a package whose cross-references do not resolve —
        // which reads as valid right up until an assessor's tooling follows one.
        var root = Oscal(Doc(("PW.7.1", "PW", "No")), OscalModel.Bundle);

        var findingUuid = root
            .GetProperty("assessment-results").GetProperty("results")[0]
            .GetProperty("findings")[0].GetProperty("uuid").GetString();

        var referenced = root
            .GetProperty("plan-of-action-and-milestones").GetProperty("poam-items")[0]
            .GetProperty("related-findings")[0].GetProperty("finding-uuid").GetString();

        Assert.Equal(findingUuid, referenced);
    }

    [Fact]
    public void Only_contradicted_practices_become_findings()
    {
        // A Partial is an incomplete measurement, not a defect; a Manual is the
        // signatory's to answer. Neither is a finding.
        var root = Oscal(
            Doc(("PO.1.1", "PO", "Manual"), ("PW.5.1", "PW", "Partial"), ("PW.7.1", "PW", "No")),
            OscalModel.AssessmentResults);

        var findings = root.GetProperty("assessment-results").GetProperty("results")[0]
            .GetProperty("findings");

        Assert.Equal(1, findings.GetArrayLength());
        Assert.Contains("PW.7.1", findings[0].GetProperty("title").GetString()!);
    }

    [Fact]
    public void Manual_practices_still_appear_as_observations()
    {
        // Omitting them would understate how much of the attestation rests on
        // the signatory rather than on measurement.
        var root = Oscal(Doc(("PO.1.1", "PO", "Manual")), OscalModel.AssessmentResults);

        var observation = root.GetProperty("assessment-results").GetProperty("results")[0]
            .GetProperty("observations")[0];

        Assert.Equal("INTERVIEW", observation.GetProperty("methods")[0].GetString());
    }

    [Fact]
    public void Poam_items_cover_both_no_and_partial()
    {
        // A Partial is not a finding but it IS outstanding work, which is
        // exactly what a POA&M records.
        var root = Oscal(
            Doc(("PW.5.1", "PW", "Partial"), ("PW.7.1", "PW", "No"), ("PO.1.1", "PO", "Manual")),
            OscalModel.Poam);

        Assert.Equal(2, root.GetProperty("plan-of-action-and-milestones")
            .GetProperty("poam-items").GetArrayLength());
    }

    [Fact]
    public void The_same_build_exports_the_same_uuids_twice()
    {
        // Random UUIDs would make every re-export look to a downstream tool
        // like a brand new assessment of the same software.
        var doc = Doc(("PW.7.1", "PW", "No"));

        var first = AttestationExporter.OscalJson(doc, OscalModel.Bundle);
        var second = AttestationExporter.OscalJson(doc, OscalModel.Bundle);

        Assert.Equal(first, second);
    }

    [Fact]
    public void A_deterministic_uuid_is_a_well_formed_uuid()
    {
        var value = AttestationExporter.DeterministicUuid("seed");

        Assert.True(Guid.TryParse(value, out var parsed));
        // Version and variant bits actually stamped, not 16 bytes wearing a
        // UUID's shape.
        Assert.Equal('8', value[14]);
        Assert.Contains(value[19], "89ab");
        Assert.NotEqual(Guid.Empty, parsed);
    }

    [Fact]
    public void The_policy_that_produced_the_score_travels_with_it()
    {
        // A number without its policy is not evidence.
        var root = Oscal(Doc(("PO.3.1", "PO", "Yes")), OscalModel.AssessmentResults);

        var props = root.GetProperty("assessment-results").GetProperty("metadata").GetProperty("props");
        var policy = props.EnumerateArray().Single(p => p.GetProperty("name").GetString() == "risk-policy");

        Assert.Equal("Federal baseline", policy.GetProperty("value").GetString());
    }

    // ---- PDF --------------------------------------------------------------

    [Fact]
    public void The_pdf_is_a_well_formed_pdf_file()
    {
        var bytes = RenderPdf(Doc(("PO.3.1", "PO", "Yes")));
        var text = Encoding.Latin1.GetString(bytes);

        Assert.StartsWith("%PDF-1.4", text, StringComparison.Ordinal);
        Assert.EndsWith("%%EOF\n", text, StringComparison.Ordinal);
        Assert.Contains("/Type /Catalog", text, StringComparison.Ordinal);
        Assert.Contains("trailer", text, StringComparison.Ordinal);
    }

    [Fact]
    public void The_xref_offsets_point_at_their_objects()
    {
        // A PDF with a wrong xref table opens in some readers and not others,
        // which is the worst possible failure for a document someone has to
        // attach to a contract package.
        var bytes = RenderPdf(Doc(("PO.3.1", "PO", "Yes")));
        var text = Encoding.Latin1.GetString(bytes);

        // "startxref" also ends in "xref", so anchor on the table's own line
        // start rather than on the bare substring.
        var xrefStart = text.LastIndexOf("\nxref\n", StringComparison.Ordinal) + 1;
        var lines = text[xrefStart..].Split('\n');

        // lines[0] "xref", lines[1] "0 N", lines[2] the free entry, then one
        // ten-digit offset per object.
        var count = int.Parse(lines[1].Split(' ')[1]);
        for (var i = 1; i < count; i++)
        {
            var offset = int.Parse(lines[2 + i][..10]);
            Assert.Equal($"{i} 0 obj", text.Substring(offset, $"{i} 0 obj".Length));
        }
    }

    [Fact]
    public void The_signatory_block_is_on_the_document()
    {
        var text = Encoding.Latin1.GetString(RenderPdf(Doc(("PO.3.1", "PO", "Yes"))));

        Assert.Contains("SIGNATORY ATTESTATION", text, StringComparison.Ordinal);
        Assert.Contains("Signature", text, StringComparison.Ordinal);
    }

    [Fact]
    public void Status_glyphs_become_words_rather_than_replacement_characters()
    {
        // WinAnsi has no ✓ or ◐. Emitting them anyway would print as '?' or as
        // whatever glyph the reader's font maps to that byte.
        var text = Encoding.Latin1.GetString(
            RenderPdf(Doc(("PO.1.1", "PO", "Manual"), ("PW.7.1", "PW", "No"))));

        Assert.Contains("[MANUAL]", text, StringComparison.Ordinal);
        Assert.Contains("[NO]", text, StringComparison.Ordinal);
        Assert.DoesNotContain("?]", text, StringComparison.Ordinal);
    }

    [Fact]
    public void An_unknown_gate_is_stated_as_unknown_on_the_printed_copy()
    {
        // Folding it into passed or failed is how the evidence becomes false.
        var text = Encoding.Latin1.GetString(RenderPdf(Doc(("PO.3.1", "PO", "Yes"))));

        Assert.Contains("2 unknown", text, StringComparison.Ordinal);
    }

    [Fact]
    public void A_long_document_spills_onto_more_than_one_page()
    {
        // Every practice on one page would mean the later ones are simply not
        // in the file. Twenty-two practices do not fit on a Letter sheet.
        var many = Enumerable.Range(1, 30)
            .Select(i => ($"PW.{i}.1", "PW", "Yes"))
            .ToArray();

        var text = Encoding.Latin1.GetString(RenderPdf(Doc(many)));

        var count = int.Parse(text.Split("/Count ")[1].Split(' ')[0]);
        Assert.True(count >= 2, $"expected more than one page, got {count}");
    }

    [Fact]
    public void Parentheses_in_evidence_do_not_break_the_content_stream()
    {
        // An unescaped ')' terminates a PDF string literal early and corrupts
        // everything after it in the stream.
        var doc = Doc(("PW.7.1", "PW", "Yes"));
        doc.Practices[0] = doc.Practices[0] with { Evidence = "coverage (78.2%) on 3 modules" };

        var text = Encoding.Latin1.GetString(RenderPdf(doc));

        Assert.Contains(@"\(78.2%\)", text, StringComparison.Ordinal);
    }

    private static byte[] RenderPdf(SsdfAttestationDoc doc) => PdfWriter.Render(doc);

    // ---- Filenames --------------------------------------------------------

    [Fact]
    public void The_filename_carries_the_build()
    {
        // Two exports of the same project on different commits must not collide
        // in someone's downloads folder.
        var exporter = new AttestationExporter(null!, null!, null!);

        var name = exporter.FileName(AttestationFormat.Pdf, OscalModel.Bundle, "tamp.findings", "179fe8bdeadbeef");

        Assert.Equal("tamp-findings-179fe8bdeadb-ssdf-attestation.pdf", name);
    }

    [Fact]
    public void An_unbuilt_project_still_produces_a_legible_filename()
    {
        var exporter = new AttestationExporter(null!, null!, null!);

        var name = exporter.FileName(AttestationFormat.Json, OscalModel.Bundle, "tamp.findings", null);

        Assert.Equal("tamp-findings-no-build-attestation.json", name);
    }
}
