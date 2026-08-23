using System.Globalization;
using System.Text;

namespace Tamp.Findings.Application.Attestation;

/// <summary>
/// The generated PDF (TFND-102).
///
/// Written by hand against the PDF 1.4 spec rather than pulling in a rendering
/// library. Two reasons, and the second is the real one:
///
///  1. The document is a form — headings, wrapped paragraphs, a table of
///     practices, and three signature rules. That is well inside what the base
///     fourteen fonts and a content stream can do.
///  2. This file is a deliverable someone signs and attaches to a federal
///     contract package. Every glyph in it should be traceable to something in
///     this repository, not to a transitive dependency's layout engine.
///
/// Encoding is WinAnsi, which is what the base-14 fonts carry. Characters
/// outside it are transliterated deliberately — the status glyphs become
/// bracketed words, which reads BETTER on paper than a run of geometric shapes
/// nobody's printer renders identically.
/// </summary>
internal static class PdfWriter
{
    // US Letter at 72dpi. Letter rather than A4 because the consumer is a US
    // federal contract package.
    private const double PageWidth = 612;
    private const double PageHeight = 792;
    private const double Margin = 54;
    private const double Leading = 13;

    private const double BodySize = 9.5;
    private const double SmallSize = 8;

    public static byte[] Render(SsdfAttestationDoc doc)
    {
        var pages = Layout(doc);
        return Assemble(pages);
    }

    // ---- Layout -----------------------------------------------------------

    private static List<string> Layout(SsdfAttestationDoc doc)
    {
        var pages = new List<string>();
        var page = new StringBuilder();
        var y = PageHeight - Margin;

        void Break()
        {
            pages.Add(page.ToString());
            page.Clear();
            y = PageHeight - Margin;
        }

        void Space(double amount)
        {
            y -= amount;
            if (y < Margin) Break();
        }

        void Line(string text, double size, bool bold = false, double indent = 0)
        {
            // A line that would fall below the bottom margin starts a new page
            // instead. Silently overprinting the signature block is exactly the
            // kind of defect nobody notices until the signed copy comes back.
            if (y - size < Margin) Break();

            page.Append("BT /")
                .Append(bold ? "F2" : "F1")
                .Append(' ').Append(Num(size)).Append(" Tf ")
                .Append(Num(Margin + indent)).Append(' ').Append(Num(y)).Append(" Td (")
                .Append(Escape(text))
                .Append(") Tj ET\n");
            y -= size + 3.5;
        }

        void Paragraph(string text, double size, double indent = 0, bool bold = false)
        {
            foreach (var line in Wrap(text, size, PageWidth - 2 * Margin - indent))
                Line(line, size, bold, indent);
        }

        void Rule(double width)
        {
            if (y < Margin + 10) Break();
            page.Append("0.6 w ")
                .Append(Num(Margin)).Append(' ').Append(Num(y)).Append(" m ")
                .Append(Num(Margin + width)).Append(' ').Append(Num(y)).Append(" l S\n");
            y -= 6;
        }

        // ---- Header ----
        Line("CISA SECURE SOFTWARE DEVELOPMENT ATTESTATION - NIST SP 800-218", SmallSize);
        Space(2);
        Line(doc.Project.Name, 19, bold: true);
        Line(doc.Project.ClientName, BodySize);

        var stamp = new StringBuilder("Generated ")
            .Append(doc.Generated.ToString("yyyy-MM-dd HH:mm 'UTC'", CultureInfo.InvariantCulture));
        if (doc.Build is { } b)
        {
            stamp.Append("  |  Build ").Append(b.CommitSha ?? b.VersionString)
                 .Append("  |  Version ").Append(b.VersionString);
        }
        // The policy that produced the score travels WITH the score, on paper
        // as on screen. A number without its policy is not evidence.
        if (doc.Risk is { } r)
        {
            stamp.Append("  |  Risk ").Append(r.Score.ToString("0.0", CultureInfo.InvariantCulture))
                 .Append(" (").Append(r.Band).Append(") under policy ").Append(r.PolicyName);
        }
        Paragraph(stamp.ToString(), SmallSize);
        Space(4);
        Rule(PageWidth - 2 * Margin);
        Space(6);

        // ---- Summary ----
        Paragraph(doc.Summary.Headline, 12, bold: true);
        Space(2);
        Line($"Yes {doc.Summary.Yes}    Partial {doc.Summary.Partial}    "
           + $"No {doc.Summary.No}    Manual {doc.Summary.Manual}", BodySize);
        Paragraph(
            "Manual practices are not failures. They require the signatory's own attestation "
          + "from artefacts held outside this tool.", SmallSize);
        Space(6);

        if (doc.Gates is { } gates)
        {
            var unknown = gates.Unknown > 0 ? $", {gates.Unknown} unknown" : "";
            var failing = gates.Failed > 0 ? $", {gates.Failed} failing" : "";
            // An Unknown gate is stated as Unknown. Folding it into either
            // column is how the evidence becomes false.
            Line($"Acceptance gates: {gates.Passed} of {gates.Enabled} enabled pass{unknown}{failing}.",
                 BodySize);
            Space(4);
        }

        // ---- Practices ----
        foreach (var family in new[]
        {
            ("PO", "Prepare the organization"),
            ("PS", "Protect the software"),
            ("PW", "Produce well-secured software"),
            ("RV", "Respond to vulnerabilities"),
        })
        {
            var practices = doc.Practices.Where(p => p.Family == family.Item1).ToArray();
            if (practices.Length == 0) continue;

            Space(6);
            Line($"{family.Item1} - {family.Item2}", 12, bold: true);
            Space(2);

            foreach (var practice in practices)
            {
                Line($"{practice.Id}  [{Status(practice.Status)}]  {practice.Label}", BodySize, bold: true);
                Paragraph(practice.Intent, SmallSize, indent: 14);
                Paragraph(practice.Evidence, SmallSize, indent: 14);
                Space(3);
            }
        }

        // ---- Signature ----
        Space(10);
        Rule(PageWidth - 2 * Margin);
        Space(4);
        Line("SIGNATORY ATTESTATION", SmallSize, bold: true);
        Space(2);
        Paragraph(
            "By signing below, I attest that the software identified above is developed in "
          + "conformity with the secure software development practices set out in NIST SP 800-218, "
          + "to the extent recorded in this document. Practices marked Manual are attested on the "
          + "basis of artefacts held outside this tool. I understand that knowingly providing false "
          + "information is subject to penalty under 18 U.S.C. 1001.", BodySize);
        Space(18);

        foreach (var label in new[] { "Name and title", "Signature", "Date" })
        {
            Rule(300);
            Line(label, SmallSize);
            Space(14);
        }

        pages.Add(page.ToString());
        return pages;
    }

    // Glyphs outside WinAnsi become words. On paper this reads better than a
    // geometric shape anyway — nobody has to be told what "PARTIAL" means.
    private static string Status(string status) => status switch
    {
        "Yes" => "YES",
        "Partial" => "PARTIAL",
        "No" => "NO",
        _ => "MANUAL",
    };

    /// <summary>
    /// Greedy wrap against Helvetica's real advance widths.
    ///
    /// Approximating with a fixed character count would either waste a third of
    /// the line or overrun the margin, and an evidence string that runs off the
    /// page is evidence the reader does not have.
    /// </summary>
    private static IEnumerable<string> Wrap(string text, double size, double width)
    {
        var words = text.Split(' ', StringSplitOptions.RemoveEmptyEntries);
        if (words.Length == 0) yield break;

        var line = new StringBuilder();
        foreach (var word in words)
        {
            var candidate = line.Length == 0 ? word : line + " " + word;
            if (Width(candidate, size) > width && line.Length > 0)
            {
                yield return line.ToString();
                line.Clear().Append(word);
            }
            else
            {
                line.Clear().Append(candidate);
            }
        }

        if (line.Length > 0) yield return line.ToString();
    }

    // Helvetica advance widths, in 1/1000 em. Only the ranges that actually
    // occur matter; anything else falls back to the average, which is close
    // enough to keep text inside the margin.
    private static double Width(string text, double size)
    {
        double total = 0;
        foreach (var c in text)
        {
            total += c switch
            {
                ' ' => 278,
                'i' or 'j' or 'l' or '.' or ',' or ':' or ';' or '\'' or '|' => 240,
                'f' or 't' or 'r' or '(' or ')' or '[' or ']' or '/' or '-' => 320,
                'm' or 'M' or 'W' or 'w' => 830,
                >= 'A' and <= 'Z' => 690,
                >= '0' and <= '9' => 556,
                _ => 545,
            };
        }
        return total * size / 1000.0;
    }

    // ---- File assembly ----------------------------------------------------

    private static byte[] Assemble(List<string> pages)
    {
        // Object numbering: 1 catalog, 2 pages, 3 F1, 4 F2, then a page object
        // and a content stream per page.
        var objects = new List<byte[]>();
        var pageIds = new List<int>();
        var firstPageId = 5;

        for (var i = 0; i < pages.Count; i++) pageIds.Add(firstPageId + i * 2);

        objects.Add(Utf8($"<< /Type /Catalog /Pages 2 0 R >>"));
        objects.Add(Utf8(
            $"<< /Type /Pages /Count {pages.Count} /Kids [{string.Join(' ', pageIds.Select(id => $"{id} 0 R"))}] >>"));
        objects.Add(Utf8("<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica /Encoding /WinAnsiEncoding >>"));
        objects.Add(Utf8("<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica-Bold /Encoding /WinAnsiEncoding >>"));

        for (var i = 0; i < pages.Count; i++)
        {
            var contentId = pageIds[i] + 1;
            objects.Add(Utf8(
                $"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 {Num(PageWidth)} {Num(PageHeight)}] "
              + $"/Resources << /Font << /F1 3 0 R /F2 4 0 R >> >> /Contents {contentId} 0 R >>"));

            var body = Latin1(pages[i]);
            var stream = new List<byte>();
            stream.AddRange(Utf8($"<< /Length {body.Length} >>\nstream\n"));
            stream.AddRange(body);
            stream.AddRange(Utf8("\nendstream"));
            objects.Add(stream.ToArray());
        }

        var output = new List<byte>();
        output.AddRange(Utf8("%PDF-1.4\n"));
        // A binary comment marks the file as binary for anything that would
        // otherwise mangle it in a text-mode transfer.
        output.AddRange(new byte[] { 0x25, 0xE2, 0xE3, 0xCF, 0xD3, 0x0A });

        var offsets = new List<int>();
        for (var i = 0; i < objects.Count; i++)
        {
            offsets.Add(output.Count);
            output.AddRange(Utf8($"{i + 1} 0 obj\n"));
            output.AddRange(objects[i]);
            output.AddRange(Utf8("\nendobj\n"));
        }

        var xref = output.Count;
        output.AddRange(Utf8($"xref\n0 {objects.Count + 1}\n"));
        output.AddRange(Utf8("0000000000 65535 f \n"));
        foreach (var offset in offsets)
            output.AddRange(Utf8($"{offset:D10} 00000 n \n"));

        output.AddRange(Utf8(
            $"trailer\n<< /Size {objects.Count + 1} /Root 1 0 R >>\nstartxref\n{xref}\n%%EOF\n"));

        return output.ToArray();
    }

    private static byte[] Utf8(string s) => Encoding.ASCII.GetBytes(s);

    // WinAnsi differs from Latin-1 only in 0x80–0x9F, and Escape has already
    // transliterated every character that would land there. So Latin-1 — which
    // ships in the base library, unlike codepage 1252 — produces bytes that are
    // correct under /WinAnsiEncoding for everything this writer emits.
    private static byte[] Latin1(string s) => Encoding.Latin1.GetBytes(s);

    private static string Escape(string text)
    {
        var sb = new StringBuilder(text.Length + 8);
        foreach (var c in text)
        {
            // Backslash, and both parens, terminate a PDF string literal.
            if (c is '\\' or '(' or ')') sb.Append('\\');
            sb.Append(c switch
            {
                '—' or '–' => '-',   // em/en dash
                '‘' or '’' => '\'',
                '“' or '”' => '"',
                ' ' => ' ',
                _ => c,
            });
        }
        return sb.ToString();
    }

    private static string Num(double value) =>
        Math.Round(value, 2).ToString("0.##", CultureInfo.InvariantCulture);
}
