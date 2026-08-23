using Tamp.Findings.Application.Explorer;

namespace Tamp.Findings.Application.Tests;

// The source viewer's tokenizer (TFND-89).
//
// Deliberately a lexer, not a parser: this is display, and a wrong colour on an
// unusual construct costs nothing while a parser that throws on a syntax it
// does not know costs the reader their file. These tests are written to that
// standard — they check it never loses text and never throws, before they check
// any colour.
public class SourceTokenizerTests
{
    private static string Rebuild(IEnumerable<SourceLine> lines) =>
        string.Join("\n", lines.Select(l => string.Concat(l.Spans.Select(s => s.Text))));

    [Theory]
    [InlineData("Program.cs")]
    [InlineData("app.ts")]
    [InlineData("schema.sql")]
    [InlineData("compose.yaml")]
    [InlineData("package.json")]
    [InlineData("Dockerfile")]
    [InlineData("mystery.qqq")]
    [InlineData(null)]
    public void Tokenizing_never_loses_a_character(string? path)
    {
        // The property that matters most. A viewer that silently drops text is
        // worse than one with no colour at all — the reader is looking at code
        // to decide whether a finding is real.
        const string source = "var x = \"a string\"; // trailing\nif (x != null) { return 42; }\n";

        var lines = SourceTokenizer.Tokenize(source, path);

        Assert.Equal(source.TrimEnd('\n'), Rebuild(lines).TrimEnd('\n'));
    }

    [Fact]
    public void Every_line_is_returned_including_empty_ones()
    {
        // Empty lines have to survive: the gutter numbers them, and dropping
        // one shifts every line number below it — which would point a finding
        // at the wrong code.
        var lines = SourceTokenizer.Tokenize("one\n\nthree\n", "x.cs");

        Assert.Equal(4, lines.Count);
        Assert.Equal(2, lines[1].Number);
        Assert.Empty(lines[1].Spans);
    }

    [Fact]
    public void Line_numbers_start_at_one_and_are_contiguous()
    {
        var lines = SourceTokenizer.Tokenize("a\nb\nc", "x.cs");

        Assert.Equal([1, 2, 3], lines.Select(l => l.Number));
    }

    [Fact]
    public void Csharp_keywords_are_recognised()
    {
        var lines = SourceTokenizer.Tokenize("public static void Main()", "Program.cs");

        var kinds = lines[0].Spans.Where(s => s.Text.Trim().Length > 0)
            .ToDictionary(s => s.Text, s => s.Kind);

        Assert.Equal(TokenKind.Keyword, kinds["public"]);
        Assert.Equal(TokenKind.Keyword, kinds["static"]);
        Assert.Equal(TokenKind.Keyword, kinds["void"]);
    }

    [Fact]
    public void A_yaml_hash_is_a_comment_and_a_csharp_hash_is_not_a_keyword()
    {
        // The whole reason for a per-language comment marker: '#' opens a
        // comment in YAML and does not in C#.
        var yaml = SourceTokenizer.Tokenize("key: value # note", "compose.yaml");
        Assert.Contains(yaml[0].Spans, s => s.Kind == TokenKind.Comment && s.Text.Contains("note"));

        var csharp = SourceTokenizer.Tokenize("var a = 1; // note", "x.cs");
        Assert.Contains(csharp[0].Spans, s => s.Kind == TokenKind.Comment && s.Text.Contains("note"));
    }

    [Fact]
    public void A_block_comment_spans_lines()
    {
        // The one piece of state the lexer carries across lines. Getting it
        // wrong colours half a file as code or half as comment.
        var lines = SourceTokenizer.Tokenize("/* start\nstill comment\nend */ var x = 1;", "x.cs");

        Assert.All(lines[1].Spans, s => Assert.Equal(TokenKind.Comment, s.Kind));
        Assert.Contains(lines[2].Spans, s => s.Kind == TokenKind.Keyword && s.Text == "var");
    }

    [Fact]
    public void An_unterminated_string_does_not_run_away()
    {
        // Real files contain broken code — that is often exactly why a scanner
        // flagged them. The lexer has to end the line rather than consuming
        // the rest of the file.
        var lines = SourceTokenizer.Tokenize("var s = \"never closed\nvar t = 2;", "x.cs");

        Assert.Equal(2, lines.Count);
        Assert.Contains(lines[1].Spans, s => s.Kind == TokenKind.Keyword && s.Text == "var");
    }

    [Fact]
    public void An_unknown_extension_still_produces_readable_output()
    {
        // Plain text is a legitimate answer. What is not legitimate is
        // throwing, or returning nothing.
        var lines = SourceTokenizer.Tokenize("some ?? weird >>> content 42", "thing.unknown");

        Assert.Single(lines);
        Assert.NotEmpty(lines[0].Spans);
        Assert.Contains(lines[0].Spans, s => s.Kind == TokenKind.Number && s.Text == "42");
    }

    [Fact]
    public void Empty_input_yields_one_empty_line_rather_than_throwing()
    {
        var lines = SourceTokenizer.Tokenize("", "x.cs");

        Assert.Single(lines);
        Assert.Empty(lines[0].Spans);
    }

    [Fact]
    public void Windows_line_endings_do_not_leave_stray_characters()
    {
        var lines = SourceTokenizer.Tokenize("a = 1;\r\nb = 2;", "x.cs");

        Assert.Equal(2, lines.Count);
        Assert.DoesNotContain(lines[0].Spans, s => s.Text.Contains('\r'));
    }
}
