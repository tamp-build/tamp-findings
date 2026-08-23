namespace Tamp.Findings.Application.Explorer;

/// <summary>
/// Server-side syntax tokenizing for the source viewer.
///
/// <para>
/// The hand-off proposes Roslyn, on the grounds that it "is already a
/// dependency". That is true at COMPILE time — the analyzers — but it is not
/// referenced at runtime, and more importantly Roslyn tokenizes C# and nothing
/// else. The explorer shows findings in whatever a scanner reports:
/// TypeScript, YAML, Dockerfile, SQL, shell, JSON. Roslyn would give one of
/// those perfect highlighting and the rest none.
/// </para>
///
/// <para>
/// So: a small language-agnostic lexer instead (TFND-89). It handles the
/// shapes every C-family and scripting language shares — line comments, block
/// comments, strings, numbers — plus a per-language keyword set. It is
/// deliberately NOT a parser: this is display, and a wrong colour on an
/// unusual construct costs nothing, while a parser that throws on a syntax it
/// does not know costs the reader their file.
/// </para>
///
/// <para>
/// Returns spans rather than HTML so the caller decides the markup, and so
/// nothing here can emit unescaped user content.
/// </para>
/// </summary>
public static class SourceTokenizer
{
    /// <summary>
    /// Returns a concrete List because Blazor's Virtualize needs an ICollection
    /// to size without enumerating — and a file is tokenized once, so
    /// materialising here costs nothing per render.
    /// </summary>
    public static List<SourceLine> Tokenize(string text, string? filePath)
    {
        var language = LanguageFor(filePath);
        var lines = text.Replace("\r\n", "\n").Split('\n');
        var result = new List<SourceLine>(lines.Length);

        // Block comments span lines, so the lexer carries that one piece of
        // state across them. Everything else is decided within a line.
        var inBlockComment = false;

        for (var i = 0; i < lines.Length; i++)
        {
            var (spans, stillInBlock) = TokenizeLine(lines[i], language, inBlockComment);
            inBlockComment = stillInBlock;
            result.Add(new SourceLine(i + 1, spans));
        }

        return result;
    }

    private static (IReadOnlyList<SourceSpan> Spans, bool InBlock) TokenizeLine(
        string line, Language language, bool inBlockComment)
    {
        var spans = new List<SourceSpan>();
        var i = 0;

        while (i < line.Length)
        {
            if (inBlockComment)
            {
                var end = line.IndexOf("*/", i, StringComparison.Ordinal);
                if (end < 0)
                {
                    spans.Add(new SourceSpan(line[i..], TokenKind.Comment));
                    return (spans, true);
                }
                spans.Add(new SourceSpan(line[i..(end + 2)], TokenKind.Comment));
                i = end + 2;
                inBlockComment = false;
                continue;
            }

            var ch = line[i];

            // Line comment. YAML and shell use '#', the C family uses '//'.
            if (language.LineComment is { } marker && line.AsSpan(i).StartsWith(marker))
            {
                spans.Add(new SourceSpan(line[i..], TokenKind.Comment));
                break;
            }

            if (language.BlockComments && ch == '/' && i + 1 < line.Length && line[i + 1] == '*')
            {
                inBlockComment = true;
                continue;
            }

            if (ch is '"' or '\'' or '`')
            {
                var (span, next) = ReadString(line, i, ch);
                spans.Add(new SourceSpan(span, TokenKind.String));
                i = next;
                continue;
            }

            if (char.IsDigit(ch))
            {
                var start = i;
                while (i < line.Length && (char.IsLetterOrDigit(line[i]) || line[i] is '.' or '_')) i++;
                spans.Add(new SourceSpan(line[start..i], TokenKind.Number));
                continue;
            }

            if (char.IsLetter(ch) || ch == '_' || ch == '@')
            {
                var start = i;
                while (i < line.Length && (char.IsLetterOrDigit(line[i]) || line[i] is '_' or '@')) i++;
                var word = line[start..i];
                spans.Add(new SourceSpan(word, language.Keywords.Contains(word)
                    ? TokenKind.Keyword
                    // A capitalised identifier is a type often enough to be
                    // worth the colour, and wrong cheaply when it is not.
                    : char.IsUpper(word[0]) ? TokenKind.Type : TokenKind.Plain));
                continue;
            }

            if (char.IsWhiteSpace(ch))
            {
                var start = i;
                while (i < line.Length && char.IsWhiteSpace(line[i])) i++;
                spans.Add(new SourceSpan(line[start..i], TokenKind.Plain));
                continue;
            }

            spans.Add(new SourceSpan(ch.ToString(), TokenKind.Punctuation));
            i++;
        }

        return (spans, inBlockComment);
    }

    private static (string Text, int Next) ReadString(string line, int start, char quote)
    {
        var i = start + 1;
        while (i < line.Length)
        {
            if (line[i] == '\\') { i += 2; continue; }
            if (line[i] == quote) { i++; break; }
            i++;
        }
        return (line[start..Math.Min(i, line.Length)], Math.Min(i, line.Length));
    }

    private sealed record Language(string? LineComment, bool BlockComments, IReadOnlySet<string> Keywords);

    private static Language LanguageFor(string? path)
    {
        var extension = Path.GetExtension(path ?? "").ToLowerInvariant();

        return extension switch
        {
            ".cs" => new("//", true, CSharp),
            ".ts" or ".tsx" or ".js" or ".jsx" or ".mjs" => new("//", true, JavaScript),
            ".sql" => new("--", true, Sql),
            ".yml" or ".yaml" or ".toml" or ".ini" or ".sh" or ".bash" => new("#", false, Shell),
            ".json" => new(null, false, Json),
            // Unknown extensions still get strings, numbers and comments —
            // the shapes are near-universal — but no keyword set. Plain text
            // is a legitimate answer and better than a wrong one.
            _ => new("#", true, Empty),
        };
    }

    private static readonly IReadOnlySet<string> Empty = new HashSet<string>(StringComparer.Ordinal);

    private static readonly IReadOnlySet<string> CSharp = new HashSet<string>(StringComparer.Ordinal)
    {
        "abstract","as","async","await","base","bool","break","byte","case","catch","char","checked",
        "class","const","continue","decimal","default","delegate","do","double","else","enum","event",
        "explicit","extern","false","finally","fixed","float","for","foreach","get","goto","if",
        "implicit","in","int","interface","internal","is","lock","long","namespace","new","null",
        "object","operator","out","override","params","private","protected","public","readonly","record",
        "ref","return","sbyte","sealed","set","short","sizeof","stackalloc","static","string","struct",
        "switch","this","throw","true","try","typeof","uint","ulong","unchecked","unsafe","ushort",
        "using","var","virtual","void","volatile","when","where","while","yield",
    };

    private static readonly IReadOnlySet<string> JavaScript = new HashSet<string>(StringComparer.Ordinal)
    {
        "async","await","break","case","catch","class","const","continue","debugger","default","delete",
        "do","else","enum","export","extends","false","finally","for","from","function","if","implements",
        "import","in","instanceof","interface","let","new","null","of","return","static","super","switch",
        "this","throw","true","try","type","typeof","undefined","var","void","while","yield",
    };

    private static readonly IReadOnlySet<string> Sql = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
    {
        "select","from","where","join","inner","left","right","outer","on","group","by","order","having",
        "insert","into","values","update","set","delete","create","table","alter","drop","index","view",
        "and","or","not","null","as","distinct","union","all","case","when","then","else","end","limit",
    };

    private static readonly IReadOnlySet<string> Shell = new HashSet<string>(StringComparer.Ordinal)
    {
        "if","then","else","elif","fi","for","in","do","done","while","case","esac","function","return",
        "export","local","true","false","null","FROM","RUN","CMD","COPY","ADD","ENV","WORKDIR","ENTRYPOINT",
    };

    private static readonly IReadOnlySet<string> Json = new HashSet<string>(StringComparer.Ordinal)
    {
        "true","false","null",
    };
}

public enum TokenKind { Plain, Keyword, Type, Method, String, Number, Comment, Punctuation }

public sealed record SourceSpan(string Text, TokenKind Kind);

public sealed record SourceLine(int Number, IReadOnlyList<SourceSpan> Spans);
