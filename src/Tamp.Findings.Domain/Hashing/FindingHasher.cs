using System.Security.Cryptography;
using System.Text;
using Tamp.Findings.Domain.Values;

namespace Tamp.Findings.Domain.Hashing;

// Line-independent finding hash per TFND-6 / F5. Inputs are scanner, rule
// id, project-relative file path, and a whitespace-normalized snippet.
// When the scanner does not emit a snippet, line is used as a fallback
// disambiguator — brittle on edits but at least keeps sibling findings of
// the same rule in the same file distinct from each other within one run.
public static class FindingHasher
{
    public static string Compute(ScannerKind scanner, string ruleId, string? filePath, string? snippet, int? line = null)
    {
        var sb = new StringBuilder();
        sb.Append((int)scanner).Append('');
        sb.Append(ruleId).Append('');
        sb.Append(filePath ?? string.Empty).Append('');

        var normalized = NormalizeSnippet(snippet);
        if (normalized.Length > 0)
        {
            sb.Append(normalized);
        }
        else if (line is not null)
        {
            sb.Append("#L").Append(line.Value);
        }

        var bytes = Encoding.UTF8.GetBytes(sb.ToString());
        var hash = SHA256.HashData(bytes);
        return Convert.ToHexStringLower(hash);
    }

    private static string NormalizeSnippet(string? snippet)
    {
        if (string.IsNullOrWhiteSpace(snippet))
        {
            return string.Empty;
        }

        var trimmed = snippet.AsSpan().Trim();
        var sb = new StringBuilder(trimmed.Length);
        var inWhitespace = false;
        foreach (var c in trimmed)
        {
            if (char.IsWhiteSpace(c))
            {
                if (!inWhitespace)
                {
                    sb.Append(' ');
                    inWhitespace = true;
                }
            }
            else
            {
                sb.Append(c);
                inWhitespace = false;
            }
        }
        return sb.ToString();
    }
}
