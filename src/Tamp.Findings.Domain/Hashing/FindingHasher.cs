using System.Security.Cryptography;
using System.Text;
using Tamp.Findings.Domain.Values;

namespace Tamp.Findings.Domain.Hashing;

// Line-independent finding hash per TFND-6 / F5. Inputs are scanner, rule
// id, project-relative file path, and a whitespace-normalized snippet.
// Snippet normalization in v0 is "trim + collapse internal whitespace runs"
// — language-aware normalization (comment stripping) is a later refinement.
public static class FindingHasher
{
    public static string Compute(ScannerKind scanner, string ruleId, string? filePath, string? snippet)
    {
        var sb = new StringBuilder();
        sb.Append((int)scanner).Append('');
        sb.Append(ruleId).Append('');
        sb.Append(filePath ?? string.Empty).Append('');
        sb.Append(NormalizeSnippet(snippet));

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
