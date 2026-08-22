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

    // Dynamic-scan (DAST) hash. Static scanners key a finding on where it
    // lives in the source tree; a dynamic scanner has no source, only the
    // request it made. The identity of a DAST finding is
    // (rule, endpoint, method, injected parameter).
    //
    // Why this can't reuse Compute(): ZAP puts the ATTACK PAYLOAD inside the
    // reported URI — the documented example is
    // /greeting?name=%3C%2Fp%3E%3Cscript%3E... — so hashing the raw URI mints
    // a brand-new hash on every scan. Findings would never dedup across
    // builds, FirstSeen would reset every run, and open-finding counts would
    // grow without bound. Stripping query VALUES while keeping the parameter
    // NAMES is what makes the hash stable across scans while still telling
    // two distinct injectable parameters apart.
    //
    // The origin (scheme/host/port) is deliberately excluded: the same
    // weakness on the same route is the same finding whether it was observed
    // on staging-7 or on a renamed ingress. Environment lives on the
    // ComponentVersion, not in the finding identity.
    public static string ComputeForDynamic(
        ScannerKind scanner,
        string ruleId,
        string? targetUrl,
        string? httpMethod = null,
        string? parameter = null)
    {
        var sb = new StringBuilder();
        sb.Append((int)scanner).Append('');
        sb.Append(ruleId).Append('');

        var (path, paramNames) = DastRoute.Normalize(targetUrl);
        sb.Append(path).Append('');
        sb.Append(paramNames).Append('');
        sb.Append(httpMethod?.Trim().ToUpperInvariant() ?? string.Empty).Append('');
        sb.Append(parameter?.Trim() ?? string.Empty);

        var bytes = Encoding.UTF8.GetBytes(sb.ToString());
        return Convert.ToHexStringLower(SHA256.HashData(bytes));
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
