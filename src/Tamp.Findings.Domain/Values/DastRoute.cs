using System.Diagnostics.CodeAnalysis;

namespace Tamp.Findings.Domain.Values;

// Route identity for dynamic-scan findings.
//
// A DAST finding has no file path — it has the request the scanner made. Two
// consumers need to agree on what "the same endpoint" means: FindingHasher,
// which decides whether two findings across builds are the same finding, and
// the DAST browse endpoint, which groups findings into a route tree. If they
// disagree, the UI shows a different set of routes than the dedup logic
// believes exist, so the normalisation lives here once.
public static class DastRoute
{
    // Split a target URL into its route path and the sorted, comma-joined
    // names of its query parameters.
    //
    // Query VALUES are dropped deliberately: a dynamic scanner reports the URI
    // it actually requested, attack payload included, so the value is scan
    // noise rather than identity. Parameter NAMES are kept because two
    // injectable parameters on one route are two different things to fix.
    //
    // The origin is dropped so the same route matches across environments and
    // ingress renames; which deployment was scanned belongs to the
    // ComponentVersion.
    //
    // Anything unparseable falls back to a hand-split of the raw string so a
    // malformed URI still produces a deterministic result rather than
    // collapsing every finding onto the empty route.
    public static (string Path, string ParamNames) Normalize(string? targetUrl)
    {
        if (string.IsNullOrWhiteSpace(targetUrl)) return (string.Empty, string.Empty);

        var raw = targetUrl.Trim();
        string path;
        string query;

        if (IsHttpUri(raw, out var uri))
        {
            path = uri.AbsolutePath;
            query = uri.Query;
        }
        else
        {
            var noFragment = raw.Split('#', 2)[0];
            var parts = noFragment.Split('?', 2);
            path = parts[0];
            query = parts.Length > 1 ? "?" + parts[1] : string.Empty;
        }

        // Trailing slashes are not meaningful for route identity, but the root
        // path must not normalise away to empty.
        if (path.Length > 1) path = path.TrimEnd('/');
        if (path.Length == 0) path = "/";

        if (query.Length <= 1) return (path, string.Empty);

        var names = query.TrimStart('?')
            .Split('&', StringSplitOptions.RemoveEmptyEntries)
            .Select(p => p.Split('=', 2)[0])
            .Where(n => n.Length > 0)
            .Select(n => n.Trim())
            .Distinct(StringComparer.Ordinal)
            .OrderBy(n => n, StringComparer.Ordinal);

        return (path, string.Join(",", names));
    }

    // Host of the scanned target, for grouping the route tree. Unlike
    // Normalize this DOES keep the origin — the tree groups by deployment so a
    // reader can see which environment produced a finding, even though finding
    // identity ignores it.
    public static string HostOf(string? targetUrl)
    {
        if (string.IsNullOrWhiteSpace(targetUrl)) return "(unknown host)";
        return IsHttpUri(targetUrl.Trim(), out var uri)
            ? uri.IsDefaultPort ? uri.Host : $"{uri.Host}:{uri.Port}"
            : "(relative)";
    }

    // Absolute-URI test that means the same thing on every OS.
    //
    // Uri.TryCreate(.., UriKind.Absolute, ..) is NOT platform-independent: on
    // Unix a rooted path like "/orders?id=1" is an *implicit file URI*
    // (file:///orders?id=1) and parses successfully, while on Windows the same
    // string is not absolute and fails. Branching on it alone put Linux and
    // Windows on different code paths, so one DAST finding hashed two ways
    // depending on where it was ingested from (TFND-130).
    //
    // A dynamic scanner reports the HTTP(S) request it made, so requiring an
    // http/https scheme is both the correct domain constraint and the thing
    // that makes the branch platform-stable. Everything else — rooted paths,
    // relative paths, malformed strings — takes the hand-split fallback on
    // every OS.
    private static bool IsHttpUri(string raw, [NotNullWhen(true)] out Uri? uri) =>
        Uri.TryCreate(raw, UriKind.Absolute, out uri)
        && (uri.Scheme == Uri.UriSchemeHttp || uri.Scheme == Uri.UriSchemeHttps);

    // Display form of a route: path plus its parameter names, so two rows on
    // the same path are distinguishable at a glance.
    public static string Display(string path, string paramNames) =>
        paramNames.Length == 0 ? path : $"{path}?{paramNames}";
}
