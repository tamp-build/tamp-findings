namespace Tamp.Findings.Web.Routing;

/// <summary>
/// The URL scheme, in one place.
///
/// Introducing a router is the highest-value structural change in the TFND-40
/// redesign — navigation was <c>useState</c> in the React app, so nothing was
/// addressable and nothing survived a reload. Every sidebar item, tab,
/// breadcrumb and drill affordance changes the URL, and these builders are how
/// they do it. Hand-built strings will drift.
/// </summary>
public static class Routes
{
    // Portfolio does NOT claim "/" yet. The React SPA still serves the root and
    // everything MapFallbackToFile catches, and an explicit Blazor route would
    // shadow index.html. At cutover (TFND-128) Portfolio gains `@page "/"`
    // alongside its current route and this constant becomes "/".
    public const string Portfolio = "/portfolio";

    public static string ProjectHub(string client, string project, string sha) =>
        $"/c/{E(client)}/p/{E(project)}/build/{E(sha)}";

    /// <param name="spine">sast | dast | sbom | coverage | tests</param>
    /// <param name="selection">
    /// A file path, host, advisory or suite id. Not escaped as a whole: it may
    /// legitimately contain '/' (a nested source path), and the route captures
    /// it as a catch-all so the slashes have to survive.
    /// </param>
    public static string Explorer(string client, string project, string sha, string spine, string? selection = null, int? line = null)
    {
        var url = $"/c/{E(client)}/p/{E(project)}/build/{E(sha)}/{E(spine)}";
        if (!string.IsNullOrEmpty(selection)) url += $"/{selection.TrimStart('/')}";
        // Findings deep links carry a line anchor so a link lands on the
        // flagged line, not merely on the file.
        if (line is > 0) url += $"#L{line}";
        return url;
    }

    public static string Poam(string client, string project) => $"/c/{E(client)}/p/{E(project)}/poam";
    public static string PoamItem(string client, string project, string id) => $"{Poam(client, project)}/{E(id)}";
    public static string Vex(string client, string project) => $"/c/{E(client)}/p/{E(project)}/vex";

    public static string Attestation(string client, string project, string sha) =>
        $"{ProjectHub(client, project, sha)}/attestation";

    public static string Policy(string client, string project) => $"/c/{E(client)}/p/{E(project)}/settings/policy";
    public static string Keys(string client, string project) => $"/c/{E(client)}/p/{E(project)}/settings/keys";

    public static string System(string panel = SystemPanels.Users) => $"/system/{E(panel)}";

    private static string E(string s) => Uri.EscapeDataString(s);
}

/// <summary>The explorer's five spines. One shell, five bodies.</summary>
public static class Spines
{
    public const string Sast = "sast";
    public const string Dast = "dast";
    public const string Sbom = "sbom";
    public const string Coverage = "coverage";
    public const string Tests = "tests";

    public static readonly IReadOnlyList<string> All = [Sast, Dast, Sbom, Coverage, Tests];

    public static bool IsValid(string? spine) => spine is not null && All.Contains(spine);
}

/// <summary>
/// Instance-level panels. These sit OUTSIDE any client or project scope, which
/// is why the nav separates them and the tab strip marks them differently.
/// </summary>
public static class SystemPanels
{
    public const string Users = "users";
    public const string Authentication = "authentication";
    public const string Scanners = "scanners";
    public const string Settings = "settings";
    public const string Audit = "audit";

    public static readonly IReadOnlyList<string> All = [Users, Authentication, Scanners, Settings, Audit];

    public static bool IsValid(string? panel) => panel is not null && All.Contains(panel);
}
