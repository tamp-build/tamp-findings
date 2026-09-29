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
    // TFND-128 landed: Blazor owns the root. Portfolio answers on both "/" and
    // "/portfolio", and this constant stays the explicit form so a generated
    // link is self-describing in a log or an email.
    public const string Portfolio = "/portfolio";

    /// <summary>
    /// Stands in for a commit sha when the caller means "whatever is newest".
    ///
    /// A link into a project from the portfolio cannot know a sha, and
    /// omitting the segment would need a second route shape. A sentinel keeps
    /// one route — but it MUST be translated to null before it reaches the
    /// query, or it gets treated as a commit prefix and matches nothing.
    /// </summary>
    public const string LatestBuild = "latest";

    /// <summary>
    /// The client tier (TFND-127). Load-bearing rather than decorative: without
    /// it the hierarchy has a gap between the portfolio and a project, and an
    /// inherited policy is invisible from the project it applies to.
    /// </summary>
    public static string Client(string client) => $"/c/{E(client)}";

    public static string ProjectHub(string client, string project, string? sha = null) =>
        $"/c/{E(client)}/p/{E(project)}/build/{E(sha ?? LatestBuild)}";

    /// <summary>A scored-category detail page (v3 §3), e.g. sastSevere, cve, coverage.</summary>
    public static string Category(string client, string project, string sha, string key) =>
        $"/c/{E(client)}/p/{E(project)}/build/{E(sha)}/score/{E(key)}";

    /// <summary>
    /// A collected-evidence detail page (v3 §4). One frame, one key: dast, kev,
    /// quality, a11y, baseImage, poam, provenance, vdp, vex, conformance. Distinct
    /// from <see cref="Category"/> (which explains a SCORE) — evidence pages show
    /// what a source produced and whether a gate or SSDF practice rides on it.
    /// </summary>
    public static string Evidence(string client, string project, string sha, string key) =>
        $"/c/{E(client)}/p/{E(project)}/build/{E(sha)}/evidence/{E(key)}";

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
    /// <summary>Costs &amp; licences (TFND-8 / F7.3).</summary>
    public static string Costs(string client, string project) => $"/c/{E(client)}/p/{E(project)}/costs";

    public static string Vex(string client, string project) => $"/c/{E(client)}/p/{E(project)}/vex";

    /// <summary>Conformance rule review (TFND-194): promote ADR-conformance rules
    /// Draft→Reviewed — the human-review gate that lets a verdict block a build.</summary>
    public static string ConformanceRules(string client, string project) =>
        $"/c/{E(client)}/p/{E(project)}/conformance-rules";

    /// <summary>Control-coverage matrix (TFND-195): the framework's in-scope controls
    /// and their disposition (gated / inherited / n-a / unmapped, ADR 0009).</summary>
    public static string ControlCoverage(string client, string project) =>
        $"/c/{E(client)}/p/{E(project)}/coverage";

    /// <summary>Undocumented decisions (TFND-197 / ADR 0013): reverse-examination advisories —
    /// architectural decisions in the code that no ADR records (CM-3 change-control drift).</summary>
    public static string Decisions(string client, string project) =>
        $"/c/{E(client)}/p/{E(project)}/decisions";

    /// <summary>
    /// Deep link to one statement, or to writing the one that is missing.
    ///
    /// The SBOM table's VEX cell is the product's main path into VEX authoring,
    /// and it always knows both halves of the key — so it hands them over
    /// rather than dropping the reader on a list to find their own row again.
    /// Carried as query parameters because a purl contains slashes, colons and
    /// an '@'.
    /// </summary>
    public static string VexStatement(string client, string project, string purl, string advisoryId) =>
        $"{Vex(client, project)}?purl={E(purl)}&advisory={E(advisoryId)}";

    public static string Attestation(string client, string project, string sha) =>
        $"{ProjectHub(client, project, sha)}/attestation";

    public static string Policy(string client, string project) => $"/c/{E(client)}/p/{E(project)}/settings/policy";
    /// <summary>The three-layer effective-policy view (ADR 0007), distinct from
    /// the weights/gates editor at <see cref="Policy"/>.</summary>
    public static string ProjectPolicy(string client, string project) => $"/c/{E(client)}/p/{E(project)}/policy";
    public static string ClientPolicy(string client) => $"/c/{E(client)}/policy";
    public static string Keys(string client, string project) => $"/c/{E(client)}/p/{E(project)}/settings/keys";

    public static string System(string panel = SystemPanels.Users) => $"/system/{E(panel)}";

    /// <summary>System → Control frameworks (v3 §6). A dedicated page rather than
    /// a SystemAdmin panel — the catalog and statement panel are substantial.</summary>
    public static string Frameworks() => "/system/frameworks";

    /// <summary>Manage → Policy templates (ADR 0007). The list, or one template's editor.</summary>
    public static string PolicyTemplates(Guid? id = null) =>
        id is { } g ? $"/manage/policy-templates/{g}" : "/manage/policy-templates";

    private static string E(string s) => Uri.EscapeDataString(s);
}

/// <summary>The collected-evidence keys (v3 §4). One evidence-detail frame per key.</summary>
public static class EvidenceKeys
{
    public const string Dast = "dast";
    public const string Kev = "kev";
    public const string Quality = "quality";
    public const string Accessibility = "a11y";
    public const string BaseImage = "baseImage";
    public const string Poam = "poam";
    public const string Provenance = "provenance";
    public const string Vdp = "vdp";
    public const string Vex = "vex";
    public const string Conformance = "conformance";

    public static readonly IReadOnlyList<string> All =
        [Dast, Kev, Quality, Accessibility, BaseImage, Poam, Provenance, Vdp, Vex, Conformance];

    public static bool IsValid(string? key) => key is not null && All.Contains(key);
}

/// <summary>The explorer's spines. One shell, one body each.</summary>
public static class Spines
{
    public const string Sast = "sast";
    public const string Dast = "dast";
    public const string Sbom = "sbom";
    public const string Coverage = "coverage";
    public const string Tests = "tests";

    /// <summary>
    /// Section 508 / WCAG 2.1 AA (TFND-27).
    ///
    /// A sixth spine rather than a fold into DAST, even though both are
    /// route-shaped: an accessibility defect is read by UX and by compliance,
    /// and burying it among security alerts would put it in front of the wrong
    /// people. The hand-off's five were the five that existed when it was
    /// written, not a ceiling.
    /// </summary>
    public const string Accessibility = "a11y";

    public static readonly IReadOnlyList<string> All =
        [Sast, Dast, Sbom, Coverage, Tests, Accessibility];

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

    /// <summary>The paid-component registry (TFND-8 / F7.2).</summary>
    public const string PaidComponents = "paid-components";

    public static readonly IReadOnlyList<string> All =
        [Users, Authentication, Scanners, PaidComponents, Settings, Audit];

    public static bool IsValid(string? panel) => panel is not null && All.Contains(panel);
}
