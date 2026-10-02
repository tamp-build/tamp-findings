using System.Security.Claims;
using System.Text.Encodings.Web;
using System.Text.Json;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Tamp.Findings.Api.Authentication;
using Tamp.Findings.Data;
using Tamp.Findings.Domain.Entities;
using Tamp.Findings.Domain.Values;

namespace Tamp.Findings.Integration.Tests;

/// <summary>
/// Test authentication for the user-facing (cookie-protected) query endpoints.
/// The caller names the user in a header; the handler turns it into the same
/// claim the cookie carries. Authorization still runs for real.
/// </summary>
public sealed class ApiATestAuthHandler : AuthenticationHandler<AuthenticationSchemeOptions>
{
    public const string SchemeName = "ApiATest";
    public const string Header = "X-ApiA-User";

    public ApiATestAuthHandler(IOptionsMonitor<AuthenticationSchemeOptions> options, ILoggerFactory logger, UrlEncoder encoder)
        : base(options, logger, encoder) { }

    protected override Task<AuthenticateResult> HandleAuthenticateAsync()
    {
        if (!Request.Headers.TryGetValue(Header, out var raw) || string.IsNullOrWhiteSpace(raw.ToString()))
            return Task.FromResult(AuthenticateResult.NoResult());

        var identity = new ClaimsIdentity(
        [
            new Claim(ClaimTypes.Name, "apia-" + raw),
            new Claim(AuthExtensions.TampUserIdClaim, raw.ToString()),
        ], SchemeName);
        return Task.FromResult(AuthenticateResult.Success(
            new AuthenticationTicket(new ClaimsPrincipal(identity), SchemeName)));
    }
}

/// <summary>Host + seeding helpers for the ApiA* endpoint test files.</summary>
public static class ApiAHarness
{
    private static readonly object Gate = new();
    private static WebApplicationFactory<Program>? _factory;

    private static WebApplicationFactory<Program> AuthFactory(DatabaseFixture fx)
    {
        lock (Gate)
        {
            return _factory ??= fx.Factory!.WithWebHostBuilder(b => b.ConfigureTestServices(services =>
            {
                services.AddAuthentication(ApiATestAuthHandler.SchemeName)
                    .AddScheme<AuthenticationSchemeOptions, ApiATestAuthHandler>(ApiATestAuthHandler.SchemeName, _ => { });
                services.PostConfigure<AuthenticationOptions>(o =>
                {
                    o.DefaultAuthenticateScheme = ApiATestAuthHandler.SchemeName;
                    o.DefaultChallengeScheme = ApiATestAuthHandler.SchemeName;
                    o.DefaultForbidScheme = ApiATestAuthHandler.SchemeName;
                    o.DefaultScheme = ApiATestAuthHandler.SchemeName;
                });
            }));
        }
    }

    /// <summary>A client signed in as the given user, or anonymous when null.</summary>
    public static HttpClient Http(DatabaseFixture fx, Guid? userId)
    {
        var http = AuthFactory(fx).CreateClient();
        if (userId is { } id) http.DefaultRequestHeaders.Add(ApiATestAuthHandler.Header, id.ToString());
        return http;
    }

    public static async Task<JsonDocument> JsonAsync(HttpResponseMessage resp)
    {
        var text = await resp.Content.ReadAsStringAsync();
        return JsonDocument.Parse(text);
    }

    public static async Task<JsonElement> GetJsonAsync(HttpClient http, string url)
    {
        var resp = await http.GetAsync(url);
        Xunit.Assert.True(resp.IsSuccessStatusCode, $"GET {url} -> {(int)resp.StatusCode}: {await resp.Content.ReadAsStringAsync()}");
        return (await JsonAsync(resp)).RootElement.Clone();
    }

    public static string Sfx() => Guid.NewGuid().ToString("N")[..8];

    public static async Task<Guid> UserAsync(DatabaseFixture fx, bool admin, bool approved = true)
    {
        var s = Sfx();
        using var scope = fx.Scope();
        var db = fx.Db(scope);
        var u = new User
        {
            Login = $"apia-{s}", DisplayName = $"ApiA {s}", Email = $"apia{s}@e.test",
            IsApproved = approved, IsAdmin = admin,
        };
        db.Users.Add(u);
        await db.SaveChangesAsync();
        return u.Id;
    }

    public static async Task GrantAsync(DatabaseFixture fx, Guid userId, ProjectRole role, Guid? clientId, Guid? projectId)
    {
        using var scope = fx.Scope();
        var db = fx.Db(scope);
        db.ProjectRoleAssignments.Add(new ProjectRoleAssignment
        {
            UserId = userId, Role = role, ClientId = clientId, ProjectId = projectId,
        });
        await db.SaveChangesAsync();
    }

    public sealed record Tree(Guid ClientId, string ClientName, Guid ProjectId, string ProjectName);

    public static async Task<Tree> ClientProjectAsync(DatabaseFixture fx, Guid? existingClient = null, string? existingClientName = null)
    {
        var s = Sfx();
        using var scope = fx.Scope();
        var db = fx.Db(scope);
        Client client;
        if (existingClient is { } cid) client = new Client { Id = cid, Name = existingClientName! };
        else { client = new Client { Name = $"apia-client-{s}" }; db.Clients.Add(client); }
        var project = new Project { ClientId = client.Id, Name = $"apia-project-{s}" };
        db.Projects.Add(project);
        await db.SaveChangesAsync();
        return new Tree(client.Id, client.Name, project.Id, project.Name);
    }

    public static async Task<Guid> VersionAsync(
        DatabaseFixture fx, Guid projectId, string version, string? flavor = null,
        string? branch = "main", string? pr = null, DateTimeOffset? createdAt = null)
    {
        using var scope = fx.Scope();
        var db = fx.Db(scope);
        var cv = new ComponentVersion
        {
            ProjectId = projectId, VersionString = version, Flavor = flavor,
            BranchName = branch, PullRequestRef = pr,
            CreatedAt = createdAt ?? DateTimeOffset.UtcNow,
        };
        db.ComponentVersions.Add(cv);
        await db.SaveChangesAsync();
        return cv.Id;
    }

    public static Finding NewFinding(
        Guid cvId, ScannerKind scanner, Severity sev, string rule,
        FindingStatus status = FindingStatus.Open, string? path = null, int? line = null,
        string? subCategory = null, string? title = null) => new()
    {
        ComponentVersionId = cvId,
        Hash = Guid.NewGuid().ToString("N"),
        Scanner = scanner, Severity = sev, RuleId = rule,
        Title = title ?? $"{rule} title", Description = $"{rule} description",
        FilePath = path, Line = line, Status = status, SubCategory = subCategory,
    };

    public static async Task AddFindingsAsync(DatabaseFixture fx, params Finding[] findings)
    {
        using var scope = fx.Scope();
        var db = fx.Db(scope);
        db.Findings.AddRange(findings);
        await db.SaveChangesAsync();
    }

    public sealed record SbomSeed(Guid SnapshotId, Dictionary<string, Guid> ComponentIds, Dictionary<string, Guid> VulnIds);

    /// <summary>
    /// A snapshot on the version with the given components. Each tuple:
    /// (purl, version, license, latestVersion, latestReleasedAt, vulnerabilities as (advisory, severity)).
    /// </summary>
    public static async Task<SbomSeed> SbomAsync(
        DatabaseFixture fx, Guid cvId, DateTimeOffset? ingestedAt,
        params (string Purl, string Version, string? License, string? Latest, DateTimeOffset? LatestAt,
                (string Advisory, Severity Sev)[] Vulns)[] comps)
    {
        using var scope = fx.Scope();
        var db = fx.Db(scope);
        var snap = new SbomSnapshot
        {
            ComponentVersionId = cvId, ToolName = "syft", SpecVersion = "1.5",
            IngestedAt = ingestedAt ?? DateTimeOffset.UtcNow,
        };
        db.SbomSnapshots.Add(snap);
        var compIds = new Dictionary<string, Guid>();
        var vulnIds = new Dictionary<string, Guid>();
        foreach (var c in comps)
        {
            var name = c.Purl[(c.Purl.LastIndexOf('/') + 1)..];
            var comp = new SbomComponent
            {
                SbomSnapshotId = snap.Id, Purl = $"{c.Purl}@{c.Version}", Name = name, Version = c.Version,
                Kind = "library", License = c.License, LatestVersion = c.Latest, LatestReleasedAt = c.LatestAt,
            };
            db.SbomComponents.Add(comp);
            compIds[c.Purl] = comp.Id;
            foreach (var (adv, sev) in c.Vulns)
            {
                var v = new Vulnerability
                {
                    SbomComponentId = comp.Id, AdvisoryId = adv, Severity = sev,
                    Title = $"{adv} title", Description = $"{adv} desc", FixedInVersion = "9.9.9",
                    ReferenceUrl = $"https://example.test/{adv}", Source = ScannerKind.OsvScanner,
                };
                db.Vulnerabilities.Add(v);
                vulnIds[adv] = v.Id;
            }
        }
        await db.SaveChangesAsync();
        return new SbomSeed(snap.Id, compIds, vulnIds);
    }

    public static async Task AddScanRunAsync(
        DatabaseFixture fx, Guid cvId, ScannerKind scanner, ScanRunStatus status,
        DateTimeOffset completed, int findings = 0)
    {
        using var scope = fx.Scope();
        var db = fx.Db(scope);
        db.ScanRunReceipts.Add(new ScanRunReceipt
        {
            ComponentVersionId = cvId, Scanner = scanner, Status = status,
            StartedAt = completed.AddMinutes(-1), CompletedAt = completed,
            FindingsCount = findings, ToolName = scanner.ToString(), ToolVersion = "1.0",
        });
        await db.SaveChangesAsync();
    }

    public static string Cve() => $"CVE-2099-{Random.Shared.Next(100000, 999999)}";
}
