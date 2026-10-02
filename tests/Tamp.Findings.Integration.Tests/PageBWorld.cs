using System.Security.Claims;
using System.Text.Encodings.Web;
using System.Xml.Linq;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.DataProtection.KeyManagement;
using Microsoft.AspNetCore.DataProtection.Repositories;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.AspNetCore.TestHost;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Tamp.Findings.Api.Authentication;
using Tamp.Findings.Data;
using Tamp.Findings.Domain.Compliance;
using Tamp.Findings.Domain.Entities;
using Tamp.Findings.Domain.Risk;
using Tamp.Findings.Domain.Values;

namespace Tamp.Findings.Integration.Tests;

/// <summary>
/// Shared, lazily-seeded world for the PageB* page-render tests.
///
/// One richly-populated project (every scanner kind, SBOM with CVEs / KEV /
/// licences / staleness, coverage, tests, receipts, POA&amp;M, VEX, quality gate,
/// conformance, container images, attestation...) plus an EMPTY project (one
/// build, no evidence) and a project with NO builds. Pages are rendered over HTTP
/// as one of three users selected by a request header.
/// </summary>
public sealed class PageBWorld
{
    public const string UserHeader = "X-PageB-User";
    public const string Admin = "admin";
    public const string Lead = "lead";
    public const string Viewer = "viewer";
    public const string Iso = "iso";

    private static readonly SemaphoreSlim Gate = new(1, 1);
    private static PageBWorld? _instance;

    public required WebApplicationFactory<Program> Host { get; init; }
    public required string Client { get; init; }
    public required string Rich { get; init; }
    public required string Empty { get; init; }
    public required string NoBuilds { get; init; }
    public required Guid RichProjectId { get; init; }
    public required Guid EmptyProjectId { get; init; }
    public required Guid ClientId { get; init; }
    public required string ShaOld { get; init; }
    public required string ShaMid { get; init; }
    public required string ShaNew { get; init; }
    public required string EmptySha { get; init; }
    public required string Tag { get; init; }
    public required Guid PoamItemId { get; init; }
    public required Guid[] PoamItemIds { get; init; }

    public static readonly Guid AdminId = Guid.NewGuid();
    public static readonly Guid LeadId = Guid.NewGuid();
    public static readonly Guid ViewerId = Guid.NewGuid();
    public static readonly Guid IsoId = Guid.NewGuid();

    /// <summary>A fresh, empty project under the shared client, for tests that mutate data.</summary>
    public async Task<(string Name, Guid Id)> NewProjectAsync(string prefix)
    {
        using var scope = Host.Services.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<FindingsDbContext>();
        var p = new Project { ClientId = ClientId, Name = prefix + Guid.NewGuid().ToString("N")[..8] };
        db.Projects.Add(p);
        await db.SaveChangesAsync();
        return (p.Name, p.Id);
    }

    /// <summary>A fresh project with one build carrying a few findings and an SBOM, for mutating tests.</summary>
    public async Task<(string Name, Guid Id, string Sha)> NewBuiltProjectAsync(string prefix)
    {
        var (name, id) = await NewProjectAsync(prefix);
        using var scope = Host.Services.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<FindingsDbContext>();
        var sha = Guid.NewGuid().ToString("N") + "00000000";
        sha = sha[..40];
        var cv = new ComponentVersion { ProjectId = id, VersionString = "1.0.0", CommitSha = sha, BranchName = "main", CreatedAt = DateTimeOffset.UtcNow };
        db.ComponentVersions.Add(cv);
        await db.SaveChangesAsync();
        var uniq = Guid.NewGuid().ToString("N")[..8];
        await SeedBuildAsync(db, cv, uniq, DateTimeOffset.UtcNow, 2, uniq);
        // A host that looks like a duplicate of app.example.test (same leftmost label).
        db.Findings.Add(new Finding
        {
            ComponentVersionId = cv.Id, Hash = Guid.NewGuid().ToString("N"), Scanner = ScannerKind.Zap, RuleId = "10202", Severity = Severity.Low,
            Title = "Internal host finding", FilePath = "https://app.internal.test/api/health",
        });
        await db.SaveChangesAsync();
        return (name, id, sha);
    }

    public HttpClient Http(string who = Admin)
    {
        var c = Host.CreateClient();
        c.DefaultRequestHeaders.Add(UserHeader, who);
        return c;
    }

    /// <summary>GET and return (status, body). Never throws on non-2xx.</summary>
    public async Task<(System.Net.HttpStatusCode Status, string Body)> GetAsync(string url, string who = Admin)
    {
        using var c = Http(who);
        using var resp = await c.GetAsync(url);
        return (resp.StatusCode, await resp.Content.ReadAsStringAsync());
    }

    public string Build(string sha, string? tail = null) =>
        $"/c/{Client}/p/{Rich}/build/{sha}" + (tail is null ? "" : "/" + tail);

    public static async Task<PageBWorld> GetAsync(DatabaseFixture fx)
    {
        if (_instance is not null) return _instance;
        await Gate.WaitAsync();
        try
        {
            return _instance ??= await SeedAsync(fx);
        }
        finally { Gate.Release(); }
    }

    private static async Task<PageBWorld> SeedAsync(DatabaseFixture fx)
    {
        var host = fx.Factory!.WithWebHostBuilder(b => b.ConfigureTestServices(services =>
        {
            services.AddOptions<KeyManagementOptions>()
                .Configure(o => o.XmlRepository = new MemXmlRepository());
            services.AddAuthentication(PageBAuthHandler.SchemeName)
                .AddScheme<AuthenticationSchemeOptions, PageBAuthHandler>(PageBAuthHandler.SchemeName, _ => { });
            services.PostConfigure<AuthenticationOptions>(o =>
            {
                o.DefaultAuthenticateScheme = PageBAuthHandler.SchemeName;
                o.DefaultChallengeScheme = PageBAuthHandler.SchemeName;
                o.DefaultScheme = PageBAuthHandler.SchemeName;
            });
        }));

        using var scope = host.Services.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<FindingsDbContext>();
        var tag = Guid.NewGuid().ToString("N")[..8];
        var now = DateTimeOffset.UtcNow;

        db.Users.AddRange(
            new User { Id = AdminId, Login = "pageb-admin-" + tag, DisplayName = "PageB Admin", Email = $"a{tag}@example.test", IsApproved = true, IsAdmin = true },
            new User { Id = LeadId, Login = "pageb-lead-" + tag, DisplayName = "PageB Lead", Email = $"l{tag}@example.test", IsApproved = true },
            new User { Id = ViewerId, Login = "pageb-viewer-" + tag, DisplayName = "PageB Viewer", Email = $"v{tag}@example.test", IsApproved = true },
            new User { Id = IsoId, Login = "pageb-iso-" + tag, DisplayName = "PageB Iso", Email = $"i{tag}@example.test", IsApproved = true });

        var client = new Client { Name = "PageBClient" + tag };
        var rich = new Project
        {
            ClientId = client.Id, Name = "rich" + tag, Description = "Rich seeded project",
            Archetype = ProjectArchetype.ServiceApp, GitHubRepository = "acme/rich",
            VdpPolicyUrl = "https://example.test/security", VdpContactEmail = "sec@example.test",
            PublicReportEnabled = true, ReportKey = "rk" + tag, BadgeKey = "bk" + tag,
            GatesConfig = AllGates(),
        };
        var empty = new Project { ClientId = client.Id, Name = "empty" + tag, GatesConfig = AllGates() };
        var nobuilds = new Project { ClientId = client.Id, Name = "nobuilds" + tag };
        db.Clients.Add(client);
        db.Projects.AddRange(rich, empty, nobuilds);
        db.ProjectRoleAssignments.Add(new ProjectRoleAssignment { UserId = LeadId, Role = ProjectRole.LeadDev, ClientId = client.Id });
        db.ProjectRoleAssignments.Add(new ProjectRoleAssignment { UserId = IsoId, Role = ProjectRole.InfoSecOfficer, ClientId = client.Id });
        await db.SaveChangesAsync();

        var shaOld = Sha(tag, "a");
        var shaMid = Sha(tag, "b");
        var shaNew = Sha(tag, "c");
        var emptySha = Sha(tag, "e");

        var cvOld = new ComponentVersion { ProjectId = rich.Id, VersionString = "1.0.0", CommitSha = shaOld, BranchName = "main", CreatedAt = now.AddDays(-5), ActorId = "ci", ActorKind = IngestActorKind.Agent };
        var cvMid = new ComponentVersion { ProjectId = rich.Id, VersionString = "1.1.0", CommitSha = shaMid, BranchName = "main", CreatedAt = now.AddDays(-3), ActorId = "ci", ActorKind = IngestActorKind.Agent };
        var cvNew = new ComponentVersion { ProjectId = rich.Id, VersionString = "1.2.0", CommitSha = shaNew, BranchName = "main", BuildId = "42", CreatedAt = now.AddDays(-1), ActorId = "scott", ActorKind = IngestActorKind.Human };
        var cvEmpty = new ComponentVersion { ProjectId = empty.Id, VersionString = "0.1.0", CommitSha = emptySha, BranchName = "main", CreatedAt = now.AddDays(-1) };
        db.ComponentVersions.AddRange(cvOld, cvMid, cvNew, cvEmpty);
        await db.SaveChangesAsync();

        await SeedBuildAsync(db, cvOld, tag, now.AddDays(-5), 0);
        await SeedBuildAsync(db, cvMid, tag, now.AddDays(-3), 1);
        var newFindings = await SeedBuildAsync(db, cvNew, tag, now.AddDays(-1), 2);

        // Extra flavors of the newest commit, each with its own container image.
        var cvW = new ComponentVersion { ProjectId = rich.Id, Flavor = "worker", VersionString = "1.2.0", CommitSha = shaNew, BranchName = "main", CreatedAt = now.AddDays(-1) };
        var cvO = new ComponentVersion { ProjectId = rich.Id, Flavor = "legacy", VersionString = "1.2.0", CommitSha = shaNew, BranchName = "main", CreatedAt = now.AddDays(-1) };
        var cvS = new ComponentVersion { ProjectId = rich.Id, Flavor = "scratch", VersionString = "1.2.0", CommitSha = shaNew, BranchName = "main", CreatedAt = now.AddDays(-1) };
        db.ComponentVersions.AddRange(cvW, cvO, cvS);
        db.ContainerImages.AddRange(
            new ContainerImage { ComponentVersionId = cvW.Id, Reference = "ghcr.io/acme/worker:1.2.0", OsFamily = "alpine", BaseImageReference = "alpine:3.20", BaseImageCreatedAt = now.AddDays(-10), InspectedAt = now },
            new ContainerImage { ComponentVersionId = cvO.Id, Reference = "ghcr.io/acme/old:1.2.0", BaseImageReference = "ubuntu:20.04", BaseImageCreatedAt = now.AddDays(-45), InspectedAt = now },
            new ContainerImage { ComponentVersionId = cvS.Id, Reference = "ghcr.io/acme/scratch:1.2.0", InspectedAt = now });
        await db.SaveChangesAsync();

        // Project-level (not per-build) data.
        var poam = await SeedPoamAsync(db, rich.Id, newFindings, now);
        SeedVexAndSuppressions(db, rich.Id, client.Id, newFindings, now);
        SeedPosture(db, rich.Id, now);
        db.IngestTokens.AddRange(
            new IngestToken { Scope = IngestTokenScope.Project, ClientId = client.Id, ProjectId = rich.Id, TokenHash = "h1" + tag, Name = "ci-token", CreatedByUserId = AdminId, LastUsedAt = now.AddHours(-1) },
            new IngestToken { Scope = IngestTokenScope.Project, ClientId = client.Id, ProjectId = rich.Id, TokenHash = "h2" + tag, Name = "old-token", CreatedByUserId = AdminId, RevokedAt = now.AddDays(-1) },
            new IngestToken { Scope = IngestTokenScope.Project, ClientId = client.Id, ProjectId = rich.Id, TokenHash = "h3" + tag, Name = "fork-token", CreatedByUserId = AdminId, Untrusted = true, GraceExpiresAt = now.AddDays(1) },
            new IngestToken { Scope = IngestTokenScope.Client, ClientId = client.Id, TokenHash = "h4" + tag, Name = "client-token", CreatedByUserId = AdminId });
        db.McpTokens.AddRange(
            new McpToken { Name = "agent-live", ProjectId = rich.Id, ClientId = client.Id, Role = ProjectRole.LeadDev, TokenHash = "m1" + tag, CreatedByUserId = AdminId, ExpiresAt = now.AddDays(30) },
            new McpToken { Name = "agent-revoked", ProjectId = rich.Id, ClientId = client.Id, Role = ProjectRole.Auditor, TokenHash = "m2" + tag, CreatedByUserId = AdminId, RevokedAt = now.AddDays(-1) });
        SeedConformance(db, rich.Id, cvNew.Id, now);
        db.ScoreSnapshots.AddRange(
            new ScoreSnapshot { ProjectId = rich.Id, CommitSha = shaOld, Score = 70, Band = "orange", BuiltAt = now.AddDays(-5), PolicyName = "Tamp Standard", Breakdown = new() { ["cve"] = 10 } },
            new ScoreSnapshot { ProjectId = rich.Id, CommitSha = shaNew, Score = 40, Band = "yellow", BuiltAt = now.AddDays(-1), PolicyName = "Tamp Standard", Breakdown = new() { ["cve"] = 5 } });
        db.KevAdvisories.Add(new KevAdvisory
        {
            CveId = KevCve(tag), VendorProject = "Acme", Product = "Widget", VulnerabilityName = "Widget RCE",
            DateAdded = DateOnly.FromDateTime(DateTime.UtcNow.AddDays(-30)), DueDate = DateOnly.FromDateTime(DateTime.UtcNow.AddDays(-10)),
            ShortDescription = "Remote code execution", RequiredAction = "Apply updates", KnownRansomwareCampaignUse = true,
        });
        await db.SaveChangesAsync();

        // Frozen attestations built by the real services: newest = signed, mid = unsigned with
        // a pending sign-off assigned to the admin (so the "awaiting me" branch renders).
        var builder = scope.ServiceProvider.GetRequiredService<Tamp.Findings.Application.Attestation.SsdfAttestationBuilder>();
        var snapshots = scope.ServiceProvider.GetRequiredService<Tamp.Findings.Application.Attestation.AttestationSnapshotService>();
        var approvals = scope.ServiceProvider.GetRequiredService<Tamp.Findings.Application.Approvals.ApprovalService>();
        var target = Tamp.Findings.Application.Authorization.ScopeTarget.Project(client.Id, rich.Id);
        var admin = Tamp.Findings.Application.Authorization.Principal.For(AdminId, "pageb-admin", true, []);
        var lead = Tamp.Findings.Application.Authorization.Principal.For(LeadId, "pageb-lead", false, [ProjectRole.LeadDev]);
        var docNew = await builder.BuildAsync(rich.Id, shaNew);
        var capNew = await snapshots.CaptureAsync(admin, target, rich.Id, docNew!);
        var snapNew = await snapshots.LatestForBuildAsync(rich.Id, shaNew);
        await snapshots.SignAsync(admin, target, rich.Id, snapNew!.Id, "Pat Signatory, CISO");
        var docMid = await builder.BuildAsync(rich.Id, shaMid);
        await snapshots.CaptureAsync(admin, target, rich.Id, docMid!);
        var snapMid = await snapshots.LatestForBuildAsync(rich.Id, shaMid);
        await approvals.RequestAsync(lead, target, Tamp.Findings.Domain.Entities.ApprovalKind.AttestationSignOff,
            nameof(AttestationSnapshot), snapMid!.Id, "please sign", AdminId);
        _ = capNew;

        return new PageBWorld
        {
            Host = host, Client = client.Name, Rich = rich.Name, Empty = empty.Name, NoBuilds = nobuilds.Name,
            RichProjectId = rich.Id, EmptyProjectId = empty.Id, ClientId = client.Id,
            ShaOld = shaOld, ShaMid = shaMid, ShaNew = shaNew, EmptySha = emptySha, Tag = tag,
            PoamItemId = poam[0], PoamItemIds = poam,
        };
    }

    public static string KevCve(string tag) => "CVE-2077-" + Math.Abs(tag.GetHashCode() % 90000 + 10000);

    /// <summary>
    /// A project that did everything right: every scanner ran and found nothing, coverage is high, tests
    /// pass, the SBOM is fresh and permissively licensed, the base image is new, the quality gate is OK.
    /// Exercises the "clean" branches that the noisy rich project never reaches.
    /// </summary>
    public async Task<(string Name, Guid Id, string Sha)> NewCleanProjectAsync(string prefix)
    {
        var (name, id) = await NewProjectAsync(prefix);
        using var scope = Host.Services.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<FindingsDbContext>();
        var now = DateTimeOffset.UtcNow;
        var sha = Guid.NewGuid().ToString("N") + "00000000";
        sha = sha[..40];
        var cv = new ComponentVersion { ProjectId = id, VersionString = "2.0.0", CommitSha = sha, BranchName = "main", CreatedAt = now };
        var proj = await db.Projects.SingleAsync(p => p.Id == id);
        proj.GatesConfig = AllGates();
        proj.Archetype = ProjectArchetype.Library;
        db.ComponentVersions.Add(cv);
        await db.SaveChangesAsync();
        var cvId = cv.Id;

        foreach (var k in new[] { ScannerKind.OpenGrep, ScannerKind.Roslyn, ScannerKind.TruffleHog, ScannerKind.Trivy, ScannerKind.Coverlet, ScannerKind.Syft, ScannerKind.CodeQL })
            db.ScanRunReceipts.Add(new ScanRunReceipt { ComponentVersionId = cvId, Scanner = k, Status = ScanRunStatus.Succeeded, StartedAt = now.AddMinutes(-3), CompletedAt = now, FindingsCount = 0, ToolName = k.ToString(), ToolVersion = "1.0" });
        db.ScanRunReceipts.Add(new ScanRunReceipt { ComponentVersionId = cvId, Scanner = ScannerKind.Grype, Status = ScanRunStatus.Succeeded, StartedAt = now.AddMinutes(-3), CompletedAt = now, FindingsCount = 0, ToolName = "Grype", ToolVersion = "0.80", Notes = "db=grype-db/v6; db_built=2026-09-30T00:00:00Z" });

        var snap = new SbomSnapshot { ComponentVersionId = cvId, SpecVersion = "1.5", ToolName = "syft", ToolVersion = "1.0", IngestedAt = now };
        db.SbomSnapshots.Add(snap);
        db.SbomComponents.AddRange(
            new SbomComponent { SbomSnapshotId = snap.Id, Purl = "pkg:nuget/Clean.A@1.0.0", Name = "Clean.A", Version = "1.0.0", License = "MIT", LatestVersion = "1.0.0", EnrichedAt = now, LatestReleasedAt = now.AddDays(-20), CurrentReleasedAt = now.AddDays(-20) },
            new SbomComponent { SbomSnapshotId = snap.Id, Purl = "pkg:nuget/Clean.B@2.0.0", Name = "Clean.B", Version = "2.0.0", License = "Apache-2.0", LatestVersion = "2.0.0", EnrichedAt = now, LatestReleasedAt = now.AddDays(-5), CurrentReleasedAt = now.AddDays(-5) });

        var cov = new CoverageReport { ComponentVersionId = cvId, ToolName = "Coverlet", SequenceCoverage = 93.5, BranchCoverage = 88, CoveredSequences = 935, TotalSequences = 1000, CoveredBranches = 88, TotalBranches = 100, IngestedAt = now };
        db.CoverageReports.Add(cov);
        var mod = new CoverageModule { CoverageReportId = cov.Id, Name = "Clean.Core", SequenceCoverage = 93.5, BranchCoverage = 88, CoveredSequences = 935, TotalSequences = 1000 };
        db.CoverageModules.Add(mod);
        var src = new CoverageSourceFile { CoverageReportId = cov.Id, RelativePath = "src/Clean/Thing.cs", SourceText = "public class Thing { public int X => 1; }\n", LineCount = 1 };
        db.CoverageSourceFiles.Add(src);
        db.CoverageClasses.Add(new CoverageClass { CoverageModuleId = mod.Id, CoverageSourceFileId = src.Id, FullName = "Clean.Thing", SequenceCoverage = 100, BranchCoverage = 100, CoveredSequences = 1, TotalSequences = 1, VisitedLines = [1], UnvisitedLines = [] });

        var tr = new TestRunReport { ComponentVersionId = cvId, ToolName = "dotnet test", TotalCount = 2, PassedCount = 2, DurationMs = 400, StartedAt = now.AddMinutes(-2), CompletedAt = now.AddMinutes(-1), IngestedAt = now };
        db.TestRunReports.Add(tr);
        var suite = new TestSuiteResult { TestRunReportId = tr.Id, AssemblyName = "Clean.Tests", ClassName = "Clean.Tests.ThingTests", TotalCount = 2, PassedCount = 2, DurationMs = 400 };
        db.TestSuiteResults.Add(suite);
        db.TestCaseResults.AddRange(
            new TestCaseResult { TestSuiteResultId = suite.Id, Name = "A", Outcome = TestOutcome.Passed, DurationMs = 1 },
            new TestCaseResult { TestSuiteResultId = suite.Id, Name = "B", Outcome = TestOutcome.Passed, DurationMs = 1 });

        db.QualityGateResults.Add(new QualityGateResult { ComponentVersionId = cvId, Status = "OK", Source = "sonarcloud", ObservedAt = now, IngestedAt = now, ConditionsJson = "[{\"Metric\":\"new_bugs\",\"Op\":\"GT\",\"Threshold\":\"0\",\"Actual\":\"0\",\"Status\":\"OK\"}]", MeasuresJson = "{\"bugs\":\"0\"}" });
        db.ContainerImages.Add(new ContainerImage { ComponentVersionId = cvId, Reference = "ghcr.io/acme/clean:2.0.0", BaseImageReference = "alpine:3.20", BaseImageCreatedAt = now.AddDays(-5), InspectedAt = now });
        await db.SaveChangesAsync();
        return (name, id, sha);
    }

    private static string Sha(string tag, string last) => (tag + new string('0', 31) + last).PadRight(40, '0')[..40];

    private static ProjectGatesConfig AllGates()
    {
        var cfg = new ProjectGatesConfig();
        string[] keys =
        [
            GateKeys.RiskScoreRegression, GateKeys.AnyCves, GateKeys.CriticalCves, GateKeys.HighCves, GateKeys.KevExposure,
            GateKeys.CriticalSast, GateKeys.CriticalIac, GateKeys.CriticalDast, GateKeys.HighSast, GateKeys.HighDast,
            GateKeys.VerifiedSecrets, GateKeys.DeniedLicenses, GateKeys.UnauthorizedComponent, GateKeys.BaseImageAge,
            GateKeys.TestFailures, GateKeys.CoverageRegression, GateKeys.CoverageFloor, GateKeys.SbomAge, GateKeys.PoamPastDue,
            GateKeys.QualityGate, GateKeys.AnalysisCoverage, GateKeys.BranchProtection, GateKeys.PrReviewsRequired,
            GateKeys.SignedCommits, GateKeys.OrgTwoFactor, GateKeys.Codeowners, GateKeys.NoUnmapped, GateKeys.AdrConformance,
        ];
        foreach (var k in keys)
            cfg.Gates[k] = new GateConfig { Enabled = true, Threshold = k switch { GateKeys.CoverageFloor => 80, GateKeys.BaseImageAge => 30, GateKeys.SbomAge => 30, _ => 0 } };
        return cfg;
    }

    private static Finding F(Guid cv, ScannerKind s, string rule, Severity sev, string title, string? file, int? line,
        string? sub = null, string? snippet = null, FindingStatus status = FindingStatus.Open, string? desc = null, DateTimeOffset? seen = null) =>
        new()
        {
            ComponentVersionId = cv, Hash = Guid.NewGuid().ToString("N"), Scanner = s, RuleId = rule, Severity = sev, Title = title,
            FilePath = file, Line = line, SubCategory = sub, Snippet = snippet, Status = status, Description = desc ?? title + " description",
            FirstSeen = seen ?? DateTimeOffset.UtcNow.AddDays(-2),
        };

    public const string FileA = "src/Api/Controllers/UserController.cs";
    public const string FileB = "src/Api/Services/PaymentService.cs";
    public const string FileC = "src/Web/app/main.ts";
    public const string FileD = "infra/main.tf";

    /// <summary>Seed one build. level 0 = sparse (old), 1 = mid, 2 = full (newest).</summary>
    private static async Task<List<Finding>> SeedBuildAsync(FindingsDbContext db, ComponentVersion cv, string tag, DateTimeOffset at, int level, string nameSuffix = "")
    {
        var findings = new List<Finding>();
        var cvId = cv.Id;
        var full = level >= 2;

        // ---- findings of every flavour ----
        findings.Add(F(cvId, ScannerKind.OpenGrep, "csharp.sql-injection", Severity.High, "SQL injection in user lookup", FileA, 42, "vulnerability", "var q = \"select * from u where id=\" + id;"));
        findings.Add(F(cvId, ScannerKind.Roslyn, "S2068", Severity.Critical, "Hard-coded credential", FileA, 77));
        findings.Add(F(cvId, ScannerKind.CodeQL, "cs/path-injection", Severity.Medium, "Path injection", FileB, 12));
        findings.Add(F(cvId, ScannerKind.ESLint, "no-eval", Severity.Low, "eval is evil", FileC, 5));
        findings.Add(F(cvId, ScannerKind.ReSharper, "RS0001", Severity.Info, "Naming nit", FileB, 99));
        findings.Add(F(cvId, ScannerKind.TruffleHog, "aws-key", Severity.Critical, "Verified AWS key", "config/secrets.env", 3, "verified"));
        findings.Add(F(cvId, ScannerKind.Trivy, "AVD-AWS-0107", Severity.High, "Open security group", FileD, 10, "misconfiguration"));
        findings.Add(F(cvId, ScannerKind.Trivy, "AVD-AWS-0088", Severity.Critical, "Public bucket", FileD, 22, "misconfiguration"));
        findings.Add(F(cvId, ScannerKind.Trivy, "generic-secret", Severity.High, "Secret in image layer", "Dockerfile", 7, "secret"));
        findings.Add(F(cvId, ScannerKind.Checkov, "CKV_AWS_1", Severity.Medium, "Unencrypted volume", FileD, 30, "misconfiguration"));
        findings.Add(F(cvId, ScannerKind.Spectral, "oas3-valid", Severity.Medium, "OpenAPI invalid", "openapi.yaml", 11));
        findings.Add(F(cvId, ScannerKind.NetArchTest, "layering", Severity.Low, "Layer violation", FileB, 1));
        findings.Add(F(cvId, ScannerKind.Stryker, "mutant-survived", Severity.Low, "Mutant survived", FileB, 50));
        findings.Add(F(cvId, ScannerKind.SonarQube, "csharpsquid:S1135", Severity.Medium, "Sonar bug", FileA, 60, "bug"));
        findings.Add(F(cvId, ScannerKind.SonarQube, "csharpsquid:S125", Severity.Low, "Sonar smell", FileB, 61, "code_smell"));
        findings.Add(F(cvId, ScannerKind.SonarQube, "csharpsquid:S5122", Severity.High, "Sonar hotspot", FileA, 62, "security_hotspot"));
        findings.Add(F(cvId, ScannerKind.OpenGrep, "csharp.fixed", Severity.High, "Already fixed issue", FileA, 10, null, null, FindingStatus.Fixed));
        findings.Add(F(cvId, ScannerKind.OpenGrep, "csharp.accepted", Severity.High, "Accepted risk", FileB, 10, null, null, FindingStatus.Accepted));

        if (full || level == 1)
        {
            findings.Add(F(cvId, ScannerKind.Zap, "10202", Severity.High, "Absence of anti-CSRF tokens", "https://app.example.test/api/users?id=1", null, null, "GET /api/users?id=1 HTTP/1.1\nHost: app.example.test\n\n\nHTTP/1.1 200 OK\nContent-Type: application/json"));
            findings.Add(F(cvId, ScannerKind.Zap, "40012", Severity.Critical, "Cross site scripting", "https://app.example.test/search?q=x", null, null, "GET /search?q=x HTTP/1.1\n\n\nHTTP/1.1 200 OK"));
            findings.Add(F(cvId, ScannerKind.Zap, "10038", Severity.Low, "CSP header missing", "https://app.example.test/", null));
            findings.Add(F(cvId, ScannerKind.Nuclei, "tech-detect", Severity.Info, "Technology detected", "https://staging.example.test/api/health", null));
            findings.Add(F(cvId, ScannerKind.Nuclei, "cve-2021-xx", Severity.High, "Template hit", "https://app.example.test/api/users?id=2", null));
            findings.Add(F(cvId, ScannerKind.AxeCore, "color-contrast", Severity.Medium, "Insufficient colour contrast", "https://app.example.test/login", null, null, "<button class='x'>"));
            findings.Add(F(cvId, ScannerKind.AxeCore, "image-alt", Severity.High, "Image missing alt text", "https://app.example.test/login", null));
            findings.Add(F(cvId, ScannerKind.AxeCore, "label", Severity.Critical, "Form element missing label", "https://app.example.test/signup", null));
            // a near-duplicate host so the DAST duplicate-host callout can fire
            findings.Add(F(cvId, ScannerKind.Zap, "10202", Severity.Medium, "Absence of anti-CSRF tokens", "https://app-example-test.example.test/api/users?id=1", null));
        }

        db.Findings.AddRange(findings);

        // ---- scan receipts ----
        void R(ScannerKind k, ScanRunStatus st, int count, string tool, string ver, string? notes = null, string? gate = null, string? gateDetails = null) =>
            db.ScanRunReceipts.Add(new ScanRunReceipt
            {
                ComponentVersionId = cvId, Scanner = k, Status = st, StartedAt = at.AddMinutes(-5), CompletedAt = at, FindingsCount = count,
                ToolName = tool, ToolVersion = ver, Notes = notes, GateStatus = gate, GateDetails = gateDetails,
            });
        R(ScannerKind.OpenGrep, ScanRunStatus.Succeeded, 3, "OpenGrep OSS", "1.22.0", "1059 rules / 258 applicable, scanned 77 files");
        R(ScannerKind.Roslyn, ScanRunStatus.Succeeded, 1, "Roslyn analyzers", "4.9");
        R(ScannerKind.TruffleHog, ScanRunStatus.Succeeded, 1, "TruffleHog", "3.80");
        R(ScannerKind.Trivy, ScanRunStatus.Succeeded, 4, "Trivy", "0.50");
        R(ScannerKind.Checkov, ScanRunStatus.Failed, 0, "Checkov", "3.0", "crashed");
        R(ScannerKind.Kics, ScanRunStatus.Skipped, 0, "KICS", "2.0", "no iac");
        R(ScannerKind.CodeQL, ScanRunStatus.Succeeded, 1, "CodeQL", "2.17");
        R(ScannerKind.Coverlet, ScanRunStatus.Succeeded, 0, "Coverlet", "6.0");
        R(ScannerKind.Syft, ScanRunStatus.Succeeded, 0, "Syft", "1.0");
        R(ScannerKind.Spectral, ScanRunStatus.Succeeded, 1, "Spectral", "6.0");
        R(ScannerKind.SonarQube, ScanRunStatus.Succeeded, 3, "SonarCloud", "10", null, "OK", "all conditions pass");
        if (level >= 1)
        {
            R(ScannerKind.OsvScanner, ScanRunStatus.Succeeded, 4, "OSV-Scanner", "1.8", "db=osv-db/v1.2; db_built=2026-09-29T00:00:00Z");
            R(ScannerKind.Zap, ScanRunStatus.Succeeded, 4, "ZAP", "2.15");
            R(ScannerKind.AxeCore, ScanRunStatus.Succeeded, 3, "axe-core", "4.9");
        }
        if (full) R(ScannerKind.Grype, ScanRunStatus.Succeeded, 4, "Grype", "0.80", "db=grype-db/v6.1.9; db_built=2026-09-28T00:00:00Z");

        // ---- SBOM ----
        var snap = new SbomSnapshot
        {
            ComponentVersionId = cvId, SerialNumber = "urn:uuid:" + Guid.NewGuid(), SpecVersion = "1.5", ToolName = "syft", ToolVersion = "1.0",
            IngestedAt = at, ProvenanceType = full ? "slsa" : null, ProvenanceUploadedAt = full ? at : null,
            ProvenanceVerified = full, ProvenanceVerifiedAt = full ? at : null, ProvenanceVerificationMethod = full ? "cosign" : null,
        };
        db.SbomSnapshots.Add(snap);
        SbomComponent C(string name, string ver, string? lic, string? latest = null, int? currentAgeDays = null, int? latestAgeDays = null, bool dev = false) =>
            new()
            {
                SbomSnapshotId = snap.Id, Purl = $"pkg:nuget/{name}{nameSuffix}@{ver}", Name = name + nameSuffix, Version = ver, Kind = "library", License = lic,
                DevDependency = dev, LatestVersion = latest, LatestReleasedAt = latestAgeDays is null ? null : at.AddDays(-latestAgeDays.Value),
                CurrentReleasedAt = currentAgeDays is null ? null : at.AddDays(-currentAgeDays.Value), EnrichedAt = latest is null ? null : at,
            };
        var cNewtonsoft = C("Newtonsoft.Json", "12.0.1", "MIT", "13.0.3", 2000, 100);
        var cLog4 = C("log4net", "2.0.8", "Apache-2.0", "2.0.17", 1500, 50);
        var cGpl = C("GplLib", "1.0.0", "GPL-3.0-only", "1.0.0", 100, 100);
        var cLgpl = C("LgplLib", "2.1.0", "LGPL-2.1-only", "2.2.0", 400, 100);
        var cAgpl = C("AgplLib", "3.0.0", "AGPL-3.0-only");
        var cUnk = C("MysteryLib", "0.9.0", null);
        var cWeird = C("WeirdLib", "0.1.0", "Custom-Proprietary-1.0");
        var cDev = C("xunit", "2.9.0", "Apache-2.0", "2.9.2", 300, 100, dev: true);
        var cFresh = C("Fresh.Lib", "5.0.0", "MIT", "5.0.0", 10, 10);
        var cDeep = C("Deep.Transitive", "1.0.0", "BSD-3-Clause", "1.4.0", 900, 60);
        var cRoot = C("Acme.Root", "1.0.0", "MIT");
        var cMid = C("Acme.Mid", "1.0.0", "MIT");
        var comps = new[] { cNewtonsoft, cLog4, cGpl, cLgpl, cAgpl, cUnk, cWeird, cDev, cFresh, cDeep, cRoot, cMid };
        db.SbomComponents.AddRange(comps);
        db.SbomDependencies.AddRange(
            new SbomDependency { SbomSnapshotId = snap.Id, ParentComponentId = cRoot.Id, ChildComponentId = cMid.Id },
            new SbomDependency { SbomSnapshotId = snap.Id, ParentComponentId = cMid.Id, ChildComponentId = cDeep.Id },
            new SbomDependency { SbomSnapshotId = snap.Id, ParentComponentId = cRoot.Id, ChildComponentId = cNewtonsoft.Id },
            new SbomDependency { SbomSnapshotId = snap.Id, ParentComponentId = cMid.Id, ChildComponentId = cLog4.Id });

        Vulnerability V(SbomComponent c, string id, Severity sev, double? cvss, string? fixedIn, ScannerKind src = ScannerKind.OsvScanner) =>
            new()
            {
                SbomComponentId = c.Id, AdvisoryId = id, Severity = sev, Title = id + " title", Description = id + " desc", FixedInVersion = fixedIn,
                ReferenceUrl = "https://example.test/adv/" + id, CvssScore = cvss, CvssVector = cvss is null ? null : "CVSS:3.1/AV:N", Source = src,
            };
        db.Vulnerabilities.AddRange(
            V(cNewtonsoft, "GHSA-5crp-9r3c-p9vr", Severity.High, 7.5, "13.0.1"),
            V(cLog4, "CVE-2018-1285", Severity.Critical, 9.8, null, ScannerKind.Grype),
            V(cLog4, level >= 2 ? KevCve(tag) : "CVE-2099-0001", Severity.Critical, 10.0, "2.0.17"),
            V(cDeep, "GHSA-aaaa-bbbb-cccc", Severity.Medium, null, "1.1.0"),
            V(cLgpl, "CVE-2022-9999", Severity.Low, 3.1, "2.2.0"));

        // ---- coverage ----
        var cov = new CoverageReport
        {
            ComponentVersionId = cvId, ToolName = "Coverlet", ToolVersion = "6.0", SequenceCoverage = level == 0 ? 40 : 71.5, BranchCoverage = level == 0 ? 30 : 55.2,
            CoveredSequences = 715, TotalSequences = 1000, CoveredBranches = 276, TotalBranches = 500, IngestedAt = at,
        };
        db.CoverageReports.Add(cov);
        var mod = new CoverageModule { CoverageReportId = cov.Id, Name = "Acme.Api", SequenceCoverage = 71.5, BranchCoverage = 55.2, CoveredSequences = 715, TotalSequences = 1000 };
        var mod2 = new CoverageModule { CoverageReportId = cov.Id, Name = "Acme.Core", SequenceCoverage = 95, BranchCoverage = 90, CoveredSequences = 95, TotalSequences = 100 };
        db.CoverageModules.AddRange(mod, mod2);
        var srcA = new CoverageSourceFile { CoverageReportId = cov.Id, RelativePath = FileA, AbsolutePath = "C:/x/" + FileA, SourceText = "using System;\nnamespace Acme.Api.Controllers;\n// comment\npublic class UserController\n{\n    public int Get(int id)\n    {\n        if (id > 0) { return id; }\n        return 0;\n    }\n}\n", LineCount = 12 };
        var srcB = new CoverageSourceFile { CoverageReportId = cov.Id, RelativePath = FileB, SourceText = "public class PaymentService { public void Pay() { } }\n", LineCount = 1 };
        var srcC = new CoverageSourceFile { CoverageReportId = cov.Id, RelativePath = "src/Core/Calc.cs", SourceText = "public class Calc { public int Add(int a,int b)=>a+b; }\n", LineCount = 1 };
        db.CoverageSourceFiles.AddRange(srcA, srcB, srcC);
        db.CoverageClasses.AddRange(
            new CoverageClass { CoverageModuleId = mod.Id, CoverageSourceFileId = srcA.Id, FullName = "Acme.Api.Controllers.UserController", SequenceCoverage = 60, BranchCoverage = 50, CoveredSequences = 6, TotalSequences = 10, CoveredBranches = 1, TotalBranches = 2, VisitedLines = [6, 7, 8], UnvisitedLines = [9] },
            new CoverageClass { CoverageModuleId = mod.Id, CoverageSourceFileId = srcB.Id, FullName = "Acme.Api.Services.PaymentService", SequenceCoverage = 0, BranchCoverage = 0, CoveredSequences = 0, TotalSequences = 4, CoveredBranches = 0, TotalBranches = 0, VisitedLines = [], UnvisitedLines = [1] },
            new CoverageClass { CoverageModuleId = mod2.Id, CoverageSourceFileId = srcC.Id, FullName = "Acme.Core.Calc", SequenceCoverage = 100, BranchCoverage = 100, CoveredSequences = 1, TotalSequences = 1, CoveredBranches = 0, TotalBranches = 0, VisitedLines = [1], UnvisitedLines = [] });

        // ---- tests ----
        var tr = new TestRunReport
        {
            ComponentVersionId = cvId, ToolName = "dotnet test (trx)", ToolVersion = "10.0", TotalCount = 7, PassedCount = 4, FailedCount = 2, SkippedCount = 1,
            DurationMs = 75_000, StartedAt = at.AddMinutes(-3), CompletedAt = at.AddMinutes(-2), IngestedAt = at,
        };
        db.TestRunReports.Add(tr);
        var s1 = new TestSuiteResult { TestRunReportId = tr.Id, AssemblyName = "Acme.Api.Tests", ClassName = "Acme.Api.Tests.UserTests", TotalCount = 4, PassedCount = 2, FailedCount = 1, SkippedCount = 1, DurationMs = 1200 };
        var s2 = new TestSuiteResult { TestRunReportId = tr.Id, AssemblyName = "Acme.Core.Tests", ClassName = "Acme.Core.Tests.CalcTests", TotalCount = 3, PassedCount = 2, FailedCount = 1, DurationMs = 800 };
        db.TestSuiteResults.AddRange(s1, s2);
        db.TestCaseResults.AddRange(
            new TestCaseResult { TestSuiteResultId = s1.Id, Name = "Get_returns_user", Outcome = TestOutcome.Passed, DurationMs = 10 },
            new TestCaseResult { TestSuiteResultId = s1.Id, Name = "Get_rejects_negative", Outcome = TestOutcome.Passed, DurationMs = 12 },
            new TestCaseResult { TestSuiteResultId = s1.Id, Name = "Get_handles_null", Outcome = TestOutcome.Failed, DurationMs = 30, ErrorMessage = "Expected 1 but was 2", ErrorStackTrace = "at UserTests.Get_handles_null()" },
            new TestCaseResult { TestSuiteResultId = s1.Id, Name = "Slow_integration", Outcome = TestOutcome.Skipped, DurationMs = 0, ErrorMessage = "needs db" },
            new TestCaseResult { TestSuiteResultId = s2.Id, Name = "Add_works", Outcome = TestOutcome.Passed, DurationMs = 2 },
            new TestCaseResult { TestSuiteResultId = s2.Id, Name = "Add_overflow", Outcome = TestOutcome.Failed, DurationMs = 3, ErrorMessage = "overflow" },
            new TestCaseResult { TestSuiteResultId = s2.Id, Name = "Add_zero", Outcome = TestOutcome.Passed, DurationMs = 1 });
        db.RawReportArtifacts.Add(new RawReportArtifact
        {
            ComponentVersionId = cvId, Kind = RawArtifactKind.TestResults, Format = "trx", FileName = "results.trx", SlotKey = "results.trx",
            Sha256 = new string('a', 64), SizeBytes = 2048, CompressedBytes = [1, 2, 3], ToolName = "dotnet", IngestedAt = at,
        });

        // ---- quality gate + analysis coverage ----
        db.QualityGateResults.Add(new QualityGateResult
        {
            ComponentVersionId = cvId, Status = level == 1 ? "OK" : "ERROR", Source = "sonarcloud", AnalysisId = "AX" + tag, ObservedAt = at, IngestedAt = at,
            ConditionsJson = "[{\"Metric\":\"new_coverage\",\"Op\":\"LT\",\"Threshold\":\"80\",\"Actual\":\"61.2\",\"Status\":\"ERROR\"},{\"Metric\":\"new_bugs\",\"Op\":\"GT\",\"Threshold\":\"0\",\"Actual\":\"0\",\"Status\":\"OK\"}]",
            MeasuresJson = "{\"coverage\":\"71.5\",\"bugs\":\"2\",\"code_smells\":\"14\"}",
        });
        var acr = new AnalysisCoverageReport { ComponentVersionId = cvId, ObservedAt = at, IngestedAt = at, GapLanguages = "kotlin, ruby", Excludes = "**/bin/**, **/obj/**" };
        db.AnalysisCoverageReports.Add(acr);
        db.AnalysisCoverageLanguages.AddRange(
            new AnalysisCoverageLanguage { AnalysisCoverageReportId = acr.Id, Language = "csharp", FilesTotal = 100, FilesAnalyzed = 100, LinesTotal = 10000, LinesAnalyzed = 10000, AnalyzedBy = "roslyn", PercentAnalyzed = 100 },
            new AnalysisCoverageLanguage { AnalysisCoverageReportId = acr.Id, Language = "kotlin", FilesTotal = 20, FilesAnalyzed = 0, LinesTotal = 3000, LinesAnalyzed = 0, PercentAnalyzed = 0, UnanalyzedSample = "a.kt,b.kt" });

        // ---- container images ----
        db.ContainerImages.Add(
            new ContainerImage { ComponentVersionId = cvId, Reference = "ghcr.io/acme/app:" + cv.VersionString, Digest = "sha256:" + new string('b', 64), CreatedAt = at, OsFamily = "debian", OsVersion = "12", SizeBytes = 120_000_000, BaseImageReference = "mcr.microsoft.com/dotnet/aspnet:8.0", BaseImageDigest = "sha256:" + new string('c', 64), BaseImageCreatedAt = at.AddDays(-120), InspectedAt = at });

        await db.SaveChangesAsync();
        return findings;
    }

    private static async Task<Guid[]> SeedPoamAsync(FindingsDbContext db, Guid projectId, List<Finding> findings, DateTimeOffset now)
    {
        var linked = findings.Take(2).Select(f => f.Id).ToList();
        PoamItem P(string title, PoamStatus st, Severity sev, int? dueInDays, PoamSource src = PoamSource.Finding, string? sref = null) =>
            new()
            {
                ProjectId = projectId, Title = title, WeaknessDescription = title + " weakness", MitigationPlan = "Fix it", ResourcesRequired = "2 dev days",
                Severity = sev, Status = st, ScheduledCompletionDate = dueInDays is null ? null : now.AddDays(dueInDays.Value),
                ActualCompletionDate = st == PoamStatus.Completed ? now.AddDays(-1) : null, ClosedAt = st is PoamStatus.Completed or PoamStatus.Cancelled or PoamStatus.RiskAccepted ? now.AddDays(-1) : null,
                LinkedFindingIds = st == PoamStatus.Open ? linked : [], ReferenceUrl = "https://example.test/ticket/1", AuthorUserId = AdminId,
                SourceKind = src, SourceRef = sref, MandatePackVersion = src == PoamSource.OperationalMandate ? "v1" : null,
            };
        var items = new[]
        {
            P("PastDue SQLi remediation", PoamStatus.Open, Severity.High, -20),
            P("In progress rotate keys", PoamStatus.InProgress, Severity.Critical, 15),
            P("Completed patch log4net", PoamStatus.Completed, Severity.Medium, -5),
            P("Risk accepted legacy lib", PoamStatus.RiskAccepted, Severity.Low, null),
            P("Cancelled dup", PoamStatus.Cancelled, Severity.Info, 30),
            P("Mandate operational", PoamStatus.Open, Severity.Medium, 5, PoamSource.OperationalMandate, "MAN-1"),
            P("ZT contradiction", PoamStatus.Open, Severity.High, 45, PoamSource.ZtContradiction, "ZT-1"),
            P("Supply chain mandate", PoamStatus.InProgress, Severity.Medium, 100, PoamSource.SupplyChainMandate, "SC-1"),
        };
        db.PoamItems.AddRange(items);
        await db.SaveChangesAsync();
        return items.Select(i => i.Id).ToArray();
    }

    private static void SeedVexAndSuppressions(FindingsDbContext db, Guid projectId, Guid clientId, List<Finding> findings, DateTimeOffset now)
    {
        VexStatement V(string purl, string? ver, string adv, VexStatementStatus st, VexJustification? j, string? impact, DateTimeOffset? retired = null) =>
            new()
            {
                ProjectId = projectId, Purl = purl, ComponentVersion = ver, AdvisoryId = adv, Status = st, Justification = j, ImpactStatement = impact,
                ResponseReferenceUrl = "https://example.test/vex/" + adv, AuthorUserId = AdminId, RetiredAt = retired, CreatedAt = now.AddDays(-4), UpdatedAt = now.AddDays(-2),
            };
        db.VexStatements.AddRange(
            V("pkg:nuget/Newtonsoft.Json", "12.0.1", "GHSA-5crp-9r3c-p9vr", VexStatementStatus.NotAffected, VexJustification.VulnerableCodeNotInExecutePath, "Not reachable"),
            V("pkg:nuget/log4net", null, "CVE-2018-1285", VexStatementStatus.UnderInvestigation, null, null),
            V("pkg:nuget/Deep.Transitive", "1.0.0", "GHSA-aaaa-bbbb-cccc", VexStatementStatus.Affected, null, "Plan upgrade"),
            V("pkg:nuget/LgplLib", "2.1.0", "CVE-2022-9999", VexStatementStatus.Fixed, null, "Upgraded"),
            V("pkg:nuget/xunit", "2.9.0", VexStatement.StalenessAdvisoryId, VexStatementStatus.NotAffected, VexJustification.BuildTimeOnly, "Test only"),
            V("pkg:nuget/Retired.Lib", null, "CVE-2001-0001", VexStatementStatus.NotAffected, VexJustification.ComponentNotPresent, "Gone", now.AddDays(-1)),
            V("pkg:nuget/Accepted.Lib", null, "CVE-2002-0002", VexStatementStatus.NotAffected, VexJustification.AcceptedRisk, "Accepted"));

        db.Suppressions.AddRange(
            new Suppression { Scope = SuppressionScope.SingleFinding, FindingId = findings[0].Id, ProjectId = projectId, ClientId = clientId, CreatedByUserId = AdminId, CreatedByRole = ProjectRole.InfoSecOfficer, Reason = "False positive", ExpiresAt = now.AddDays(30) },
            new Suppression { Scope = SuppressionScope.RuleOnFile, RuleId = "no-eval", FilePath = FileC, ProjectId = projectId, ClientId = clientId, CreatedByUserId = AdminId, CreatedByRole = ProjectRole.LeadDev, Reason = "Legacy" },
            new Suppression { Scope = SuppressionScope.RuleEverywhere, RuleId = "RS0001", ClientId = clientId, ProjectId = projectId, CreatedByUserId = AdminId, CreatedByRole = ProjectRole.Architect, Reason = "Style", ExpiresAt = now.AddDays(-2) });
    }

    private static void SeedPosture(FindingsDbContext db, Guid projectId, DateTimeOffset now)
    {
        var ids = new[] { GateKeys.BranchProtection, GateKeys.PrReviewsRequired, GateKeys.SignedCommits, GateKeys.OrgTwoFactor, GateKeys.Codeowners };
        var st = new[] { PostureStatus.Pass, PostureStatus.Fail, PostureStatus.Unknown, PostureStatus.NotApplicable, PostureStatus.Pass };
        for (var i = 0; i < ids.Length; i++)
            db.PostureObservations.Add(new PostureObservation { ProjectId = projectId, CheckId = ids[i], Status = st[i], Detail = "detail " + i, Source = "github", ObservedAt = now.AddHours(-1) });
    }

    private static void SeedConformance(FindingsDbContext db, Guid projectId, Guid cvId, DateTimeOffset now)
    {
        db.ConformanceRules.AddRange(
            new ConformanceRule { ProjectId = projectId, AdrRef = "ADR 0002", RuleId = "auth-boundary-single", Intent = "Single auth boundary", Method = ConformanceMethod.Deterministic, CheckSpec = "grep", ReviewStatus = ReviewStatus.Reviewed, ControlRefs = ["AC-3"], RulesSha = "r1" },
            new ConformanceRule { ProjectId = projectId, AdrRef = "ADR 0003", RuleId = "no-direct-db", Intent = "No direct DB", Method = ConformanceMethod.Semantic, ReviewStatus = ReviewStatus.Draft, RulesSha = "r2" });
        ConformanceFinding Cf(string adr, string rule, string claim, ConformanceVerdict v, ConformanceMethod m, bool disp = false, VerifyOutcome vo = VerifyOutcome.NotRun) =>
            new()
            {
                ComponentVersionId = cvId, AdrRef = adr, RuleId = rule, Claim = claim, Verdict = v, Method = m, AdrQuote = "quote", CodeEvidence = "evidence",
                Location = "src/x.cs:10", CommitSha = "abc", RulesSha = "r1", ModelId = "model", VerifyVerdict = vo, ControlRefs = ["AC-3", "SC-7"],
                ZtPillar = "Applications", ZtFunction = "Auth", ZtStage = 2, Dispositioned = disp, DispositionJustification = disp ? "Accepted" : null,
                DispositionedByLogin = disp ? "scott" : null, EvaluatedAt = now,
            };
        db.ConformanceFindings.AddRange(
            Cf("ADR 0002", "auth-boundary-single", "Single auth boundary holds", ConformanceVerdict.Pass, ConformanceMethod.Deterministic),
            Cf("ADR 0002", "auth-boundary-single", "Second boundary found", ConformanceVerdict.Fail, ConformanceMethod.Deterministic),
            Cf("ADR 0003", "no-direct-db", "Direct DB access in controller", ConformanceVerdict.Fail, ConformanceMethod.Semantic, false, VerifyOutcome.Confirmed),
            Cf("ADR 0003", "no-direct-db", "Possibly direct DB", ConformanceVerdict.Unknown, ConformanceMethod.Semantic),
            Cf("ADR 0004", "gating", "Accepted failing", ConformanceVerdict.Fail, ConformanceMethod.Verify, true, VerifyOutcome.Disputed));
    }

    private sealed class MemXmlRepository : IXmlRepository
    {
        private readonly List<XElement> _elements = [];
        public IReadOnlyCollection<XElement> GetAllElements() { lock (_elements) return _elements.ToArray(); }
        public void StoreElement(XElement element, string friendlyName) { lock (_elements) _elements.Add(element); }
    }

    private sealed class PageBAuthHandler(IOptionsMonitor<AuthenticationSchemeOptions> o, ILoggerFactory l, UrlEncoder e)
        : AuthenticationHandler<AuthenticationSchemeOptions>(o, l, e)
    {
        public const string SchemeName = "PageBTest";

        protected override Task<AuthenticateResult> HandleAuthenticateAsync()
        {
            var who = Request.Headers.TryGetValue(UserHeader, out var v) ? v.ToString() : Admin;
            var (id, login, isAdmin) = who switch
            {
                Lead => (LeadId, "pageb-lead", false),
                Viewer => (ViewerId, "pageb-viewer", false),
                Iso => (IsoId, "pageb-iso", false),
                _ => (AdminId, "pageb-admin", true),
            };
            var identity = new ClaimsIdentity(
            [
                new Claim(ClaimTypes.Name, login),
                new Claim(ClaimTypes.NameIdentifier, id.ToString()),
                new Claim(AuthExtensions.TampUserIdClaim, id.ToString()),
                new Claim(AuthExtensions.TampIsAdminClaim, isAdmin.ToString()),
            ], SchemeName);
            return Task.FromResult(AuthenticateResult.Success(new AuthenticationTicket(new ClaimsPrincipal(identity), SchemeName)));
        }
    }
}
