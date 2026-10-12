using System.Text.Json;
using Microsoft.Extensions.DependencyInjection;
using Tamp.Findings.Application.Authorization;
using Tamp.Findings.Application.Mcp;
using Tamp.Findings.Domain.Entities;
using Tamp.Findings.Domain.Values;
using Tamp.Findings.Mcp;

namespace Tamp.Findings.Integration.Tests;

/// <summary>
/// The compliance and quality tools (TFND-238 / TFND-239).
///
/// Most of what these assert is about ABSENCE. A project with no POA&amp;M items,
/// no conformance run, no test report and no posture observation is the normal
/// state of a new project, and every one of those absences has a wrong reading
/// that an agent will reach for unprompted — "nothing is wrong", "it conforms",
/// "the build passed", "the checks pass". The tools have to say the other thing,
/// so these tests check that they do.
/// </summary>
[Collection(DatabaseCollection.Name)]
public class ApiBMcpComplianceToolsTests
{
    private readonly DatabaseFixture _fx;
    public ApiBMcpComplianceToolsTests(DatabaseFixture fx) => _fx = fx;

    private sealed record World(
        Guid ClientId, Guid ProjectId, Guid ForeignProjectId, Guid PoamId, string CommitSha);

    // The one package the fixture leaves unclassifiable. A field rather than an
    // inline array so the expectation is allocated once and named where it is
    // seeded.
    private static readonly string[] ExpectedUnresolvedPurls = ["pkg:nuget/Mystery@2"];

    private async Task<World> SeedAsync()
    {
        var s = ApiBSupport.Suffix();
        using var scope = _fx.Scope();
        var db = _fx.Db(scope);

        var client = new Client { Name = $"apib-comp-{s}" };
        var otherClient = new Client { Name = $"apib-comp-o-{s}" };
        db.Clients.AddRange(client, otherClient);

        var project = new Project { ClientId = client.Id, Name = $"p-{s}" };
        var foreign = new Project { ClientId = otherClient.Id, Name = $"f-{s}" };
        db.Projects.AddRange(project, foreign);

        var sha = $"{s}head";
        var build = new ComponentVersion
        {
            ProjectId = project.Id, VersionString = "1.0.0", CommitSha = sha, BranchName = "main",
        };
        db.ComponentVersions.Add(build);

        // Tests: deliberately a RED build. A green fixture would let the "a fix
        // lands on top of this" note go untested, and that note is the reason
        // an agent should read this before changing anything.
        db.TestRunReports.Add(new TestRunReport
        {
            ComponentVersionId = build.Id, ToolName = "dotnet test (trx)",
            TotalCount = 10, PassedCount = 8, FailedCount = 2, SkippedCount = 0,
            StartedAt = DateTimeOffset.UtcNow.AddMinutes(-5), CompletedAt = DateTimeOffset.UtcNow,
        });

        db.CoverageReports.Add(new CoverageReport
        {
            ComponentVersionId = build.Id, ToolName = "Coverlet",
            SequenceCoverage = 72.5, BranchCoverage = 61.0,
            CoveredSequences = 290, TotalSequences = 400,
        });

        // SBOM with one unclassifiable license, so the worklist has a row.
        var snap = new SbomSnapshot { ComponentVersionId = build.Id, ToolName = "syft" };
        db.SbomSnapshots.Add(snap);
        db.SbomComponents.AddRange(
            new SbomComponent
            {
                SbomSnapshotId = snap.Id, Purl = "pkg:nuget/Known@1", Name = "Known",
                Version = "1", License = "MIT",
            },
            new SbomComponent
            {
                SbomSnapshotId = snap.Id, Purl = "pkg:nuget/Mystery@2", Name = "Mystery",
                Version = "2", License = null,
            });

        // The board's "owner" is the author's display name, not a field on the
        // item — so the author has to exist for the column to say anything.
        var author = new User
        {
            Login = $"apib-comp-u-{s}", DisplayName = "platform-team", IsApproved = true,
        };
        db.Users.Add(author);

        var poam = new PoamItem
        {
            ProjectId = project.Id,
            AuthorUserId = author.Id,
            Title = $"Upgrade the vulnerable parser ({s})",
            WeaknessDescription = "Transitive dependency carries a known CVE",
            Severity = Severity.High,
            Status = PoamStatus.Open,
            // Past due on purpose: an item whose date has gone is a different
            // state from one in progress, and the tool is supposed to say so.
            ScheduledCompletionDate = DateTimeOffset.UtcNow.AddDays(-7),
        };
        db.PoamItems.Add(poam);

        // One row per check — (ProjectId, CheckId) is unique, so an observation
        // is an upsert and this table is current state rather than a history.
        db.PostureObservations.AddRange(
            new PostureObservation
            {
                ProjectId = project.Id, CheckId = "branch-protection",
                Status = PostureStatus.Pass, Detail = "main is protected",
                Source = "github", ObservedAt = DateTimeOffset.UtcNow,
            },
            new PostureObservation
            {
                ProjectId = project.Id, CheckId = "require-reviews",
                Status = PostureStatus.Fail, Detail = "no review required on main",
                Source = "github", ObservedAt = DateTimeOffset.UtcNow,
            });

        await db.SaveChangesAsync();

        return new World(client.Id, project.Id, foreign.Id, poam.Id, sha);
    }

    private static AgentIdentity Agent(ScopeTarget scope) =>
        new(Guid.NewGuid(), "agent", Principal.For(Guid.Empty, "agent:test", false, []), scope);

    // Cached rather than constructed per call: JsonSerializerOptions builds and
    // caches reflection metadata on first use, so a fresh instance per
    // serialization throws that away every time.
    private static readonly JsonSerializerOptions Web = new(JsonSerializerDefaults.Web);

    private static JsonElement Json(object o) => JsonSerializer.SerializeToElement(o, Web);

    private static (AgentReadService reads, AgentContext ctx) Services(IServiceScope scope, AgentIdentity identity)
    {
        var ctx = new AgentContext();
        ctx.Attach(identity);
        return (scope.ServiceProvider.GetRequiredService<AgentReadService>(), ctx);
    }

    // ---- get_controls -------------------------------------------------------

    [SkippableFact]
    public async Task get_controls_without_a_framework_says_so_rather_than_reporting_zero_controls()
    {
        Skip.IfNot(_fx.Available);

        // A project whose client has no framework has no in-scope controls. The
        // wrong reading is "nothing to prove"; the right one is "nobody has said
        // what this project has to prove".
        var w = await SeedAsync();
        using var scope = _fx.Scope();
        var (reads, ctx) = Services(scope, Agent(ScopeTarget.Project(w.ClientId, w.ProjectId)));

        var coverage = Json(await FindingsTools.GetControlsAsync(reads, ctx, w.ProjectId));

        Assert.False(coverage.TryGetProperty("inScope", out _));
        Assert.Contains("no compliance framework", coverage.GetProperty("note").GetString(), StringComparison.Ordinal);
    }

    [SkippableFact]
    public async Task get_controls_refuses_an_unparseable_disposition_rather_than_ignoring_it()
    {
        Skip.IfNot(_fx.Available);

        // Silently dropping the filter would answer a different question and
        // look like a complete answer to the one asked.
        var w = await SeedAsync();
        using var scope = _fx.Scope();
        var (reads, ctx) = Services(scope, Agent(ScopeTarget.Project(w.ClientId, w.ProjectId)));

        var bad = Json(await FindingsTools.GetControlsAsync(reads, ctx, w.ProjectId, disposition: "Gatedd"));

        Assert.Contains("not a disposition", bad.GetProperty("error").GetString(), StringComparison.Ordinal);
    }

    [SkippableFact]
    public async Task get_controls_refuses_a_project_outside_the_token_scope()
    {
        Skip.IfNot(_fx.Available);
        var w = await SeedAsync();
        using var scope = _fx.Scope();
        var (reads, ctx) = Services(scope, Agent(ScopeTarget.Project(w.ClientId, w.ProjectId)));

        var coverage = Json(await FindingsTools.GetControlsAsync(reads, ctx, w.ForeignProjectId));

        Assert.Contains("outside this token", coverage.GetProperty("error").GetString(), StringComparison.Ordinal);
    }

    // ---- list_poams ---------------------------------------------------------

    [SkippableFact]
    public async Task list_poams_returns_the_item_and_marks_it_past_due()
    {
        Skip.IfNot(_fx.Available);
        var w = await SeedAsync();
        using var scope = _fx.Scope();
        var (reads, ctx) = Services(scope, Agent(ScopeTarget.Project(w.ClientId, w.ProjectId)));

        var board = Json(await FindingsTools.ListPoamsAsync(reads, ctx, w.ProjectId));
        var item = board.GetProperty("items")[0];

        Assert.Equal(w.PoamId, item.GetProperty("id").GetGuid());
        Assert.True(item.GetProperty("pastDue").GetBoolean());
        Assert.Equal("platform-team", item.GetProperty("owner").GetString());
        Assert.Equal(1, board.GetProperty("pastDue").GetInt32());
        Assert.Contains("past their scheduled date", board.GetProperty("note").GetString(), StringComparison.Ordinal);
    }

    [SkippableFact]
    public async Task list_poams_on_a_project_with_none_says_findings_are_open_on_their_own_account()
    {
        Skip.IfNot(_fx.Available);

        // "No POA&M items" must not read as "nothing is being tracked, so
        // nothing is wrong".
        var w = await SeedAsync();
        using var scope = _fx.Scope();
        var (reads, ctx) = Services(scope, Agent(ScopeTarget.Client(w.ClientId)));
        var bare = await BareProjectAsync(w.ClientId);

        var board = Json(await FindingsTools.ListPoamsAsync(reads, ctx, bare));

        Assert.Equal(0, board.GetProperty("items").GetArrayLength());
        Assert.Contains("on its own account", board.GetProperty("note").GetString(), StringComparison.Ordinal);
    }

    // ---- get_conformance ----------------------------------------------------

    [SkippableFact]
    public async Task get_conformance_with_no_run_says_nothing_has_been_checked()
    {
        Skip.IfNot(_fx.Available);

        // The reading this exists to prevent: an empty conformance report as
        // evidence of conformance.
        var w = await SeedAsync();
        using var scope = _fx.Scope();
        var (reads, ctx) = Services(scope, Agent(ScopeTarget.Project(w.ClientId, w.ProjectId)));

        var report = Json(await FindingsTools.GetConformanceAsync(reads, ctx, w.ProjectId));

        Assert.Contains("not conformance", report.GetProperty("note").GetString(), StringComparison.Ordinal);
    }

    // ---- get_quality --------------------------------------------------------

    [SkippableFact]
    public async Task get_quality_reports_tests_and_coverage_for_the_canonical_build()
    {
        Skip.IfNot(_fx.Available);
        var w = await SeedAsync();
        using var scope = _fx.Scope();
        var (reads, ctx) = Services(scope, Agent(ScopeTarget.Project(w.ClientId, w.ProjectId)));

        var quality = Json(await FindingsTools.GetQualityAsync(reads, ctx, w.ProjectId));

        Assert.Equal(w.CommitSha, quality.GetProperty("commitSha").GetString());
        Assert.Equal(10, quality.GetProperty("tests").GetProperty("total").GetInt32());
        Assert.Equal(2, quality.GetProperty("tests").GetProperty("failed").GetInt32());
        Assert.Equal(72.5, quality.GetProperty("coverage").GetProperty("sequencePercent").GetDouble());
    }

    [SkippableFact]
    public async Task get_quality_warns_that_a_fix_would_land_on_a_red_build()
    {
        Skip.IfNot(_fx.Available);

        // A fix shipped into a red build is indistinguishable, in the next
        // report, from whatever was already broken.
        var w = await SeedAsync();
        using var scope = _fx.Scope();
        var (reads, ctx) = Services(scope, Agent(ScopeTarget.Project(w.ClientId, w.ProjectId)));

        var quality = Json(await FindingsTools.GetQualityAsync(reads, ctx, w.ProjectId));

        Assert.Contains("lands on top of that", quality.GetProperty("note").GetString(), StringComparison.Ordinal);
    }

    [SkippableFact]
    public async Task get_quality_calls_an_unmeasured_build_unmeasured_not_passing()
    {
        Skip.IfNot(_fx.Available);
        var w = await SeedAsync();
        using var scope = _fx.Scope();
        var (reads, ctx) = Services(scope, Agent(ScopeTarget.Client(w.ClientId)));
        var bare = await BareProjectWithBuildAsync(w.ClientId);

        var quality = Json(await FindingsTools.GetQualityAsync(reads, ctx, bare));

        Assert.Contains("unmeasured one", quality.GetProperty("note").GetString(), StringComparison.Ordinal);
    }

    // ---- get_license_worklist -----------------------------------------------

    [SkippableFact]
    public async Task get_license_worklist_lists_only_the_unclassifiable_package()
    {
        Skip.IfNot(_fx.Available);
        var w = await SeedAsync();
        using var scope = _fx.Scope();
        var (reads, ctx) = Services(scope, Agent(ScopeTarget.Project(w.ClientId, w.ProjectId)));

        var worklist = Json(await FindingsTools.GetLicenseWorklistAsync(reads, ctx, w.ProjectId));
        var purls = worklist.GetProperty("unresolved").EnumerateArray()
            .Select(u => u.GetProperty("purl").GetString() ?? "")
            .ToArray();

        Assert.Equal(ExpectedUnresolvedPurls, purls);
        Assert.Equal(2, worklist.GetProperty("totalComponents").GetInt32());
    }

    // ---- get_posture --------------------------------------------------------

    [SkippableFact]
    public async Task get_posture_reports_each_checks_current_state_with_its_source()
    {
        Skip.IfNot(_fx.Available);

        // The source travels with the status so a reader can tell an
        // observation from an assumption — a failing check nobody reported is
        // not the same as one GitHub reported as failing.
        var w = await SeedAsync();
        using var scope = _fx.Scope();
        var (reads, ctx) = Services(scope, Agent(ScopeTarget.Project(w.ClientId, w.ProjectId)));

        var posture = Json(await FindingsTools.GetPostureAsync(reads, ctx, w.ProjectId));
        var checks = posture.GetProperty("checks").EnumerateArray()
            .ToDictionary(c => c.GetProperty("checkId").GetString()!, c => c);

        Assert.Equal(2, checks.Count);
        Assert.Equal("Pass", checks["branch-protection"].GetProperty("status").GetString());
        Assert.Equal("Fail", checks["require-reviews"].GetProperty("status").GetString());
        Assert.Equal("github", checks["require-reviews"].GetProperty("source").GetString());
    }

    [SkippableFact]
    public async Task get_posture_with_nothing_observed_does_not_read_as_passing()
    {
        Skip.IfNot(_fx.Available);
        var w = await SeedAsync();
        using var scope = _fx.Scope();
        var (reads, ctx) = Services(scope, Agent(ScopeTarget.Client(w.ClientId)));
        var bare = await BareProjectAsync(w.ClientId);

        var posture = Json(await FindingsTools.GetPostureAsync(reads, ctx, bare));

        Assert.Equal(0, posture.GetProperty("checks").GetArrayLength());
        Assert.Contains("not a passing one", posture.GetProperty("note").GetString(), StringComparison.Ordinal);
    }

    // ---- helpers ------------------------------------------------------------

    private async Task<Guid> BareProjectAsync(Guid clientId)
    {
        using var scope = _fx.Scope();
        var db = _fx.Db(scope);
        var project = new Project { ClientId = clientId, Name = $"bare-{ApiBSupport.Suffix()}" };
        db.Projects.Add(project);
        await db.SaveChangesAsync();
        return project.Id;
    }

    private async Task<Guid> BareProjectWithBuildAsync(Guid clientId)
    {
        var s = ApiBSupport.Suffix();
        using var scope = _fx.Scope();
        var db = _fx.Db(scope);
        var project = new Project { ClientId = clientId, Name = $"bare-build-{s}" };
        db.Projects.Add(project);
        db.ComponentVersions.Add(new ComponentVersion
        {
            ProjectId = project.Id, VersionString = "1.0.0", CommitSha = $"{s}bare", BranchName = "main",
        });
        await db.SaveChangesAsync();
        return project.Id;
    }
}
