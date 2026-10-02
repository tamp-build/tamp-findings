using Microsoft.EntityFrameworkCore;
using Tamp.Findings.Domain.Entities;
using Tamp.Findings.Domain.Values;

namespace Tamp.Findings.Integration.Tests;

/// <summary>
/// Server-side renders every group-A page as a real signed-in user against seeded data, so the
/// data-dependent branches of each page's OnInitialized / OnParametersSet execute.
/// </summary>
[Collection(DatabaseCollection.Name)]
public class PageARenderSweepTests
{
    private readonly DatabaseFixture _fx;
    public PageARenderSweepTests(DatabaseFixture fx) => _fx = fx;

    private sealed record World(
        User Admin, User Lead, User Viewer, Client Client, Client EmptyClient,
        Project Project, Project EmptyProject, ComponentVersion Cv, string ReportKey, string S);

    private async Task<World> SeedAsync()
    {
        using var scope = _fx.Scope();
        var db = _fx.Db(scope);
        var s = PageAHarness.Suffix();

        var admin = PageAHarness.NewUser(s, admin: true);
        var lead = PageAHarness.NewUser("l" + s, admin: false);
        var viewer = PageAHarness.NewUser("v" + s, admin: false);
        var client = new Client { Name = $"pagea-client-{s}", Description = "seeded" };
        var emptyClient = new Client { Name = $"pagea-empty-{s}" };
        var project = new Project
        {
            ClientId = client.Id, Name = $"pagea-proj-{s}", PublicReportEnabled = true,
            ReportKey = $"rk{s}{Guid.NewGuid():N}", Archetype = ProjectArchetype.Library,
        };
        var emptyProject = new Project { ClientId = emptyClient.Id, Name = $"pagea-eproj-{s}" };
        var cv = new ComponentVersion { ProjectId = project.Id, VersionString = "1.2.3", CommitSha = $"{s}abcdef0123" };
        db.Users.AddRange(admin, lead, viewer);
        db.Clients.AddRange(client, emptyClient);
        db.Projects.AddRange(project, emptyProject);
        db.ComponentVersions.Add(cv);
        db.ProjectRoleAssignments.Add(new ProjectRoleAssignment { UserId = lead.Id, Role = ProjectRole.LeadDev, ClientId = client.Id });
        db.ProjectRoleAssignments.Add(new ProjectRoleAssignment { UserId = viewer.Id, Role = ProjectRole.Architect, ProjectId = project.Id, ClientId = client.Id });

        foreach (var (sev, i) in new[] { Severity.Critical, Severity.High, Severity.Medium, Severity.Low }.Select((x, i) => (x, i)))
            db.Findings.Add(new Finding
            {
                ComponentVersionId = cv.Id, Hash = Guid.NewGuid().ToString("N"), Scanner = ScannerKind.OpenGrep,
                RuleId = $"r{i}", Title = $"finding {i}", FilePath = $"src/f{i}.cs", Line = 10 + i, Severity = sev,
            });
        db.ScanRunReceipts.Add(new ScanRunReceipt
        {
            ComponentVersionId = cv.Id, Scanner = ScannerKind.OpenGrep, Status = ScanRunStatus.Succeeded,
            StartedAt = DateTimeOffset.UtcNow.AddMinutes(-2), CompletedAt = DateTimeOffset.UtcNow,
            FindingsCount = 4, ToolName = "OpenGrep", ToolVersion = "1.0",
        });
        db.ScanUsageObservations.Add(new ScanUsageObservation
        {
            ComponentVersionId = cv.Id, Adapter = "claude-sca", Capability = "triage", ModelId = "claude-sonnet-4",
            Provider = "anthropic", InputTokens = 12000, OutputTokens = 3000, LatencyMs = 900, ObservedAt = DateTimeOffset.UtcNow,
        });
        db.BannedComponents.Add(new BannedComponent
        {
            Purl = $"pkg:npm/evil-{s}", Source = "manual", Reason = "malicious", Versions = ["1.0.0"],
        });
        db.PolicyTemplates.Add(new PolicyTemplate { Name = $"tmpl-{s}" });
        db.ZtSystems.Add(new ZtSystem { ClientId = client.Id, ProjectId = project.Id, Name = $"zt-{s}", CsamId = "CSAM-1", SystemKind = "app" });
        await db.SaveChangesAsync();
        return new World(admin, lead, viewer, client, emptyClient, project, emptyProject, cv, project.ReportKey!, s);
    }

    private static string Cp(World w) => $"/c/{w.Client.Name}/p/{w.Project.Name}";

    [SkippableFact]
    public async Task Admin_renders_every_group_a_route()
    {
        Skip.IfNot(_fx.Available);
        var w = await SeedAsync();
        var c = _fx.Factory!.SignedInAs(w.Admin);

        var routes = new List<string>
        {
            "/", "/portfolio", $"/c/{w.Client.Name}", $"/c/{w.EmptyClient.Name}", $"/c/{w.Client.Name}/policy",
            $"{Cp(w)}/policy", $"{Cp(w)}/settings/policy", $"{Cp(w)}/costs", $"{Cp(w)}/zt",
            $"/c/{w.EmptyClient.Name}/p/{w.EmptyProject.Name}/costs", $"/c/{w.EmptyClient.Name}/p/{w.EmptyProject.Name}/zt",
            $"/c/{w.EmptyClient.Name}/p/{w.EmptyProject.Name}/policy", $"/c/{w.EmptyClient.Name}/p/{w.EmptyProject.Name}/settings/policy",
            "/system", "/system/banned-components", "/system/eo-registry", "/system/frameworks", "/system/policy-pack",
            "/manage/policy-templates", $"/report/{w.ReportKey}", "/report/nope", "/signin", "/dev/primitives",
        };
        routes.AddRange(Tamp.Findings.Web.Routing.SystemPanels.All.Select(p => $"/system/{p}"));

        foreach (var r in routes) await c.GetAsync(r);
    }
}
