using Tamp.Findings.Domain.Entities;
using Tamp.Findings.Domain.Values;

namespace Tamp.Findings.Integration.Tests;

/// <summary>A seeded tenant used by the PageA tests: admin, lead (client role), architect (project role), data.</summary>
public sealed record PageAWorld(
    User Admin, User Lead, User Architect, User Nobody, Client Client, Client EmptyClient,
    Project Project, Project Project2, Project EmptyProject, ComponentVersion Cv, ComponentVersion Cv2, string S)
{
    public static async Task<PageAWorld> SeedAsync(DatabaseFixture fx)
    {
        using var scope = fx.Scope();
        var db = fx.Db(scope);
        var s = PageAHarness.Suffix();

        var admin = PageAHarness.NewUser(s, admin: true);
        var lead = PageAHarness.NewUser("l" + s, admin: false);
        var architect = PageAHarness.NewUser("a" + s, admin: false);
        var nobody = PageAHarness.NewUser("n" + s, admin: false);
        var client = new Client { Name = $"pagea-client-{s}", Description = "seeded client" };
        var emptyClient = new Client { Name = $"pagea-empty-{s}" };
        var project = new Project
        {
            ClientId = client.Id, Name = $"pagea-proj-{s}", PublicReportEnabled = true,
            ReportKey = $"rk{s}{Guid.NewGuid():N}", Archetype = ProjectArchetype.ServiceApp,
        };
        var project2 = new Project { ClientId = client.Id, Name = $"pagea-proj2-{s}", Archetype = ProjectArchetype.Library };
        var emptyProject = new Project { ClientId = emptyClient.Id, Name = $"pagea-eproj-{s}" };
        var cv = new ComponentVersion { ProjectId = project.Id, VersionString = "1.2.3", CommitSha = $"{s}abcdef0123" };
        var cv2 = new ComponentVersion { ProjectId = project.Id, VersionString = "1.2.4", CommitSha = $"{s}fedcba9876" };
        db.Users.AddRange(admin, lead, architect, nobody);
        db.Clients.AddRange(client, emptyClient);
        db.Projects.AddRange(project, project2, emptyProject);
        db.ComponentVersions.AddRange(cv, cv2);
        db.ProjectRoleAssignments.Add(new ProjectRoleAssignment { UserId = lead.Id, Role = ProjectRole.LeadDev, ClientId = client.Id });
        db.ProjectRoleAssignments.Add(new ProjectRoleAssignment
        {
            UserId = architect.Id, Role = ProjectRole.Architect, ClientId = client.Id, ProjectId = project.Id,
        });

        foreach (var c in new[] { cv, cv2 })
            foreach (var (sev, i) in new[] { Severity.Critical, Severity.High, Severity.Medium, Severity.Low }.Select((x, i) => (x, i)))
                db.Findings.Add(new Finding
                {
                    ComponentVersionId = c.Id, Hash = Guid.NewGuid().ToString("N"), Scanner = ScannerKind.OpenGrep,
                    RuleId = $"r{i}", Title = $"finding {i}", FilePath = $"src/f{i}.cs", Line = 10 + i, Severity = sev,
                });
        db.ScanRunReceipts.Add(new ScanRunReceipt
        {
            ComponentVersionId = cv.Id, Scanner = ScannerKind.OpenGrep, Status = ScanRunStatus.Succeeded,
            StartedAt = DateTimeOffset.UtcNow.AddMinutes(-2), CompletedAt = DateTimeOffset.UtcNow,
            FindingsCount = 4, ToolName = "OpenGrep", ToolVersion = "1.0",
        });
        await db.SaveChangesAsync();
        return new PageAWorld(admin, lead, architect, nobody, client, emptyClient, project, project2, emptyProject, cv, cv2, s);
    }

    public (string Name, object Value) Client_ => ("Client", Client.Name);
    public (string Name, object? Value)[] Of(Project p) => [("Client", p.ClientId == Client.Id ? Client.Name : EmptyClient.Name), ("Project", p.Name)];
}
