using Tamp.Findings.Application.Authorization;
using Tamp.Findings.Data;
using Tamp.Findings.Domain.Entities;
using Tamp.Findings.Domain.Values;

namespace Tamp.Findings.Integration.Tests;

/// <summary>Seeding helpers private to the AppCov test files.</summary>
internal static class AppCovSeed
{
    internal sealed record Actors(Principal Admin, Principal InfoSec, Principal Lead, Principal Viewer);

    internal static async Task<Actors> UsersAsync(FindingsDbContext db)
    {
        var s = Guid.NewGuid().ToString("N")[..8];
        User U(string role, bool admin = false) => new()
        {
            Login = $"cov-{role}-{s}", DisplayName = role, Email = $"cov-{role}-{s}@example.test", IsApproved = true, IsAdmin = admin,
        };
        var admin = U("admin", true); var infosec = U("infosec"); var lead = U("lead"); var viewer = U("viewer");
        db.Users.AddRange(admin, infosec, lead, viewer);
        await db.SaveChangesAsync();
        return new Actors(
            Principal.For(admin.Id, admin.Login, true, []),
            Principal.For(infosec.Id, infosec.Login, false, [ProjectRole.InfoSecOfficer]),
            Principal.For(lead.Id, lead.Login, false, [ProjectRole.LeadDev]),
            Principal.For(viewer.Id, viewer.Login, false, []));
    }

    internal static async Task<(Client Client, Project Project)> ClientProjectAsync(FindingsDbContext db, string tag = "cov")
    {
        var s = Guid.NewGuid().ToString("N")[..8];
        var client = new Client { Name = $"{tag}-client-{s}" };
        var project = new Project { ClientId = client.Id, Name = $"{tag}-project-{s}" };
        db.Clients.Add(client);
        db.Projects.Add(project);
        await db.SaveChangesAsync();
        return (client, project);
    }

    internal static async Task<ComponentVersion> BuildAsync(FindingsDbContext db, Guid projectId, string? sha = null,
        string? branch = "main", DateTimeOffset? at = null, string? pr = null)
    {
        var cv = new ComponentVersion
        {
            ProjectId = projectId, VersionString = "1.0." + Guid.NewGuid().ToString("N")[..4],
            CommitSha = sha ?? Guid.NewGuid().ToString("N")[..12], BranchName = branch, PullRequestRef = pr,
            CreatedAt = at ?? DateTimeOffset.UtcNow,
        };
        db.ComponentVersions.Add(cv);
        await db.SaveChangesAsync();
        return cv;
    }
}
