using System.Net;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Tamp.Findings.Application.Authorization;
using Tamp.Findings.Application.Projects;
using Tamp.Findings.Domain.Entities;
using Tamp.Findings.Domain.Values;

namespace Tamp.Findings.Integration.Tests;

// TFND-215: the public evidence report is opt-in, key-gated, anonymous, and an allow-list of posture
// and counts — nothing that identifies code or finding detail.
[Collection(DatabaseCollection.Name)]
public class PublicReportIntegrationTests
{
    private const string SecretPath = "src/Internal/SecretPaymentsModule.cs";
    private const string SecretTitle = "Hardcoded credential in vault bootstrap";
    private const string SecretNote = "internal-host.corp.example scanned 77 files";

    private readonly DatabaseFixture _fx;
    public PublicReportIntegrationTests(DatabaseFixture fx) => _fx = fx;

    private sealed record World(Guid ProjectId, Guid UserId, string Login, string ProjectName);

    private async Task<World> SeedAsync()
    {
        using var scope = _fx.Scope();
        var db = _fx.Db(scope);
        var s = Guid.NewGuid().ToString("N")[..8];
        var user = new User { Login = $"pr-{s}", DisplayName = "pr", Email = $"pr{s}@e.test", IsApproved = true };
        var client = new Client { Name = $"pr-client-{s}" };
        var project = new Project { ClientId = client.Id, Name = $"pr-project-{s}" };
        var cv = new ComponentVersion { ProjectId = project.Id, VersionString = "1.0.0", CommitSha = $"{s}abc1234" };
        db.Users.Add(user); db.Clients.Add(client); db.Projects.Add(project); db.ComponentVersions.Add(cv);
        db.Findings.Add(new Finding
        {
            ComponentVersionId = cv.Id, Hash = Guid.NewGuid().ToString("N"), Scanner = ScannerKind.OpenGrep,
            RuleId = "r1", Title = SecretTitle, FilePath = SecretPath, Line = 12, Severity = Severity.High,
        });
        db.ScanRunReceipts.Add(new ScanRunReceipt
        {
            ComponentVersionId = cv.Id, Scanner = ScannerKind.OpenGrep, Status = ScanRunStatus.Succeeded,
            StartedAt = DateTimeOffset.UtcNow.AddMinutes(-2), CompletedAt = DateTimeOffset.UtcNow,
            FindingsCount = 1, ToolName = "OpenGrep", ToolVersion = "1.0", Notes = SecretNote,
        });
        await db.SaveChangesAsync();
        return new World(project.Id, user.Id, user.Login, project.Name);
    }

    private Principal Admin(World w) => Principal.For(w.UserId, w.Login, isAdmin: true, []);

    private async Task<string?> EnableAsync(World w)
    {
        using var scope = _fx.Scope();
        var r = await scope.ServiceProvider.GetRequiredService<ProjectSettingsService>()
            .SetPublicReportAsync(Admin(w), ScopeTarget.Instance, w.ProjectId, enabled: true);
        Assert.True(r.Success);
        return r.Value;
    }

    [SkippableFact]
    public async Task A_private_project_has_no_report_even_with_a_valid_key()
    {
        Skip.IfNot(_fx.Available);
        var w = await SeedAsync();
        var key = await EnableAsync(w);
        using (var scope = _fx.Scope())
            await scope.ServiceProvider.GetRequiredService<ProjectSettingsService>()
                .SetPublicReportAsync(Admin(w), ScopeTarget.Instance, w.ProjectId, enabled: false);

        using var scope2 = _fx.Scope();
        var q = scope2.ServiceProvider.GetRequiredService<PublicReportQuery>();

        Assert.Null(await q.LoadAsync(key!));
        Assert.Null(await q.LoadAsync("not-a-key"));
    }

    [SkippableFact]
    public async Task Rotating_the_key_revokes_the_old_link()
    {
        Skip.IfNot(_fx.Available);
        var w = await SeedAsync();
        var oldKey = await EnableAsync(w);
        string? newKey;
        using (var scope = _fx.Scope())
            newKey = (await scope.ServiceProvider.GetRequiredService<ProjectSettingsService>()
                .SetPublicReportAsync(Admin(w), ScopeTarget.Instance, w.ProjectId, enabled: true, rotateKey: true)).Value;

        using var scope2 = _fx.Scope();
        var q = scope2.ServiceProvider.GetRequiredService<PublicReportQuery>();
        Assert.NotEqual(oldKey, newKey);
        Assert.Null(await q.LoadAsync(oldKey!));
        Assert.NotNull(await q.LoadAsync(newKey!));
    }

    [SkippableFact]
    public async Task Only_a_privileged_principal_can_publish()
    {
        Skip.IfNot(_fx.Available);
        var w = await SeedAsync();
        using var scope = _fx.Scope();
        var viewer = Principal.For(w.UserId, w.Login, isAdmin: false, []);

        var r = await scope.ServiceProvider.GetRequiredService<ProjectSettingsService>()
            .SetPublicReportAsync(viewer, ScopeTarget.Instance, w.ProjectId, enabled: true);

        Assert.False(r.Success);
        Assert.True(r.WasDenied);
        Assert.False(await _fx.Db(scope).Projects.AnyAsync(p => p.Id == w.ProjectId && p.PublicReportEnabled));
    }

    [SkippableFact]
    public async Task The_anonymous_page_renders_posture_and_never_leaks_finding_or_receipt_detail()
    {
        Skip.IfNot(_fx.Available);
        var w = await SeedAsync();
        var key = await EnableAsync(w);
        var http = _fx.Factory!.CreateClient();   // no credentials

        var resp = await http.GetAsync($"/report/{key}");
        var html = await resp.Content.ReadAsStringAsync();

        Assert.Equal(HttpStatusCode.OK, resp.StatusCode);
        Assert.Contains(w.ProjectName, html);
        Assert.Contains("OpenGrep", html);                       // the receipt's scanner IS shown
        Assert.DoesNotContain(SecretPath, html);
        Assert.DoesNotContain(SecretTitle, html);
        Assert.DoesNotContain(SecretNote, html);
        Assert.Contains("no-store", resp.Headers.CacheControl?.ToString() ?? "");
    }

    [SkippableFact]
    public async Task An_unknown_or_disabled_key_is_a_404_with_no_project_detail()
    {
        Skip.IfNot(_fx.Available);
        var w = await SeedAsync();
        var http = _fx.Factory!.CreateClient();

        var resp = await http.GetAsync("/report/0000000000000000000000000000dead");
        var html = await resp.Content.ReadAsStringAsync();

        Assert.Equal(HttpStatusCode.NotFound, resp.StatusCode);
        Assert.DoesNotContain(w.ProjectName, html);
    }
}
