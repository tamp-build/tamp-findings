using System.Net.Http.Json;
using System.Text.Json;
using Tamp.Findings.Domain.Entities;
using Tamp.Findings.Domain.Values;

namespace Tamp.Findings.Integration.Tests;

// TFND-231: /aggregates derived iac.scanned from "does ANY Trivy finding exist in the database", so one tenant's
// IaC scan made every other project read as scanned. It must follow the requested scope.
[Collection(DatabaseCollection.Name)]
public class AggregatesIacScopeTests
{
    private readonly DatabaseFixture _fx;
    public AggregatesIacScopeTests(DatabaseFixture fx) => _fx = fx;

    private sealed record Tenants(Guid ScannedClient, Guid ScannedProject, Guid UnscannedClient, Guid UnscannedProject, Guid AdminId);

    private async Task<Tenants> SeedAsync(FindingStatus trivyStatus)
    {
        var s = ApiBSupport.Suffix();
        using var scope = _fx.Scope();
        var db = _fx.Db(scope);
        var admin = new User { Login = $"iac-admin-{s}", DisplayName = "a", Email = $"a{s}@e.test", IsApproved = true, IsAdmin = true };
        var c1 = new Client { Name = $"iac-c1-{s}" };
        var c2 = new Client { Name = $"iac-c2-{s}" };
        var p1 = new Project { ClientId = c1.Id, Name = $"iac-p1-{s}" };
        var p2 = new Project { ClientId = c2.Id, Name = $"iac-p2-{s}" };
        db.Users.Add(admin); db.Clients.AddRange(c1, c2); db.Projects.AddRange(p1, p2);
        var cv1 = new ComponentVersion { ProjectId = p1.Id, VersionString = "1.0.0", CommitSha = $"{s}i1" };
        var cv2 = new ComponentVersion { ProjectId = p2.Id, VersionString = "1.0.0", CommitSha = $"{s}i2" };
        db.ComponentVersions.AddRange(cv1, cv2);
        // Only project 1 has ever had a Trivy finding (possibly closed: a once-found-now-fixed finding still
        // counts as evidence the scanner ran, for THAT project).
        db.Findings.Add(new Finding
        {
            ComponentVersionId = cv1.Id, Hash = Guid.NewGuid().ToString("N"), Scanner = ScannerKind.Trivy, RuleId = "AVD-1",
            Title = "iac", Severity = Severity.High, Status = trivyStatus, SubCategory = "misconfiguration",
        });
        await db.SaveChangesAsync();
        return new Tenants(c1.Id, p1.Id, c2.Id, p2.Id, admin.Id);
    }

    private async Task<bool> IacScannedAsync(Guid adminId, string query)
    {
        var http = _fx.Factory!.WithTestAuth().As(adminId);
        var json = await http.GetFromJsonAsync<JsonElement>($"/aggregates?{query}&latest=false");
        return json.GetProperty("iac").GetProperty("scanned").GetBoolean();
    }

    [SkippableTheory]
    [InlineData(FindingStatus.Open)]
    [InlineData(FindingStatus.Fixed)]
    public async Task A_project_with_no_trivy_evidence_is_not_scanned_even_when_another_tenant_has_some(FindingStatus status)
    {
        Skip.IfNot(_fx.Available);
        var t = await SeedAsync(status);

        Assert.True(await IacScannedAsync(t.AdminId, $"projectId={t.ScannedProject}"));
        Assert.False(await IacScannedAsync(t.AdminId, $"projectId={t.UnscannedProject}"));
        Assert.True(await IacScannedAsync(t.AdminId, $"clientId={t.ScannedClient}"));
        Assert.False(await IacScannedAsync(t.AdminId, $"clientId={t.UnscannedClient}"));
    }
}
