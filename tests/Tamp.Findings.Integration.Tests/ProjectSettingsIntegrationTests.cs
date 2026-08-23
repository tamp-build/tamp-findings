using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Tamp.Findings.Application.Attestation;
using Tamp.Findings.Application.Authorization;
using Tamp.Findings.Application.Projects;
using Tamp.Findings.Domain.Entities;
using Tamp.Findings.Domain.Values;

namespace Tamp.Findings.Integration.Tests;

// Project settings: ingest tokens and the disclosure policy
// (TFND-107 / TFND-108).
[Collection(DatabaseCollection.Name)]
public class ProjectSettingsIntegrationTests
{
    private readonly DatabaseFixture _fx;

    public ProjectSettingsIntegrationTests(DatabaseFixture fx) => _fx = fx;

    // ---- Tokens -------------------------------------------------------------

    [SkippableFact]
    public async Task A_minted_token_returns_its_plaintext_exactly_once()
    {
        Skip.IfNot(_fx.Available);

        var world = await SeedAsync();
        using var scope = _fx.Scope();
        var settings = scope.ServiceProvider.GetRequiredService<ProjectSettingsService>();
        var db = _fx.Db(scope);

        var minted = await settings.MintTokenAsync(
            world.Admin, world.Scope, world.ProjectId, "ci · brewerybot");

        Assert.True(minted.Success);
        Assert.NotEmpty(minted.Value!.Plaintext);

        // And the plaintext is genuinely not in the database.
        var stored = await db.IngestTokens.SingleAsync(t => t.Id == minted.Value.Record.Id);
        Assert.DoesNotContain(minted.Value.Plaintext, stored.TokenHash, StringComparison.Ordinal);
    }

    [SkippableFact]
    public async Task The_list_shows_a_hash_prefix_rather_than_anything_usable()
    {
        Skip.IfNot(_fx.Available);

        // Enough to match a rejected request in a log against a row here; not
        // enough to authenticate with.
        var world = await SeedAsync();
        using var scope = _fx.Scope();
        var settings = scope.ServiceProvider.GetRequiredService<ProjectSettingsService>();

        var minted = await settings.MintTokenAsync(world.Admin, world.Scope, world.ProjectId, "ci");
        var row = (await settings.TokensAsync(world.ProjectId, world.AsOf)).Single();

        Assert.Equal(8, row.HashPrefix.Length);
        Assert.DoesNotContain(row.HashPrefix, minted.Value!.Plaintext, StringComparison.Ordinal);
    }

    [SkippableFact]
    public async Task An_unlabelled_token_is_refused()
    {
        Skip.IfNot(_fx.Available);

        // The label is what makes a revoke decision possible six months from
        // now.
        var world = await SeedAsync();
        using var scope = _fx.Scope();
        var settings = scope.ServiceProvider.GetRequiredService<ProjectSettingsService>();

        var result = await settings.MintTokenAsync(world.Admin, world.Scope, world.ProjectId, "   ");

        Assert.False(result.Success);
        Assert.False(result.WasDenied);
    }

    [SkippableFact]
    public async Task A_revoked_token_stays_in_the_list()
    {
        Skip.IfNot(_fx.Available);

        // "Was this key live in March?" is the question asked after an
        // incident, and a list that drops revoked rows cannot answer it.
        var world = await SeedAsync();
        using var scope = _fx.Scope();
        var settings = scope.ServiceProvider.GetRequiredService<ProjectSettingsService>();

        var minted = await settings.MintTokenAsync(world.Admin, world.Scope, world.ProjectId, "ci");
        await settings.RevokeTokenAsync(world.Admin, world.Scope, world.ProjectId, minted.Value!.Record.Id);

        var row = (await settings.TokensAsync(world.ProjectId, world.AsOf)).Single();

        Assert.True(row.Revoked);
    }

    [SkippableFact]
    public async Task A_live_token_nobody_has_ever_used_is_flagged()
    {
        Skip.IfNot(_fx.Available);

        // Either the pipeline was never wired up or it is failing silently.
        var world = await SeedAsync();
        using var scope = _fx.Scope();
        var settings = scope.ServiceProvider.GetRequiredService<ProjectSettingsService>();

        await settings.MintTokenAsync(world.Admin, world.Scope, world.ProjectId, "ci");

        // A month later it has still never been presented.
        var rows = await settings.TokensAsync(world.ProjectId, DateTimeOffset.UtcNow.AddDays(30));

        Assert.True(rows.Single().NeverUsed);
    }

    [SkippableFact]
    public async Task A_token_minted_today_is_not_flagged_as_unused()
    {
        Skip.IfNot(_fx.Available);

        // A pipeline that runs weekly has not failed just because it has not
        // run yet. Flagging immediately would train people to ignore the flag.
        var world = await SeedAsync();
        using var scope = _fx.Scope();
        var settings = scope.ServiceProvider.GetRequiredService<ProjectSettingsService>();

        await settings.MintTokenAsync(world.Admin, world.Scope, world.ProjectId, "ci");

        Assert.False((await settings.TokensAsync(world.ProjectId, DateTimeOffset.UtcNow)).Single().NeverUsed);
    }

    [SkippableFact]
    public async Task Minting_and_revoking_are_audited_as_access_changes()
    {
        Skip.IfNot(_fx.Available);

        // A new key is a new way in — what an assessor reads first alongside
        // role grants and risk acceptance.
        var world = await SeedAsync();
        using var scope = _fx.Scope();
        var settings = scope.ServiceProvider.GetRequiredService<ProjectSettingsService>();
        var db = _fx.Db(scope);

        var minted = await settings.MintTokenAsync(world.Admin, world.Scope, world.ProjectId, "ci");
        await settings.RevokeTokenAsync(world.Admin, world.Scope, world.ProjectId, minted.Value!.Record.Id);

        var entries = db.AuditEntries
            .Where(a => a.SubjectId == minted.Value.Record.Id)
            .ToArray();

        Assert.Equal(2, entries.Length);
        Assert.All(entries, e => Assert.Equal(AuditClass.Access, e.Class));
    }

    [SkippableFact]
    public async Task An_architect_may_not_mint_a_token()
    {
        Skip.IfNot(_fx.Available);

        // Recycling breaks CI until the pipeline is redeployed, which is why
        // Architect is excluded from key management.
        var world = await SeedAsync();
        using var scope = _fx.Scope();
        var settings = scope.ServiceProvider.GetRequiredService<ProjectSettingsService>();

        var result = await settings.MintTokenAsync(world.Architect, world.Scope, world.ProjectId, "ci");

        Assert.True(result.WasDenied);
    }

    // ---- Disclosure policy --------------------------------------------------

    [SkippableFact]
    public async Task A_published_policy_url_answers_rv_3_1_outright()
    {
        Skip.IfNot(_fx.Available);

        var world = await SeedAsync();
        using var scope = _fx.Scope();
        var settings = scope.ServiceProvider.GetRequiredService<ProjectSettingsService>();

        var result = await settings.SaveDisclosureAsync(
            world.Admin, world.Scope, world.ProjectId,
            new VdpSettings("https://example.test/security", "security@example.test", null));

        Assert.Equal(VdpEffect.Yes, result.Value);
    }

    [SkippableFact]
    public async Task A_contact_email_alone_caps_rv_3_1_at_partial()
    {
        Skip.IfNot(_fx.Available);

        // The minimum CISA BOD 20-01 asks for, and not the gold standard.
        var world = await SeedAsync();
        using var scope = _fx.Scope();
        var settings = scope.ServiceProvider.GetRequiredService<ProjectSettingsService>();

        var result = await settings.SaveDisclosureAsync(
            world.Admin, world.Scope, world.ProjectId,
            new VdpSettings(null, "security@example.test", null));

        Assert.Equal(VdpEffect.Partial, result.Value);
    }

    [SkippableFact]
    public async Task The_settings_screen_and_the_attestation_agree_about_rv_3_1()
    {
        Skip.IfNot(_fx.Available);

        // Two different answers on two screens is how a team learns to trust
        // neither.
        var world = await SeedAsync();
        using var scope = _fx.Scope();
        var settings = scope.ServiceProvider.GetRequiredService<ProjectSettingsService>();
        var builder = scope.ServiceProvider.GetRequiredService<SsdfAttestationBuilder>();

        await settings.SaveDisclosureAsync(
            world.Admin, world.Scope, world.ProjectId,
            new VdpSettings("https://example.test/security", null, null));

        var doc = await builder.BuildAsync(world.ProjectId, world.Sha);
        var practice = doc!.Practices.Single(p => p.Id == "RV.3.1");

        Assert.Equal("Yes", practice.Status);
    }

    [SkippableFact]
    public async Task A_policy_url_that_is_not_a_url_is_refused()
    {
        Skip.IfNot(_fx.Available);

        // Saving one would put a claim in an attestation that nobody can check.
        var world = await SeedAsync();
        using var scope = _fx.Scope();
        var settings = scope.ServiceProvider.GetRequiredService<ProjectSettingsService>();

        var result = await settings.SaveDisclosureAsync(
            world.Admin, world.Scope, world.ProjectId,
            new VdpSettings("example.test/security", null, null));

        Assert.False(result.Success);
        Assert.False(result.WasDenied);
    }

    [SkippableFact]
    public async Task Moving_the_attestation_answer_is_audited_as_a_risk_decision()
    {
        Skip.IfNot(_fx.Available);

        var world = await SeedAsync();
        using var scope = _fx.Scope();
        var settings = scope.ServiceProvider.GetRequiredService<ProjectSettingsService>();
        var db = _fx.Db(scope);

        await settings.SaveDisclosureAsync(
            world.Admin, world.Scope, world.ProjectId,
            new VdpSettings("https://example.test/security", null, null));

        var entry = db.AuditEntries.Single(
            a => a.SubjectId == world.ProjectId && a.Action == "project.vdp_changed");

        Assert.Equal(AuditClass.Risk, entry.Class);
        Assert.Contains("RV.3.1 No → Yes", entry.Detail!, StringComparison.Ordinal);
    }

    [SkippableFact]
    public async Task Editing_a_detail_without_moving_the_answer_is_not_a_risk_decision()
    {
        Skip.IfNot(_fx.Available);

        // Changing a contact address is housekeeping. Classing it as risk
        // would bury the real decisions.
        var world = await SeedAsync();
        using var scope = _fx.Scope();
        var settings = scope.ServiceProvider.GetRequiredService<ProjectSettingsService>();
        var db = _fx.Db(scope);

        await settings.SaveDisclosureAsync(
            world.Admin, world.Scope, world.ProjectId,
            new VdpSettings("https://example.test/security", "first@example.test", null));
        await settings.SaveDisclosureAsync(
            world.Admin, world.Scope, world.ProjectId,
            new VdpSettings("https://example.test/security", "second@example.test", null));

        var entry = db.AuditEntries
            .Where(a => a.SubjectId == world.ProjectId && a.Action == "project.vdp_changed")
            .OrderByDescending(a => a.At)
            .First();

        Assert.NotEqual(AuditClass.Risk, entry.Class);
    }

    [SkippableFact]
    public async Task A_lead_dev_may_not_change_the_disclosure_policy()
    {
        Skip.IfNot(_fx.Available);

        // It changes what a signed attestation claims, so it sits with gates
        // rather than with ordinary project settings.
        var world = await SeedAsync();
        using var scope = _fx.Scope();
        var settings = scope.ServiceProvider.GetRequiredService<ProjectSettingsService>();

        var result = await settings.SaveDisclosureAsync(
            world.LeadDev, world.Scope, world.ProjectId,
            new VdpSettings("https://example.test/security", null, null));

        Assert.True(result.WasDenied);
    }

    // ---- Seed ---------------------------------------------------------------

    private sealed record World(
        Guid ProjectId, string Sha, ScopeTarget Scope, DateTimeOffset AsOf,
        Principal Admin, Principal LeadDev, Principal Architect);

    private async Task<World> SeedAsync()
    {
        using var scope = _fx.Scope();
        var db = _fx.Db(scope);

        var suffix = Guid.NewGuid().ToString("N")[..8];
        var sha = suffix + "eeeeee";

        var client = new Client { Name = $"set-client-{suffix}" };
        var project = new Project { ClientId = client.Id, Name = $"set-project-{suffix}" };
        var component = new Component { ProjectId = project.Id, Name = $"set-component-{suffix}" };
        var version = new ComponentVersion
        {
            ComponentId = component.Id, VersionString = "1.0.0", CommitSha = sha, BranchName = "main",
        };

        db.Clients.Add(client);
        db.Projects.Add(project);
        db.Components.Add(component);
        db.ComponentVersions.Add(version);

        var user = new User
        {
            Login = $"set-{suffix}",
            DisplayName = "Settings Author",
            Email = $"set-{suffix}@example.test",
            IsApproved = true,
        };
        db.Users.Add(user);

        await db.SaveChangesAsync();

        var target = ScopeTarget.Project(client.Id, project.Id);
        return new World(
            project.Id, sha, target, DateTimeOffset.UtcNow,
            Admin: Principal.For(user.Id, user.Login, isAdmin: true, []),
            LeadDev: Principal.For(user.Id, user.Login, isAdmin: false, [ProjectRole.LeadDev]),
            Architect: Principal.For(user.Id, user.Login, isAdmin: false, [ProjectRole.Architect]));
    }
}
