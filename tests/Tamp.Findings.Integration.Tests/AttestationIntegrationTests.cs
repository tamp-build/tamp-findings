using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Tamp.Findings.Application.Attestation;
using Tamp.Findings.Application.Authorization;
using Tamp.Findings.Domain.Entities;
using Tamp.Findings.Domain.Values;

namespace Tamp.Findings.Integration.Tests;

// The attestation (TFND-100 … TFND-103).
//
// The determinism requirement from ADR 0001 is the reason most of these exist:
// "an attestation signed in March must be reproducible in September, or the
// signature attests to nothing."
[Collection(DatabaseCollection.Name)]
public class AttestationIntegrationTests
{
    private readonly DatabaseFixture _fx;

    public AttestationIntegrationTests(DatabaseFixture fx) => _fx = fx;

    // ---- Building -----------------------------------------------------------

    [SkippableFact]
    public async Task The_document_names_the_build_it_actually_used()
    {
        Skip.IfNot(_fx.Available);

        var world = await SeedAsync();
        using var scope = _fx.Scope();
        var builder = scope.ServiceProvider.GetRequiredService<SsdfAttestationBuilder>();

        var doc = await builder.BuildAsync(world.ProjectId, world.Sha);

        Assert.Equal(world.Sha, doc!.Build!.CommitSha);
    }

    [SkippableFact]
    public async Task A_sha_that_matches_nothing_does_not_silently_attest_the_latest_build()
    {
        Skip.IfNot(_fx.Available);

        // The single worst thing this document could do: attest a different
        // commit than the URL names.
        var world = await SeedAsync();
        using var scope = _fx.Scope();
        var builder = scope.ServiceProvider.GetRequiredService<SsdfAttestationBuilder>();

        var doc = await builder.BuildAsync(world.ProjectId, "0000000000");

        Assert.Null(doc!.Build);
    }

    [SkippableFact]
    public async Task Every_practice_family_is_present()
    {
        Skip.IfNot(_fx.Available);

        var world = await SeedAsync();
        using var scope = _fx.Scope();
        var builder = scope.ServiceProvider.GetRequiredService<SsdfAttestationBuilder>();

        var doc = await builder.BuildAsync(world.ProjectId, world.Sha);

        foreach (var family in new[] { "PO", "PS", "PW", "RV" })
            Assert.Contains(doc!.Practices, p => p.Family == family);
    }

    [SkippableFact]
    public async Task Organizational_practices_read_as_manual_rather_than_as_failures()
    {
        Skip.IfNot(_fx.Available);

        // A tool that scored these would be inventing an answer the signatory
        // is the only person entitled to give.
        var world = await SeedAsync();
        using var scope = _fx.Scope();
        var builder = scope.ServiceProvider.GetRequiredService<SsdfAttestationBuilder>();

        var doc = await builder.BuildAsync(world.ProjectId, world.Sha);

        Assert.Equal("Manual", doc!.Practices.Single(p => p.Id == "PO.1.1").Status);
        Assert.True(doc.Summary.Manual > 0);
    }

    [SkippableFact]
    public async Task A_build_with_no_dast_cannot_reach_a_full_yes_on_pw_8_1()
    {
        Skip.IfNot(_fx.Available);

        // PW.8.1 is THE dynamic-analysis practice. Answering "Yes" off a
        // passing unit suite would assert a control that was never exercised.
        var world = await SeedAsync();
        using var scope = _fx.Scope();
        var builder = scope.ServiceProvider.GetRequiredService<SsdfAttestationBuilder>();

        var doc = await builder.BuildAsync(world.ProjectId, world.Sha);
        var practice = doc!.Practices.Single(p => p.Id == "PW.8.1");

        Assert.NotEqual("Yes", practice.Status);
        Assert.Contains("PW.8.1", practice.Evidence, StringComparison.Ordinal);
    }

    // ---- Snapshots ----------------------------------------------------------

    [SkippableFact]
    public async Task A_snapshot_reads_back_the_document_verbatim()
    {
        Skip.IfNot(_fx.Available);

        var world = await SeedAsync();
        using var scope = _fx.Scope();
        var builder = scope.ServiceProvider.GetRequiredService<SsdfAttestationBuilder>();
        var snapshots = scope.ServiceProvider.GetRequiredService<AttestationSnapshotService>();

        var doc = await builder.BuildAsync(world.ProjectId, world.Sha);
        await snapshots.CaptureAsync(world.Admin, world.Scope, world.ProjectId, doc!);

        var stored = await snapshots.LatestForBuildAsync(world.ProjectId, world.Sha);

        Assert.Equal(doc!.Practices.Count, stored!.Document.Practices.Count);
        Assert.Equal(doc.Summary.Headline, stored.Document.Summary.Headline);
        Assert.Equal(doc.Risk!.PolicyName, stored.Document.Risk!.PolicyName);
    }

    [SkippableFact]
    public async Task Changing_the_policy_afterwards_does_not_alter_a_snapshot()
    {
        Skip.IfNot(_fx.Available);

        // The acceptance criterion from TFND-103, and the reason the whole
        // document is stored rather than recomputed.
        var world = await SeedAsync();
        using var scope = _fx.Scope();
        var builder = scope.ServiceProvider.GetRequiredService<SsdfAttestationBuilder>();
        var snapshots = scope.ServiceProvider.GetRequiredService<AttestationSnapshotService>();
        var db = _fx.Db(scope);

        var doc = await builder.BuildAsync(world.ProjectId, world.Sha);
        await snapshots.CaptureAsync(world.Admin, world.Scope, world.ProjectId, doc!);
        var originalPolicy = doc!.Risk!.PolicyName;

        // Policy names are unique across the instance, so the rename carries
        // the seed's own suffix.
        var renamed = $"{originalPolicy}-renamed";
        var policy = await db.RiskPolicies.SingleAsync(p => p.Id == world.PolicyId);
        policy.Name = renamed;
        await db.SaveChangesAsync();

        var stored = await snapshots.LatestForBuildAsync(world.ProjectId, world.Sha);

        Assert.Equal(originalPolicy, stored!.Document.Risk!.PolicyName);
        // And the live build now says something different, which is exactly why
        // the snapshot had to be stored.
        var rebuilt = await builder.BuildAsync(world.ProjectId, world.Sha);
        Assert.Equal(renamed, rebuilt!.Risk!.PolicyName);
    }

    [SkippableFact]
    public async Task A_snapshot_cannot_be_edited()
    {
        Skip.IfNot(_fx.Available);

        // A snapshot that can be edited is not evidence.
        var world = await SeedAsync();
        using var scope = _fx.Scope();
        var builder = scope.ServiceProvider.GetRequiredService<SsdfAttestationBuilder>();
        var snapshots = scope.ServiceProvider.GetRequiredService<AttestationSnapshotService>();
        var db = _fx.Db(scope);

        var doc = await builder.BuildAsync(world.ProjectId, world.Sha);
        var created = await snapshots.CaptureAsync(world.Admin, world.Scope, world.ProjectId, doc!);

        var snapshot = await db.AttestationSnapshots.SingleAsync(s => s.Id == created.Value);
        snapshot.Score = 0;

        await Assert.ThrowsAsync<InvalidOperationException>(() => db.SaveChangesAsync());
    }

    [SkippableFact]
    public async Task A_snapshot_cannot_be_deleted()
    {
        Skip.IfNot(_fx.Available);

        var world = await SeedAsync();
        using var scope = _fx.Scope();
        var builder = scope.ServiceProvider.GetRequiredService<SsdfAttestationBuilder>();
        var snapshots = scope.ServiceProvider.GetRequiredService<AttestationSnapshotService>();
        var db = _fx.Db(scope);

        var doc = await builder.BuildAsync(world.ProjectId, world.Sha);
        var created = await snapshots.CaptureAsync(world.Admin, world.Scope, world.ProjectId, doc!);

        db.AttestationSnapshots.Remove(await db.AttestationSnapshots.SingleAsync(s => s.Id == created.Value));

        await Assert.ThrowsAsync<InvalidOperationException>(() => db.SaveChangesAsync());
    }

    [SkippableFact]
    public async Task Recording_a_signature_is_the_one_permitted_change()
    {
        Skip.IfNot(_fx.Available);

        var world = await SeedAsync();
        using var scope = _fx.Scope();
        var builder = scope.ServiceProvider.GetRequiredService<SsdfAttestationBuilder>();
        var snapshots = scope.ServiceProvider.GetRequiredService<AttestationSnapshotService>();

        var doc = await builder.BuildAsync(world.ProjectId, world.Sha);
        var created = await snapshots.CaptureAsync(world.Admin, world.Scope, world.ProjectId, doc!);

        var signed = await snapshots.SignAsync(
            world.Admin, world.Scope, world.ProjectId, created.Value, "A. Signatory, CISO");

        Assert.True(signed.Success);
        var stored = await snapshots.LatestForBuildAsync(world.ProjectId, world.Sha);
        Assert.Equal("A. Signatory, CISO", stored!.SignedBy);
    }

    [SkippableFact]
    public async Task A_snapshot_can_only_be_signed_once()
    {
        Skip.IfNot(_fx.Available);

        // A second signature would overwrite the first and leave no record that
        // it existed.
        var world = await SeedAsync();
        using var scope = _fx.Scope();
        var builder = scope.ServiceProvider.GetRequiredService<SsdfAttestationBuilder>();
        var snapshots = scope.ServiceProvider.GetRequiredService<AttestationSnapshotService>();

        var doc = await builder.BuildAsync(world.ProjectId, world.Sha);
        var created = await snapshots.CaptureAsync(world.Admin, world.Scope, world.ProjectId, doc!);

        await snapshots.SignAsync(world.Admin, world.Scope, world.ProjectId, created.Value, "First");
        var second = await snapshots.SignAsync(world.Admin, world.Scope, world.ProjectId, created.Value, "Second");

        Assert.False(second.Success);
        Assert.Contains("First", second.Error!, StringComparison.Ordinal);
    }

    [SkippableFact]
    public async Task Two_snapshots_of_one_build_are_both_kept()
    {
        Skip.IfNot(_fx.Available);

        // Two statements about the same commit taken a month apart are two
        // different statements — the second may reflect a suppression written
        // in between.
        var world = await SeedAsync();
        using var scope = _fx.Scope();
        var builder = scope.ServiceProvider.GetRequiredService<SsdfAttestationBuilder>();
        var snapshots = scope.ServiceProvider.GetRequiredService<AttestationSnapshotService>();

        var doc = await builder.BuildAsync(world.ProjectId, world.Sha);
        await snapshots.CaptureAsync(world.Admin, world.Scope, world.ProjectId, doc!);
        await snapshots.CaptureAsync(world.Admin, world.Scope, world.ProjectId, doc!);

        Assert.Equal(2, (await snapshots.ListAsync(world.ProjectId)).Count);
    }

    // ---- Export -------------------------------------------------------------

    [SkippableFact]
    public async Task A_viewer_may_not_export()
    {
        Skip.IfNot(_fx.Available);

        var world = await SeedAsync();
        using var scope = _fx.Scope();
        var builder = scope.ServiceProvider.GetRequiredService<SsdfAttestationBuilder>();
        var exporter = scope.ServiceProvider.GetRequiredService<AttestationExporter>();

        var doc = await builder.BuildAsync(world.ProjectId, world.Sha);
        var result = await exporter.ExportAsync(world.Viewer, world.Scope, doc!, AttestationFormat.Json);

        Assert.True(result.WasDenied);
    }

    [SkippableFact]
    public async Task An_auditor_may_export()
    {
        Skip.IfNot(_fx.Available);

        // Export is the auditor's whole job, and the only capability separating
        // an Auditor from a Viewer.
        var world = await SeedAsync();
        using var scope = _fx.Scope();
        var builder = scope.ServiceProvider.GetRequiredService<SsdfAttestationBuilder>();
        var exporter = scope.ServiceProvider.GetRequiredService<AttestationExporter>();

        var doc = await builder.BuildAsync(world.ProjectId, world.Sha);
        var result = await exporter.ExportAsync(world.Auditor, world.Scope, doc!, AttestationFormat.Oscal);

        Assert.True(result.Success);
        Assert.True(result.Value!.Content.Length > 0);
    }

    [SkippableFact]
    public async Task Every_export_is_audited()
    {
        Skip.IfNot(_fx.Available);

        // "Who exported what, when" is a question that gets asked afterwards.
        var world = await SeedAsync();
        using var scope = _fx.Scope();
        var builder = scope.ServiceProvider.GetRequiredService<SsdfAttestationBuilder>();
        var exporter = scope.ServiceProvider.GetRequiredService<AttestationExporter>();
        var db = _fx.Db(scope);

        var doc = await builder.BuildAsync(world.ProjectId, world.Sha);
        await exporter.ExportAsync(world.Admin, world.Scope, doc!, AttestationFormat.Pdf);

        var entry = db.AuditEntries
            .Where(a => a.ProjectId == world.ProjectId && a.Action == "attestation.exported")
            .OrderByDescending(a => a.At)
            .First();

        Assert.Contains("Pdf", entry.Detail!, StringComparison.Ordinal);
        Assert.Contains(world.Sha, entry.Detail!, StringComparison.Ordinal);
    }

    // ---- Seed ---------------------------------------------------------------

    private sealed record World(
        Guid ProjectId, string Sha, Guid PolicyId, ScopeTarget Scope,
        Principal Admin, Principal Auditor, Principal Viewer);

    private async Task<World> SeedAsync()
    {
        using var scope = _fx.Scope();
        var db = _fx.Db(scope);

        var suffix = Guid.NewGuid().ToString("N")[..8];
        var sha = suffix + "dddddd";

        var policy = new RiskPolicy
        {
            Name = $"att-policy-{suffix}",
            Config = Tamp.Findings.Domain.Risk.RiskPolicyDefaults.BuildTampFederalV1(),
        };
        db.RiskPolicies.Add(policy);

        var client = new Client { Name = $"att-client-{suffix}" };
        var project = new Project { ClientId = client.Id, Name = $"att-project-{suffix}", RiskPolicyId = policy.Id };
        var component = new Component { ProjectId = project.Id, Name = $"att-component-{suffix}" };
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
            Login = $"att-{suffix}",
            DisplayName = "Attestation Author",
            Email = $"att-{suffix}@example.test",
            IsApproved = true,
        };
        db.Users.Add(user);

        await db.SaveChangesAsync();

        var target = ScopeTarget.Project(client.Id, project.Id);
        return new World(
            project.Id, sha, policy.Id, target,
            Admin: Principal.For(user.Id, user.Login, isAdmin: true, []),
            Auditor: Principal.For(user.Id, user.Login, isAdmin: false, [ProjectRole.Auditor]),
            Viewer: Principal.For(user.Id, user.Login, isAdmin: false, []));
    }
}
