using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Tamp.Findings.Data;
using Tamp.Findings.Domain.Entities;
using AttestationPage = Tamp.Findings.Web.Components.Pages.Attestation;

namespace Tamp.Findings.Integration.Tests;

/// <summary>Drives the attestation page: freeze, sign, request / decide sign-off, export.</summary>
[Collection(DatabaseCollection.Name)]
public sealed class PageBAttestationInteractionTests(DatabaseFixture fx)
{
    private readonly DatabaseFixture _fx = fx;

    private static Dictionary<string, object?> P(PageBWorld w, string project, string sha) =>
        new() { ["Client"] = w.Client, ["Project"] = project, ["Sha"] = sha };

    private static async Task<List<AttestationSnapshot>> SnapshotsAsync(PageBWorld w, Guid pid)
    {
        using var scope = w.Host.Services.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<FindingsDbContext>();
        return await db.AttestationSnapshots.AsNoTracking().Where(s => s.ProjectId == pid).ToListAsync();
    }

    [SkippableFact]
    public async Task Freeze_then_sign_directly()
    {
        Skip.IfNot(_fx.Available, "TAMP_FINDINGS_TEST_DB not set");
        var w = await PageBWorld.GetAsync(_fx);
        var (name, pid, sha) = await w.NewBuiltProjectAsync("attf");

        await using var live = await PageBRenderHost.RenderAsync<AttestationPage>(w, P(w, name, sha));
        Assert.Contains("LIVE", live.Text);
        Assert.Contains("Nothing is frozen yet", live.Text);
        Assert.True(await live.ClickAsync("Freeze this attestation"));
        Assert.Single(await SnapshotsAsync(w, pid));
        Assert.Contains("SNAPSHOT", live.Text);

        Assert.True(await live.ClickAsync("Record signature"));
        Assert.True(await live.ClickWhereAsync(e => e.Name == "button" && e.Text == "Record signature", 1));   // dialog confirm, blank (refused)
        Assert.True(await live.TypeLabelAsync("Name and title", "Pat Signatory, CISO"));
        Assert.True(await live.ClickWhereAsync(e => e.Name == "button" && e.Text == "Record signature", 1));
        var signed = Assert.Single(await SnapshotsAsync(w, pid));
        Assert.Equal("Pat Signatory, CISO", signed.SignedBy);
        Assert.Contains("signed by", live.Text);
        Assert.Empty(live.Errors);
    }

    [SkippableFact]
    public async Task Sign_off_request_is_approved_or_rejected_by_another_officer()
    {
        Skip.IfNot(_fx.Available, "TAMP_FINDINGS_TEST_DB not set");
        var w = await PageBWorld.GetAsync(_fx);

        foreach (var approve in new[] { true, false })
        {
            var (name, pid, sha) = await w.NewBuiltProjectAsync("atts");
            await using (var admin = await PageBRenderHost.RenderAsync<AttestationPage>(w, P(w, name, sha)))
            {
                Assert.True(await admin.ClickAsync("Freeze this attestation"));
                Assert.True(await admin.ClickAsync("Request sign-off"));
                Assert.True(await admin.TypeLabelAsync("Note to the approver", "please sign this"));
                Assert.True(await admin.ClickAsync("Send request"));
                Assert.Contains("requested sign-off", admin.Text);
                Assert.Contains("please sign this", admin.Text);
            }

            await using var iso = await PageBRenderHost.RenderAsync<AttestationPage>(w, P(w, name, sha), PageBWorld.Iso);
            if (!await iso.ClickAsync(approve ? "Approve & sign" : "Reject")) continue;   // not awaiting this officer
            if (approve)
            {
                Assert.True(await iso.ClickWhereAsync(e => e.Name == "button" && e.Text == "Approve & sign", 1));   // dialog confirm, blank => refused
                Assert.Contains("Sign with your name and title.", iso.Text);
                Assert.True(await iso.TypeLabelAsync("Your name and title", "Ada AO, Authorizing Official"));
                Assert.True(await iso.ClickWhereAsync(e => e.Name == "button" && e.Text == "Approve & sign", 1));
                Assert.NotNull(Assert.Single(await SnapshotsAsync(w, pid)).SignedAt);
            }
            else
            {
                Assert.True(await iso.ClickWhereAsync(e => e.Name == "button" && e.Text == "Reject", 1));
                Assert.Contains("needs a reason", iso.Text);
                Assert.True(await iso.TypeLabelAsync("Reason for rejecting", "Evidence is stale"));
                Assert.True(await iso.ClickWhereAsync(e => e.Name == "button" && e.Text == "Reject", 1));
                Assert.Null(Assert.Single(await SnapshotsAsync(w, pid)).SignedAt);
            }
            Assert.Empty(iso.Errors);
        }
    }

    [SkippableFact]
    public async Task Export_dialog_offers_every_format()
    {
        Skip.IfNot(_fx.Available, "TAMP_FINDINGS_TEST_DB not set");
        var w = await PageBWorld.GetAsync(_fx);
        await using var page = await PageBRenderHost.RenderAsync<AttestationPage>(w, P(w, w.Rich, w.ShaNew));
        foreach (var model in new[] { "Assessment results", "POA&M", "Both — bundle" })
        {
            Assert.True(await page.ClickAsync("Export…"));
            Assert.Contains("OSCAL model", page.Text);
            Assert.True(await page.ClickAsync(model));
            Assert.True(await page.ClickWhereAsync(e => e.Name == "button" && e.Text == "Export"));   // closes the dialog
        }
        var formats = 0;
        for (var i = 0; i < 8; i++)
        {
            Assert.True(await page.ClickAsync("Export…"));
            if (!await page.ClickWhereAsync(e => e.Class.StartsWith("format"), i)) break;
            formats++;
            Assert.True(await page.ClickWhereAsync(e => e.Name == "button" && e.Text == "Export"));
        }
        Assert.True(formats >= 2, "expected several export formats");
        Assert.True(await page.ClickAsync("Export…"));
        Assert.True(await page.ClickAsync("Cancel"));
        Assert.Empty(page.Errors);
    }

    [SkippableFact]
    public async Task Missing_empty_and_hidden_contexts()
    {
        Skip.IfNot(_fx.Available, "TAMP_FINDINGS_TEST_DB not set");
        var w = await PageBWorld.GetAsync(_fx);
        await using var missing = await PageBRenderHost.RenderAsync<AttestationPage>(w, P(w, "nope" + w.Tag, "latest"));
        Assert.Contains("No project matches", missing.Text);

        await using var empty = await PageBRenderHost.RenderAsync<AttestationPage>(w, P(w, w.Empty, w.EmptySha));
        Assert.NotEmpty(empty.Text);
        await using var nobuilds = await PageBRenderHost.RenderAsync<AttestationPage>(w, P(w, w.NoBuilds, "latest"));
        Assert.Contains("NO EVIDENCE", nobuilds.Text);
        Assert.False(await nobuilds.ClickAsync("Freeze this attestation"));   // nothing to freeze

        await using var viewer = await PageBRenderHost.RenderAsync<AttestationPage>(w, P(w, w.Rich, w.ShaNew), PageBWorld.Viewer);
        Assert.NotEmpty(viewer.Text);
        // The seeded newest build is frozen and signed; mid is frozen with a pending sign-off for the admin.
        await using var signed = await PageBRenderHost.RenderAsync<AttestationPage>(w, P(w, w.Rich, w.ShaNew));
        Assert.Contains("Pat Signatory", signed.Text);
        await using var pending = await PageBRenderHost.RenderAsync<AttestationPage>(w, P(w, w.Rich, w.ShaMid));
        Assert.Contains("requested sign-off", pending.Text);
        Assert.True(await pending.ClickAsync("Approve & sign"));
        Assert.True(await pending.ClickAsync("Cancel"));
        Assert.True(await pending.ClickAsync("Reject"));
        Assert.True(await pending.ClickAsync("Cancel"));
    }
}
