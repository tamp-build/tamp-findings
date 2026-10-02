using System.Net;
using Tamp.Findings.Web.Routing;

namespace Tamp.Findings.Integration.Tests;

[Collection(DatabaseCollection.Name)]
public sealed class PageBEvidenceTests(DatabaseFixture fx)
{
    private readonly DatabaseFixture _fx = fx;

    [SkippableFact]
    public async Task Every_evidence_key_renders_with_seeded_data()
    {
        Skip.IfNot(_fx.Available, "TAMP_FINDINGS_TEST_DB not set");
        var w = await PageBWorld.GetAsync(_fx);
        foreach (var sha in new[] { w.ShaNew, w.ShaMid, "latest" })
        foreach (var key in EvidenceKeys.All)
        {
            var (status, body) = await w.GetAsync(w.Build(sha, "evidence/" + key));
            Assert.Equal(HttpStatusCode.OK, status);
            Assert.Contains($">{key}<", body);
        }
    }

    [SkippableFact]
    public async Task Evidence_pages_show_the_seeded_facts()
    {
        Skip.IfNot(_fx.Available, "TAMP_FINDINGS_TEST_DB not set");
        var w = await PageBWorld.GetAsync(_fx);

        var (_, dast) = await w.GetAsync(w.Build(w.ShaNew, "evidence/dast"));
        Assert.Contains("Cross site scripting", dast);

        var (_, a11y) = await w.GetAsync(w.Build(w.ShaNew, "evidence/a11y"));
        Assert.Contains("color-contrast", a11y);

        var (_, kev) = await w.GetAsync(w.Build(w.ShaNew, "evidence/kev"));
        Assert.Contains(PageBWorld.KevCve(w.Tag), kev);

        var (_, img) = await w.GetAsync(w.Build(w.ShaNew, "evidence/baseImage"));
        Assert.Contains("ghcr.io/acme/app", img);

        var (_, quality) = await w.GetAsync(w.Build(w.ShaNew, "evidence/quality"));
        Assert.Contains("new_coverage", quality);

        var (_, poam) = await w.GetAsync(w.Build(w.ShaNew, "evidence/poam"));
        Assert.Contains("PastDue SQLi remediation", poam);

        var (_, vex) = await w.GetAsync(w.Build(w.ShaNew, "evidence/vex"));
        Assert.Contains("GHSA-5crp-9r3c-p9vr", vex);

        var (_, conf) = await w.GetAsync(w.Build(w.ShaNew, "evidence/conformance"));
        Assert.Contains("auth-boundary-single", conf);
    }

    [SkippableFact]
    public async Task Evidence_pages_render_for_a_build_with_no_evidence()
    {
        Skip.IfNot(_fx.Available, "TAMP_FINDINGS_TEST_DB not set");
        var w = await PageBWorld.GetAsync(_fx);
        foreach (var key in EvidenceKeys.All)
        {
            var (status, body) = await w.GetAsync($"/c/{w.Client}/p/{w.Empty}/build/{w.EmptySha}/evidence/{key}");
            Assert.Equal(HttpStatusCode.OK, status);
            Assert.Contains($">{key}<", body);
            var (s2, _) = await w.GetAsync($"/c/{w.Client}/p/{w.Empty}/build/latest/evidence/{key}");
            Assert.Equal(HttpStatusCode.OK, s2);
        }
    }

    [SkippableFact]
    public async Task Evidence_for_unknown_project_or_hidden_from_viewer_says_so()
    {
        Skip.IfNot(_fx.Available, "TAMP_FINDINGS_TEST_DB not set");
        var w = await PageBWorld.GetAsync(_fx);
        var (s1, b1) = await w.GetAsync($"/c/{w.Client}/p/nope-{w.Tag}/build/latest/evidence/dast");
        Assert.Equal(HttpStatusCode.OK, s1);
        Assert.Contains("No project", b1);

        foreach (var who in new[] { PageBWorld.Viewer, PageBWorld.Lead })
        foreach (var key in EvidenceKeys.All)
        {
            var (s, _) = await w.GetAsync(w.Build(w.ShaNew, "evidence/" + key), who);
            Assert.Equal(HttpStatusCode.OK, s);
        }

        var (s3, b3) = await w.GetAsync($"/c/{w.Client}/p/{w.NoBuilds}/build/latest/evidence/vex");
        Assert.Equal(HttpStatusCode.OK, s3);
        Assert.NotEmpty(b3);
    }
}
