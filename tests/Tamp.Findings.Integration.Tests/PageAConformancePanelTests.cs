using Microsoft.AspNetCore.Components;
using Microsoft.Extensions.DependencyInjection;
using Tamp.Findings.Application.Compliance;
using Tamp.Findings.Domain.Compliance;
using Tamp.Findings.Domain.Entities;
using Tamp.Findings.Domain.Values;
using Tamp.Findings.Web.Components.Compliance;

namespace Tamp.Findings.Integration.Tests;

[Collection(DatabaseCollection.Name)]
public class PageAConformancePanelTests
{
    private readonly DatabaseFixture _fx;
    public PageAConformancePanelTests(DatabaseFixture fx) => _fx = fx;

    [SkippableFact]
    public async Task Conformance_panel_lists_verdicts_filters_by_control_and_accepts_risk()
    {
        Skip.IfNot(_fx.Available);
        var w = await PageAWorld.SeedAsync(_fx);
        var infosec = PageAHarness.NewUser("i" + w.S, admin: false);
        using (var scope = _fx.Scope())
        {
            var db = _fx.Db(scope);
            db.Users.Add(infosec);
            db.ProjectRoleAssignments.Add(new ProjectRoleAssignment { UserId = infosec.Id, Role = ProjectRole.InfoSecOfficer, ClientId = w.Client.Id });

            ConformanceFinding F(Guid cvId, string rule, ConformanceVerdict v, ConformanceMethod m, params string[] controls) => new()
            {
                ComponentVersionId = cvId, AdrRef = "ADR 0002", RuleId = rule, Claim = "claim " + rule, Verdict = v, Method = m,
                CommitSha = w.Cv2.CommitSha, RulesSha = "rules123", ModelId = m == ConformanceMethod.Semantic ? "claude-x" : null,
                ControlRefs = [.. controls], Location = "src/A.cs:1",
                AdrQuote = v == ConformanceVerdict.Fail ? "the ADR says X" : null,
                CodeEvidence = v == ConformanceVerdict.Fail ? "var x = Y;" : null,
                VerifyVerdict = m == ConformanceMethod.Semantic ? VerifyOutcome.Disputed : VerifyOutcome.NotRun,
            };
            // Findings on every build of the project, so "latest" resolves whichever way builds are ordered.
            foreach (var cvId in new[] { w.Cv.Id, w.Cv2.Id })
            {
                var disp = F(cvId, "r-disp", ConformanceVerdict.Fail, ConformanceMethod.Deterministic, "SC-8");
                disp.Dispositioned = true;
                disp.DispositionJustification = "accepted for now";
                disp.DispositionedByLogin = "boss";
                disp.DispositionExpiry = DateTimeOffset.UtcNow.AddDays(30);
                db.ConformanceFindings.AddRange(
                    F(cvId, "r-pass", ConformanceVerdict.Pass, ConformanceMethod.Deterministic, "AC-3"),
                    F(cvId, "r-fail", ConformanceVerdict.Fail, ConformanceMethod.Semantic, "AC-3", "CM-6"),
                    F(cvId, "r-fail2", ConformanceVerdict.Fail, ConformanceMethod.Deterministic, "CM-6"),
                    F(cvId, "r-unknown", ConformanceVerdict.Unknown, ConformanceMethod.Deterministic),
                    F(cvId, "r-error", ConformanceVerdict.Error, ConformanceMethod.Deterministic),
                    disp);
            }
            await db.SaveChangesAsync();
        }

        ConformanceReport report;
        using (var scope = _fx.Scope())
            report = (await scope.ServiceProvider.GetRequiredService<ConformanceQuery>().ForProjectAsync(w.Project.Id, null))!;

        var changed = 0;
        var args = new (string, object?)[]
        {
            ("Report", report), ("ClientId", w.Client.Id), ("ProjectId", w.Project.Id),
            ("OnChanged", EventCallback.Factory.Create(this, () => { changed++; })),
        };

        await using var h = await PageAHost.ForAsync(_fx, infosec, "/");
        var page = await h.OpenAsync<ConformancePanel>(args);
        page.Expect("claim r-fail");
        page.Expect("the ADR says X");
        page.Expect("disputed");
        page.Expect("Dispositioned with justification");
        page.Expect("re-anchor");
        page.Expect("Evaluation broke");
        await page.ClickRowAsync("button", "CM-6");
        page.Expect("claim r-fail2");
        await page.ClickRowAsync("button", "clear filter");
        await page.ClickRowAsync("button", "CM-6");
        await page.ClickRowAsync("button", "CM-6");

        // Accept risk: blank justification, bad date, then success.
        await page.ClickButtonAsync("Accept risk…");
        await page.ClickButtonAsync("Accept risk");
        page.Expect("justification is required");
        await page.TypeAsync("Justification", "compensating control in place");
        await page.TypeAsync("Expiry", "nonsense");
        await page.ClickButtonAsync("Accept risk");
        page.Expect("not a valid date");
        await page.TypeAsync("Expiry", DateTime.UtcNow.AddDays(10).ToString("yyyy-MM-dd"));
        await page.ClickButtonAsync("Accept risk");
        Assert.Equal(1, changed);

        // A user without AcceptRisk is refused by the service.
        await using var h2 = await PageAHost.ForAsync(_fx, w.Lead, "/");
        var denied = await h2.OpenAsync<ConformancePanel>(args);
        await denied.ClickButtonAsync("Accept risk…");
        await denied.TypeAsync("Justification", "because");
        await denied.ClickButtonAsync("Accept risk");
        await denied.ClickButtonAsync("Cancel");

        // An empty report renders just the run line.
        var empty = report with { Findings = [], ControlCounts = new Dictionary<string, int>(), Dispositioned = 0, CommitSha = null, RulesSha = null };
        await using var h3 = await PageAHost.ForAsync(_fx, infosec, "/");
        (await h3.OpenAsync<ConformancePanel>(("Report", empty))).Expect("conformance.evaluated");
    }
}
