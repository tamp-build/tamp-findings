using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Tamp.Findings.Application.Projects;
using Tamp.Findings.Domain.Compliance;
using Tamp.Findings.Domain.Entities;
using Tamp.Findings.Domain.Values;
using Tamp.Findings.Web.Components.Pages;
using ReviewStatus = Tamp.Findings.Domain.Entities.ReviewStatus;

namespace Tamp.Findings.Integration.Tests;

[Collection(DatabaseCollection.Name)]
public class PageAProjectPagesTests
{
    private readonly DatabaseFixture _fx;
    public PageAProjectPagesTests(DatabaseFixture fx) => _fx = fx;

    private async Task<(PageAWorld W, string Sha1, string Sha2)> RichWorldAsync()
    {
        var w = await PageAWorld.SeedAsync(_fx);
        var sha1 = $"{w.S}aaaa1111bbbb";
        var sha2 = $"{w.S}cccc2222dddd";
        await PageAIngest.IngestBuildAsync(_fx, w, sha1, "1.0.0");
        await PageAIngest.IngestBuildAsync(_fx, w, sha2, "1.1.0", full: false);

        using var scope = _fx.Scope();
        var db = _fx.Db(scope);
        var cv = await db.ComponentVersions.FirstAsync(c => c.CommitSha == sha2);
        var framework = await db.Frameworks.FirstAsync();
        await db.Clients.Where(c => c.Id == w.Client.Id).ExecuteUpdateAsync(u => u.SetProperty(c => c.FrameworkId, framework.Id));
        var ids = (await db.ControlCatalogs.Where(c => c.IsCurrent).Select(c => c.Controls).FirstAsync()).Select(c => c.Id).Take(60).ToList();
        await db.Projects.Where(p => p.Id == w.Project.Id).ExecuteUpdateAsync(u => u.SetProperty(p => p.PolicyLayer, new Tamp.Findings.Domain.Risk.PolicyLayer
        {
            Assertions =
            [
                new() { Kind = Tamp.Findings.Domain.Risk.ControlDispositionKind.Gated, ControlIds = ids.Take(7).ToList(), Gates = ["anyCves"] },
                new() { Kind = Tamp.Findings.Domain.Risk.ControlDispositionKind.Inherited, ControlIds = ids.Skip(7).Take(7).ToList(), InheritedFrom = "cloud host", Justification = "provider" },
                new() { Kind = Tamp.Findings.Domain.Risk.ControlDispositionKind.NotApplicable, ControlIds = ids.Skip(14).Take(6).ToList(), Justification = "n/a here" },
            ],
        }));

        db.DecisionDiagnostics.AddRange(
            new DecisionDiagnostic { ComponentVersionId = cv.Id, RuleId = "undocumented-decision:new-dependency", Kind = "new-dependency", Summary = "Added Foo", Location = "src/A.cs:3", CommitSha = sha2 },
            new DecisionDiagnostic { ComponentVersionId = cv.Id, RuleId = "undocumented-decision:new_endpoint", Kind = "new_endpoint", Summary = "POST /x", CommitSha = sha2, ControlRefs = ["CM-3", "SA-8"] });
        db.ConformanceRules.AddRange(
            new ConformanceRule { ProjectId = w.Project.Id, AdrRef = "ADR 0002", RuleId = "auth-boundary", Intent = "One auth boundary", Method = ConformanceMethod.Deterministic, ControlRefs = ["AC-3"], ReviewStatus = ReviewStatus.Draft },
            new ConformanceRule { ProjectId = w.Project.Id, AdrRef = "ADR 0002", RuleId = "no-direct-db", Method = ConformanceMethod.Semantic, ZtPillar = "Data", ZtFunction = "Access", ZtStage = 2, MandateId = "EO-14028", ReviewStatus = ReviewStatus.Reviewed },
            new ConformanceRule { ProjectId = w.Project.Id, AdrRef = "ADR 0005", RuleId = "hosted-workers", Method = ConformanceMethod.Deterministic, ReviewStatus = ReviewStatus.Draft });
        db.ConformanceFindings.Add(new ConformanceFinding
        {
            ComponentVersionId = cv.Id, AdrRef = "ADR 0002", RuleId = "auth-boundary", Claim = "Single boundary",
            Verdict = ConformanceVerdict.Fail, Method = ConformanceMethod.Deterministic, CommitSha = sha2,
        });
        await db.SaveChangesAsync();
        return (w, sha1, sha2);
    }

    [SkippableFact]
    public async Task Project_hub_renders_a_populated_build_latest_and_pinned()
    {
        Skip.IfNot(_fx.Available);
        var (w, sha1, sha2) = await RichWorldAsync();

        await using var h = await PageAHost.ForAsync(_fx, w.Admin, "/c/x/p/y/build/latest");
        var latest = await h.OpenAsync<ProjectHub>(w.Of(w.Project).Concat([("Sha", (object?)"latest")]).ToArray());
        latest.Expect(w.Project.Name);
        latest.Expect("Latest build");
        latest.Expect("Ship gate");
        latest.Expect("Risk");
        latest.Expect("Coverage");

        await using var h2 = await PageAHost.ForAsync(_fx, w.Architect, "/c/x/p/y/build/" + sha1);
        var pinned = await h2.OpenAsync<ProjectHub>(w.Of(w.Project).Concat([("Sha", (object?)sha1)]).ToArray());
        pinned.Expect("Tests passing");

        // A new ingest notifies subscribers; the page reloads without throwing.
        h2.Services.GetRequiredService<BuildUpdateNotifier>().Publish(w.Project.Id);
        h.Services.GetRequiredService<BuildUpdateNotifier>().Publish(w.Project.Id);
        await Task.Delay(2500);
        latest.ThrowIfErrors();
        pinned.ThrowIfErrors();
        pinned.Expect("A newer build");

        // No build / unknown project / read-nothing user.
        await using var h3 = await PageAHost.ForAsync(_fx, w.Admin, "/c/x/p/y/build/latest");
        var empty = await h3.OpenAsync<ProjectHub>(w.Of(w.EmptyProject).Concat([("Sha", (object?)"latest")]).ToArray());
        empty.Expect("No scan");
        var missing = await (await PageAHost.ForAsync(_fx, w.Admin)).OpenAsync<ProjectHub>(
            ("Client", w.Client.Name), ("Project", "missing"), ("Sha", "latest"));
        missing.Expect("Project not found");
    }

    [SkippableFact]
    public async Task Control_coverage_decisions_and_conformance_rules_render_and_review()
    {
        Skip.IfNot(_fx.Available);
        var (w, _, _) = await RichWorldAsync();

        await using var h = await PageAHost.ForAsync(_fx, w.Admin, "/c/x/p/y/coverage");
        var cov = await h.OpenAsync<Tamp.Findings.Web.Components.Pages.ControlCoverage>(w.Of(w.Project));
        cov.Expect("control coverage");
        foreach (var f in new[] { "Unmapped", "Gated", "Inherited", "NotApplicable", "All" })
            await cov.ClickButtonAsync(f);

        await using var h1 = await PageAHost.ForAsync(_fx, w.Admin, "/c/x/p/y/coverage");
        var noFw = await h1.OpenAsync<Tamp.Findings.Web.Components.Pages.ControlCoverage>(w.Of(w.EmptyProject));
        noFw.Expect("No framework");
        var missingCov = await (await PageAHost.ForAsync(_fx, w.Admin)).OpenAsync<Tamp.Findings.Web.Components.Pages.ControlCoverage>(("Client", w.Client.Name), ("Project", "zzz"));
        missingCov.Expect("Project not found");

        await using var h2 = await PageAHost.ForAsync(_fx, w.Admin, "/c/x/p/y/decisions");
        var dec = await h2.OpenAsync<Decisions>(w.Of(w.Project));
        dec.Expect("Added Foo");
        dec.Expect("write an ADR");
        await using var h2b = await PageAHost.ForAsync(_fx, w.Admin, "/c/x/p/y/decisions");
        (await h2b.OpenAsync<Decisions>(w.Of(w.EmptyProject))).Expect("Not examined");
        (await (await PageAHost.ForAsync(_fx, w.Admin)).OpenAsync<Decisions>(("Client", w.Client.Name), ("Project", "zzz"))).Expect("Project not found");

        await using var h3 = await PageAHost.ForAsync(_fx, w.Admin, "/c/x/p/y/conformance-rules");
        var rules = await h3.OpenAsync<ConformanceRules>(w.Of(w.Project));
        rules.Expect("auth-boundary");
        rules.Expect("mandate: EO-14028");
        await rules.ClickButtonAsync("Mark reviewed");
        await rules.ClickButtonAsync("Revert to draft");
        await rules.ClickButtonAsync("Review 1 draft");
        await rules.ClickButtonAsync("Review all");
        (await (await PageAHost.ForAsync(_fx, w.Admin)).OpenAsync<ConformanceRules>(("Client", w.Client.Name), ("Project", "zzz"))).Expect("Project not found");

        await using var h4 = await PageAHost.ForAsync(_fx, w.Admin, "/c/x/p/y/conformance-rules");
        (await h4.OpenAsync<ConformanceRules>(w.Of(w.EmptyProject))).Expect("No conformance rules");

        // A non-privileged reader sees the rules but cannot act on them.
        await using var h5 = await PageAHost.ForAsync(_fx, w.Nobody, "/c/x/p/y/conformance-rules");
        var ro = await h5.OpenAsync<ConformanceRules>(w.Of(w.Project));
        ro.ThrowIfErrors();
    }
}
