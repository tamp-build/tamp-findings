using System.Net;
using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using Tamp.Findings.Domain.Entities;
using Tamp.Findings.Domain.Risk;
using Tamp.Findings.Domain.Values;
using static Tamp.Findings.Integration.Tests.ApiAHarness;

namespace Tamp.Findings.Integration.Tests;

// GET /aggregates — the hierarchy ring roll-up. One huge handler with scope
// variants (all / client / project), latest on/off, canonical-only version
// selection, VEX suppression and scanner-override handling.
[Collection(DatabaseCollection.Name)]
public class ApiAAggregatesTests
{
    private readonly DatabaseFixture _fx;
    public ApiAAggregatesTests(DatabaseFixture fx) => _fx = fx;

    private sealed record World(
        Tree Tree, Guid Admin, Guid CvOld, Guid CvNew, Guid CvLinux, Guid CvPr,
        string KevCve, string VexCve, Guid VexVulnId);

    private static JsonElement P(JsonElement e, params string[] path)
    {
        foreach (var p in path) e = e.GetProperty(p);
        return e;
    }

    private static int Sev(JsonElement counts, string name) => counts.GetProperty(name).GetInt32();

    private async Task<World> SeedAsync(bool withVex = false)
    {
        var admin = await UserAsync(_fx, admin: true);
        var tree = await ClientProjectAsync(_fx);
        var now = DateTimeOffset.UtcNow;
        var s = Sfx();

        var cvOld = await VersionAsync(_fx, tree.ProjectId, $"1.0.{s}", createdAt: now.AddDays(-5));
        var cvNew = await VersionAsync(_fx, tree.ProjectId, $"2.0.{s}", createdAt: now.AddHours(-1));
        var cvLinux = await VersionAsync(_fx, tree.ProjectId, $"2.0.{s}-linux", flavor: "linux", createdAt: now.AddDays(-1));
        var cvPr = await VersionAsync(_fx, tree.ProjectId, $"2.1.{s}-pr", branch: "feature/x", pr: "refs/pull/7/merge", createdAt: now);

        await AddFindingsAsync(_fx,
            // superseded build — only visible with latest=false
            NewFinding(cvOld, ScannerKind.Roslyn, Severity.Critical, "OLD1"),
            NewFinding(cvOld, ScannerKind.Roslyn, Severity.Critical, "OLD1"),
            // current canonical build
            NewFinding(cvNew, ScannerKind.Roslyn, Severity.High, "CA1"),
            NewFinding(cvNew, ScannerKind.Roslyn, Severity.High, "CA1"),
            NewFinding(cvNew, ScannerKind.Roslyn, Severity.Low, "CA1"),
            NewFinding(cvNew, ScannerKind.Roslyn, Severity.Medium, "CA2", FindingStatus.Suppressed),
            NewFinding(cvNew, ScannerKind.OpenGrep, Severity.Critical, "OG1"),
            NewFinding(cvNew, ScannerKind.OpenGrep, Severity.Medium, "OG2"),
            NewFinding(cvNew, ScannerKind.OpenGrep, Severity.Low, "OG3", FindingStatus.Fixed),
            NewFinding(cvNew, ScannerKind.ESLint, Severity.High, "ES1"),
            NewFinding(cvNew, ScannerKind.ESLint, Severity.Info, "ES2", FindingStatus.Accepted),
            NewFinding(cvNew, ScannerKind.Nuclei, Severity.High, "Z1"),
            NewFinding(cvNew, ScannerKind.Nuclei, Severity.Medium, "Z2"),
            NewFinding(cvNew, ScannerKind.Trivy, Severity.High, "T1"),                                  // null sub-category (legacy => IaC)
            NewFinding(cvNew, ScannerKind.Trivy, Severity.Critical, "T2", subCategory: "misconfiguration"),
            NewFinding(cvNew, ScannerKind.Trivy, Severity.High, "T3", subCategory: "secret"),
            NewFinding(cvNew, ScannerKind.Trivy, Severity.High, "T4", subCategory: "vulnerability"),
            NewFinding(cvNew, ScannerKind.TruffleHog, Severity.Critical, "TH1"),
            NewFinding(cvNew, ScannerKind.TruffleHog, Severity.High, "TH2"),
            // second flavor — its own "latest"
            NewFinding(cvLinux, ScannerKind.OpenGrep, Severity.High, "OG4"),
            // PR build — never canonical
            NewFinding(cvPr, ScannerKind.OpenGrep, Severity.Critical, "OGPR"));

        var kev = Cve();
        var vex = Cve() + "9";
        var old = now.AddDays(-400);
        var sbom = await SbomAsync(_fx, cvNew, now,
            ($"pkg:nuget/Alpha{s}", "1.0.0", "MIT", null, null, [(kev, Severity.Critical), (vex, Severity.High)]),
            ($"pkg:npm/bravo{s}", "2.0.0", "LGPL-2.1", "3.0.0", old, []),
            ($"pkg:npm/charlie{s}", "1.0.0", "GPL-2.0", "1.1.0", now.AddDays(-10), []),
            ($"pkg:nuget/Delta{s}", "1.0.0", null, "1.0.0", null, []),
            ($"pkg:pypi/echo{s}", "1.0.0", "GPL-3.0", null, null, []),
            ($"pkg:nuget/Foxtrot{s}", "1.0.0", "MIT", null, null, []));
        await SbomAsync(_fx, cvLinux, now.AddDays(-1),
            ($"pkg:npm/golf{s}", "1.0.0", "Apache-2.0", null, null, []));
        await SbomAsync(_fx, cvOld, now.AddDays(-5),
            ($"pkg:nuget/Legacy{s}", "0.1.0", "MIT", null, null, []));

        using (var scope = _fx.Scope())
        {
            var db = _fx.Db(scope);
            db.KevAdvisories.Add(new KevAdvisory { CveId = kev, VendorProject = "v", Product = "p" });
            if (withVex)
                db.VexStatements.Add(new VexStatement
                {
                    ProjectId = tree.ProjectId, Purl = $"pkg:nuget/Alpha{s}", AdvisoryId = vex,
                    Status = VexStatementStatus.NotAffected, Justification = VexJustification.ComponentNotPresent,
                    AuthorUserId = admin,
                });
            // coverage: two reports in the latest set + one on the superseded build
            db.CoverageReports.AddRange(
                new CoverageReport
                {
                    ComponentVersionId = cvNew, ToolName = "Coverlet", SequenceCoverage = 80, BranchCoverage = 80,
                    CoveredSequences = 80, TotalSequences = 100, CoveredBranches = 40, TotalBranches = 50,
                    Modules =
                    [
                        new CoverageModule { Name = "Mod.A", CoveredSequences = 30, TotalSequences = 50 },
                        new CoverageModule { Name = "Mod.B", CoveredSequences = 50, TotalSequences = 50 },
                        new CoverageModule { Name = "Mod.Empty", CoveredSequences = 0, TotalSequences = 0 },
                    ],
                },
                new CoverageReport
                {
                    ComponentVersionId = cvLinux, ToolName = "Coverlet", SequenceCoverage = 40, BranchCoverage = 20,
                    CoveredSequences = 40, TotalSequences = 100, CoveredBranches = 10, TotalBranches = 50,
                    Modules = [new CoverageModule { Name = "mod.a", CoveredSequences = 10, TotalSequences = 50 }],
                },
                new CoverageReport
                {
                    ComponentVersionId = cvOld, ToolName = "Coverlet", SequenceCoverage = 10, BranchCoverage = 10,
                    CoveredSequences = 10, TotalSequences = 100, CoveredBranches = 5, TotalBranches = 50,
                });
            db.TestRunReports.Add(new TestRunReport
            {
                ComponentVersionId = cvNew, ToolName = "trx", TotalCount = 10, PassedCount = 8, FailedCount = 2,
                StartedAt = now.AddMinutes(-5), CompletedAt = now,
            });
            await db.SaveChangesAsync();
        }

        await AddScanRunAsync(_fx, cvLinux, ScannerKind.OpenGrep, ScanRunStatus.Failed, now.AddHours(-2), 0);
        await AddScanRunAsync(_fx, cvNew, ScannerKind.OpenGrep, ScanRunStatus.Succeeded, now.AddHours(-1), 3);
        await AddScanRunAsync(_fx, cvNew, ScannerKind.Trivy, ScanRunStatus.Succeeded, now, 4);
        await AddScanRunAsync(_fx, cvNew, ScannerKind.TruffleHog, ScanRunStatus.Succeeded, now, 2);
        await AddScanRunAsync(_fx, cvNew, ScannerKind.Nuclei, ScanRunStatus.Succeeded, now, 2);
        await AddScanRunAsync(_fx, cvNew, ScannerKind.Syft, ScanRunStatus.Skipped, now, 0);

        return new World(tree, admin, cvOld, cvNew, cvLinux, cvPr, kev, vex, sbom.VulnIds[vex]);
    }

    [SkippableFact]
    public async Task Project_scope_latest_rolls_up_only_current_canonical_builds()
    {
        Skip.IfNot(_fx.Available);
        var w = await SeedAsync();
        var http = Http(_fx, w.Admin);

        var r = await GetJsonAsync(http, $"/aggregates?projectId={w.Tree.ProjectId}");

        Assert.Equal("Project", P(r, "scope", "level").GetString());
        Assert.Equal($"{w.Tree.ClientName} / {w.Tree.ProjectName}", P(r, "scope", "label").GetString());
        Assert.Equal(w.Tree.ClientName, P(r, "scope", "clientName").GetString());

        var counts = P(r, "findings", "counts");
        Assert.Equal(0, Sev(counts, "info"));
        Assert.Equal(1, Sev(counts, "low"));
        Assert.Equal(2, Sev(counts, "medium"));
        Assert.Equal(9, Sev(counts, "high"));
        Assert.Equal(3, Sev(counts, "critical"));

        var byScanner = P(r, "findings", "byScanner");
        Assert.Equal(3, byScanner.GetProperty("Roslyn").GetInt32());
        Assert.Equal(3, byScanner.GetProperty("OpenGrep").GetInt32());   // OG1, OG2 + linux OG4
        Assert.Equal(4, byScanner.GetProperty("Trivy").GetInt32());
        Assert.Equal(2, byScanner.GetProperty("TruffleHog").GetInt32());

        var byStatus = P(r, "findings", "byStatus");
        Assert.Equal(15, byStatus.GetProperty("Open").GetInt32());
        Assert.Equal(1, byStatus.GetProperty("Fixed").GetInt32());
        Assert.Equal(1, byStatus.GetProperty("Suppressed").GetInt32());
        Assert.Equal(1, byStatus.GetProperty("Accepted").GetInt32());

        var detail = P(r, "findings", "byScannerDetail").EnumerateArray().ToList();
        var names = detail.Select(d => d.GetProperty("scanner").GetString()).ToList();
        Assert.Equal(names.OrderBy(n => n, StringComparer.Ordinal).ToList(), names);
        var og = detail.Single(d => d.GetProperty("scanner").GetString() == "OpenGrep");
        Assert.Equal(1, og.GetProperty("closed").GetInt32());
        Assert.Equal(1, Sev(og.GetProperty("open"), "critical"));
        var ro = detail.Single(d => d.GetProperty("scanner").GetString() == "Roslyn");
        Assert.Equal(1, ro.GetProperty("suppressed").GetInt32());
        var es = detail.Single(d => d.GetProperty("scanner").GetString() == "ESLint");
        Assert.Equal(1, es.GetProperty("accepted").GetInt32());

        var rules = P(r, "findings", "byRule").EnumerateArray().ToList();
        Assert.Equal("CA1", rules[0].GetProperty("ruleId").GetString());   // most frequent first
        Assert.Equal(3, rules[0].GetProperty("count").GetInt32());
        Assert.Equal("High", rules[0].GetProperty("severity").GetString());
        Assert.DoesNotContain(rules, x => x.GetProperty("ruleId").GetString() is "OLD1" or "OGPR" or "OG3");

        // SBOM half — latest snapshot per (project, flavor)
        Assert.Equal(7, P(r, "sbom", "componentsCount").GetInt32());
        Assert.Equal(2, P(r, "sbom", "vulnerabilitiesCount").GetInt32());
        Assert.Equal(3, P(r, "sbom", "byEcosystem", "nuget").GetInt32());
        Assert.Equal(3, P(r, "sbom", "byEcosystem", "npm").GetInt32());
        Assert.Equal(1, P(r, "sbom", "byEcosystem", "other").GetInt32());
        Assert.Equal(1, P(r, "sbom", "health", "vulnerable").GetInt32());
        Assert.Equal(2, P(r, "sbom", "health", "outdated").GetInt32());
        Assert.Equal(1, P(r, "sbom", "health", "stale").GetInt32());
        Assert.Equal(4, P(r, "sbom", "health", "current").GetInt32());

        // Licenses
        var tiers = P(r, "licenses", "tiers");
        Assert.Equal(3, tiers.GetProperty("permissive").GetInt32());
        Assert.Equal(1, tiers.GetProperty("weakCopyleft").GetInt32());
        Assert.Equal(1, tiers.GetProperty("strongCopyleft").GetInt32());
        Assert.Equal(1, tiers.GetProperty("denied").GetInt32());
        Assert.Equal(1, tiers.GetProperty("unknown").GetInt32());
        Assert.Equal(2, P(r, "licenses", "byLicense", "MIT").GetInt32());
        Assert.Equal(1, P(r, "licenses", "byLicense", "(unknown)").GetInt32());

        // Secrets: TruffleHog + Trivy(secret)
        Assert.Equal(1, P(r, "secrets", "health", "verified").GetInt32());
        Assert.Equal(2, P(r, "secrets", "health", "unverified").GetInt32());

        // IaC: Trivy null/misconfiguration only
        Assert.Equal(1, Sev(P(r, "iac", "counts"), "high"));
        Assert.Equal(1, Sev(P(r, "iac", "counts"), "critical"));
        Assert.True(P(r, "iac", "scanned").GetBoolean());

        // Coverage: two latest reports (200 seq / 100 branches), old build ignored
        var cov = P(r, "coverage");
        Assert.True(cov.GetProperty("measured").GetBoolean());
        Assert.Equal(200, cov.GetProperty("totalSequences").GetInt32());
        Assert.Equal(120, cov.GetProperty("coveredSequences").GetInt32());
        Assert.Equal(60.0, cov.GetProperty("sequenceCoverage").GetDouble(), 3);
        Assert.Equal(50.0, cov.GetProperty("branchCoverage").GetDouble(), 3);
        var mods = cov.GetProperty("modules").EnumerateArray().ToList();
        Assert.Equal(3, mods.Count);                                   // Mod.A+mod.a merged case-insensitively
        Assert.Equal(0.0, mods[0].GetProperty("sequenceCoverage").GetDouble());   // worst first (empty module = 0)
        Assert.Equal("mod.a", mods[1].GetProperty("name").GetString(), ignoreCase: true);
        Assert.Equal(40.0, mods[1].GetProperty("sequenceCoverage").GetDouble(), 3);
        Assert.Equal(100.0, mods[2].GetProperty("sequenceCoverage").GetDouble(), 3);

        // Scan runs: one per scanner, latest wins, ordered by name
        var runs = P(r, "scanRuns").EnumerateArray().ToList();
        Assert.Equal("Nuclei,OpenGrep,Syft,Trivy,TruffleHog",
            string.Join(",", runs.Select(x => x.GetProperty("scanner").GetString())));
        Assert.Equal("Succeeded", runs[1].GetProperty("status").GetString());
        Assert.Equal(3, runs[1].GetProperty("findingsCount").GetInt32());
        Assert.Equal("Skipped", runs[2].GetProperty("status").GetString());

        // Risk score present, with a breakdown
        var risk = P(r, "risk");
        Assert.Equal(JsonValueKind.Object, risk.ValueKind);
        Assert.InRange(risk.GetProperty("score").GetDouble(), 0, 100);
        Assert.Contains(risk.GetProperty("band").GetString(), new[] { "green", "yellow", "orange", "red" });
        Assert.True(risk.GetProperty("breakdown").GetArrayLength() > 0);
    }

    [SkippableFact]
    public async Task Latest_false_includes_superseded_flavored_and_pull_request_builds()
    {
        Skip.IfNot(_fx.Available);
        var w = await SeedAsync();
        var http = Http(_fx, w.Admin);

        var r = await GetJsonAsync(http, $"/aggregates?projectId={w.Tree.ProjectId}&latest=false");

        var counts = P(r, "findings", "counts");
        Assert.Equal(6, Sev(counts, "critical"));        // 3 + 2 OLD1 + OGPR
        Assert.Equal(9, Sev(counts, "high"));
        Assert.Equal(8, P(r, "sbom", "componentsCount").GetInt32());   // + the superseded snapshot's component
        Assert.Equal(300, P(r, "coverage", "totalSequences").GetInt32());   // + the old report
    }

    [SkippableFact]
    public async Task Client_scope_sums_every_project_under_the_client()
    {
        Skip.IfNot(_fx.Available);
        var w = await SeedAsync();
        var second = await ClientProjectAsync(_fx, w.Tree.ClientId, w.Tree.ClientName);
        var cv = await VersionAsync(_fx, second.ProjectId, "1.0.0-" + Sfx(), branch: null);
        await AddFindingsAsync(_fx, NewFinding(cv, ScannerKind.CodeQL, Severity.Critical, "CQ1"));
        var http = Http(_fx, w.Admin);

        var r = await GetJsonAsync(http, $"/aggregates?clientId={w.Tree.ClientId}");

        Assert.Equal("Client", P(r, "scope", "level").GetString());
        Assert.Equal(w.Tree.ClientName, P(r, "scope", "label").GetString());
        Assert.Equal(JsonValueKind.Null, P(r, "scope", "projectName").ValueKind);
        Assert.Equal(4, Sev(P(r, "findings", "counts"), "critical"));   // 3 + the new project's
        Assert.Equal(1, P(r, "findings", "byScanner", "CodeQL").GetInt32());
    }

    [SkippableFact]
    public async Task Unscoped_and_unknown_scope_fall_back_to_the_All_label()
    {
        Skip.IfNot(_fx.Available);
        var admin = await UserAsync(_fx, admin: true);
        var http = Http(_fx, admin);

        var all = await GetJsonAsync(http, "/aggregates");
        Assert.Equal("All", P(all, "scope", "level").GetString());
        Assert.Equal("All", P(all, "scope", "label").GetString());

        // A project id that matches nothing resolves to "All" for the label but filters to zero rows.
        var ghost = await GetJsonAsync(http, $"/aggregates?projectId={Guid.NewGuid()}");
        Assert.Equal("All", P(ghost, "scope", "level").GetString());
        Assert.Equal(0, P(ghost, "findings", "counts", "critical").GetInt32());
        Assert.Equal(JsonValueKind.Null, P(ghost, "risk").ValueKind);

        var ghostClient = await GetJsonAsync(http, $"/aggregates?clientId={Guid.NewGuid()}&latest=false");
        Assert.Equal("All", P(ghostClient, "scope", "level").GetString());
        Assert.False(P(ghostClient, "coverage", "measured").GetBoolean());

        // componentId is accepted for compatibility but does not narrow.
        var comp = await http.GetAsync($"/aggregates?componentId={Guid.NewGuid()}");
        Assert.Equal(HttpStatusCode.OK, comp.StatusCode);
    }

    [SkippableFact]
    public async Task An_empty_project_has_no_risk_score_and_unmeasured_coverage()
    {
        Skip.IfNot(_fx.Available);
        var admin = await UserAsync(_fx, admin: true);
        var tree = await ClientProjectAsync(_fx);
        var http = Http(_fx, admin);

        var r = await GetJsonAsync(http, $"/aggregates?projectId={tree.ProjectId}");

        Assert.Equal(JsonValueKind.Null, P(r, "risk").ValueKind);
        Assert.False(P(r, "coverage", "measured").GetBoolean());
        Assert.Equal(JsonValueKind.Null, P(r, "coverage", "sequenceCoverage").ValueKind);
        Assert.Equal(0, P(r, "sbom", "componentsCount").GetInt32());
        Assert.Equal(0, P(r, "scanRuns").GetArrayLength());
        Assert.Equal(0, P(r, "findings", "byRule").GetArrayLength());
    }

    [SkippableFact]
    public async Task Coverage_reports_with_zero_totals_report_zero_percent_not_a_division_error()
    {
        Skip.IfNot(_fx.Available);
        var admin = await UserAsync(_fx, admin: true);
        var tree = await ClientProjectAsync(_fx);
        var cv = await VersionAsync(_fx, tree.ProjectId, "1.0." + Sfx(), branch: null);
        using (var scope = _fx.Scope())
        {
            var db = _fx.Db(scope);
            db.CoverageReports.Add(new CoverageReport { ComponentVersionId = cv, ToolName = "Coverlet" });
            await db.SaveChangesAsync();
        }

        var r = await GetJsonAsync(Http(_fx, admin), $"/aggregates?projectId={tree.ProjectId}");

        Assert.True(P(r, "coverage", "measured").GetBoolean());
        Assert.Equal(0.0, P(r, "coverage", "sequenceCoverage").GetDouble());
        Assert.Equal(0.0, P(r, "coverage", "branchCoverage").GetDouble());
        Assert.NotEqual(JsonValueKind.Null, P(r, "risk").ValueKind);   // coverage alone is evidence
    }

    [SkippableFact]
    public async Task A_vex_statement_removes_the_cve_from_the_score_but_not_from_the_display_count()
    {
        Skip.IfNot(_fx.Available);
        var w = await SeedAsync();
        var http = Http(_fx, w.Admin);

        var before = await GetJsonAsync(http, $"/aggregates?projectId={w.Tree.ProjectId}");
        var scoreBefore = P(before, "risk", "score").GetDouble();

        using (var scope = _fx.Scope())
        {
            var db = _fx.Db(scope);
            var vulnPurl = await db.Vulnerabilities.Where(v => v.Id == w.VexVulnId).Select(v => v.SbomComponent!.Purl).SingleAsync();
            db.VexStatements.Add(new VexStatement
            {
                ProjectId = w.Tree.ProjectId, Purl = vulnPurl[..vulnPurl.LastIndexOf('@')], AdvisoryId = w.VexCve,
                Status = VexStatementStatus.Fixed, AuthorUserId = w.Admin,
            });
            await db.SaveChangesAsync();
        }

        var after = await GetJsonAsync(http, $"/aggregates?projectId={w.Tree.ProjectId}");
        Assert.True(P(after, "risk", "score").GetDouble() <= scoreBefore);
        Assert.Equal(2, P(after, "sbom", "vulnerabilitiesCount").GetInt32());

        // Client scope deliberately ignores project-owned VEX dispositions.
        var client = await GetJsonAsync(http, $"/aggregates?clientId={w.Tree.ClientId}");
        Assert.Equal(JsonValueKind.Object, P(client, "risk").ValueKind);
    }

    [SkippableFact]
    public async Task Scanner_severity_ceilings_in_the_assigned_policy_lower_the_score_not_the_counts()
    {
        Skip.IfNot(_fx.Available);
        var w = await SeedAsync();
        var s = Sfx();
        Guid plainId, cappedId;
        using (var scope = _fx.Scope())
        {
            var db = _fx.Db(scope);
            var plain = new RiskPolicy { Name = $"apia-plain-{s}", Config = RiskPolicyDefaults.BuildTampStandardV1() };
            var capped = new RiskPolicy { Name = $"apia-capped-{s}", Config = RiskPolicyDefaults.BuildTampStandardV1() };
            foreach (var sk in new[] { "Roslyn", "OpenGrep", "ESLint", "Nuclei", "Trivy" })
                capped.Config.ScannerOverrides[sk] = new ScannerOverride { SeverityCeiling = Severity.Low };
            db.RiskPolicies.AddRange(plain, capped);
            var project = await db.Projects.SingleAsync(p => p.Id == w.Tree.ProjectId);
            project.RiskPolicyId = plain.Id;
            await db.SaveChangesAsync();
            (plainId, cappedId) = (plain.Id, capped.Id);
        }
        var http = Http(_fx, w.Admin);

        var r1 = await GetJsonAsync(http, $"/aggregates?projectId={w.Tree.ProjectId}");
        Assert.Equal(plainId, P(r1, "risk", "policyId").GetGuid());
        Assert.Equal($"apia-plain-{s}", P(r1, "risk", "policyName").GetString());

        using (var scope = _fx.Scope())
        {
            var db = _fx.Db(scope);
            (await db.Projects.SingleAsync(p => p.Id == w.Tree.ProjectId)).RiskPolicyId = cappedId;
            await db.SaveChangesAsync();
        }
        var r2 = await GetJsonAsync(http, $"/aggregates?projectId={w.Tree.ProjectId}");

        Assert.Equal(cappedId, P(r2, "risk", "policyId").GetGuid());
        Assert.True(P(r2, "risk", "score").GetDouble() <= P(r1, "risk", "score").GetDouble());
        // Display counts are untouched by overrides.
        Assert.Equal(Sev(P(r1, "findings", "counts"), "critical"), Sev(P(r2, "findings", "counts"), "critical"));
    }

    [SkippableFact]
    public async Task Client_scope_resolves_the_policy_assigned_to_the_client()
    {
        Skip.IfNot(_fx.Available);
        var admin = await UserAsync(_fx, admin: true);
        var tree = await ClientProjectAsync(_fx);
        var cv = await VersionAsync(_fx, tree.ProjectId, "1.0." + Sfx(), branch: null);
        await AddFindingsAsync(_fx, NewFinding(cv, ScannerKind.OpenGrep, Severity.High, "X1"));
        var s = Sfx();
        Guid policyId;
        using (var scope = _fx.Scope())
        {
            var db = _fx.Db(scope);
            var p = new RiskPolicy { Name = $"apia-client-pol-{s}", Config = RiskPolicyDefaults.BuildTampStandardV1() };
            db.RiskPolicies.Add(p);
            (await db.Clients.SingleAsync(c => c.Id == tree.ClientId)).RiskPolicyId = p.Id;
            await db.SaveChangesAsync();
            policyId = p.Id;
        }

        var r = await GetJsonAsync(Http(_fx, admin), $"/aggregates?clientId={tree.ClientId}");

        Assert.Equal(policyId, P(r, "risk", "policyId").GetGuid());
    }

    [SkippableFact]
    public async Task Anonymous_callers_are_refused_and_the_visibility_boundary_returns_404()
    {
        Skip.IfNot(_fx.Available);
        var mine = await ClientProjectAsync(_fx);
        var theirs = await ClientProjectAsync(_fx);
        var member = await UserAsync(_fx, admin: false);
        await GrantAsync(_fx, member, ProjectRole.LeadDev, mine.ClientId, null);
        var unapproved = await UserAsync(_fx, admin: false, approved: false);

        var anon = await Http(_fx, null).GetAsync("/aggregates");
        Assert.Equal(HttpStatusCode.Unauthorized, anon.StatusCode);

        var asMember = Http(_fx, member);
        Assert.Equal(HttpStatusCode.OK, (await asMember.GetAsync($"/aggregates?clientId={mine.ClientId}")).StatusCode);
        Assert.Equal(HttpStatusCode.OK, (await asMember.GetAsync($"/aggregates?projectId={mine.ProjectId}")).StatusCode);
        Assert.Equal(HttpStatusCode.NotFound, (await asMember.GetAsync($"/aggregates?projectId={theirs.ProjectId}")).StatusCode);
        Assert.Equal(HttpStatusCode.NotFound, (await asMember.GetAsync($"/aggregates?clientId={theirs.ClientId}")).StatusCode);

        // Signed in but not approved yet: sees nothing, and naming an id is a 404.
        var asUnapproved = Http(_fx, unapproved);
        Assert.Equal(HttpStatusCode.NotFound, (await asUnapproved.GetAsync($"/aggregates?projectId={mine.ProjectId}")).StatusCode);
    }
}
