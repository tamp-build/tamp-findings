using Microsoft.Extensions.DependencyInjection;
using Tamp.Findings.Application.Explorer;
using Tamp.Findings.Domain.Entities;
using Tamp.Findings.Domain.Values;

namespace Tamp.Findings.Integration.Tests;

// The SBOM, coverage and tests spines against a real database (TFND-92/93/94).
//
// All three do their grouping and ordering over real rows, and two of them
// resolve a second table into the answer — KEV and VEX for SBOM, the per-class
// line arrays for coverage. None of that is visible to a contract test.
[Collection(DatabaseCollection.Name)]
public class SpineIntegrationTests
{
    private readonly DatabaseFixture _fx;

    public SpineIntegrationTests(DatabaseFixture fx) => _fx = fx;

    // ---- SBOM ---------------------------------------------------------------

    [SkippableFact]
    public async Task Dependencies_group_by_ecosystem()
    {
        Skip.IfNot(_fx.Available);

        var world = await SeedAsync();
        using var scope = _fx.Scope();
        var query = scope.ServiceProvider.GetRequiredService<SbomExplorerQuery>();

        var groups = await query.TreeAsync(world.ProjectId, world.Sha);

        // A .NET dependency and a JavaScript one are usually two different
        // people's problem, which is why the ecosystem is the grouping.
        Assert.Contains(groups, g => g.Ecosystem == "nuget");
        Assert.Contains(groups, g => g.Ecosystem == "npm");
    }

    [SkippableFact]
    public async Task Vulnerable_dependencies_sort_ahead_of_clean_ones()
    {
        Skip.IfNot(_fx.Available);

        var world = await SeedAsync();
        using var scope = _fx.Scope();
        var query = scope.ServiceProvider.GetRequiredService<SbomExplorerQuery>();

        var nuget = (await query.TreeAsync(world.ProjectId, world.Sha))
            .Single(g => g.Ecosystem == "nuget");

        // Someone opening this spine is looking for what is wrong, not taking
        // inventory.
        Assert.True(nuget.Components[0].VulnerabilityCount > 0);
        Assert.Equal(0, nuget.Components[^1].VulnerabilityCount);
    }

    [SkippableFact]
    public async Task A_leaf_carries_the_worst_severity_across_its_advisories()
    {
        Skip.IfNot(_fx.Available);

        var world = await SeedAsync();
        using var scope = _fx.Scope();
        var query = scope.ServiceProvider.GetRequiredService<SbomExplorerQuery>();

        var leaf = (await query.TreeAsync(world.ProjectId, world.Sha))
            .SelectMany(g => g.Components).Single(c => c.Name == "Vulnerable.Lib");

        Assert.Equal(2, leaf.VulnerabilityCount);
        Assert.Equal(Severity.Critical, leaf.WorstSeverity);
    }

    [SkippableFact]
    public async Task A_kev_listed_advisory_sorts_above_a_higher_scored_one()
    {
        Skip.IfNot(_fx.Available);

        var world = await SeedAsync();
        using var scope = _fx.Scope();
        var query = scope.ServiceProvider.GetRequiredService<SbomExplorerQuery>();

        var detail = await query.DetailAsync(world.ProjectId, world.Sha, world.VulnerablePurl);

        // The KEV entry is the MEDIUM one, deliberately: something being
        // exploited today outranks something merely scored higher.
        Assert.True(detail[0].KevListed);
        Assert.Equal(Severity.Medium, detail[0].Severity);
    }

    [SkippableFact]
    public async Task A_justified_not_affected_statement_reads_as_suppressing()
    {
        Skip.IfNot(_fx.Available);

        var world = await SeedAsync();
        using var scope = _fx.Scope();
        var query = scope.ServiceProvider.GetRequiredService<SbomExplorerQuery>();

        var detail = await query.DetailAsync(world.ProjectId, world.Sha, world.VulnerablePurl);
        var vuln = detail.Single(v => v.AdvisoryId == "CVE-2024-00001");

        Assert.Equal(VexStatementStatus.NotAffected, vuln.VexStatus);
        Assert.True(vuln.VexSuppresses);
    }

    [SkippableFact]
    public async Task A_not_affected_statement_with_no_justification_does_not_suppress()
    {
        Skip.IfNot(_fx.Available);

        // The one that matters. Scoring ignores it (VexResolver), so the table
        // has to as well — otherwise someone writes half a statement, sees it
        // echoed back, and believes the CVE is handled.
        var world = await SeedAsync();
        using var scope = _fx.Scope();
        var query = scope.ServiceProvider.GetRequiredService<SbomExplorerQuery>();

        var detail = await query.DetailAsync(world.ProjectId, world.Sha, world.VulnerablePurl);
        var vuln = detail.Single(v => v.AdvisoryId == "CVE-2024-00002");

        Assert.Equal(VexStatementStatus.NotAffected, vuln.VexStatus);
        Assert.False(vuln.VexSuppresses);
    }

    [SkippableFact]
    public async Task A_retired_statement_is_not_shown_as_the_answer()
    {
        Skip.IfNot(_fx.Available);

        var world = await SeedAsync();
        using var scope = _fx.Scope();
        var query = scope.ServiceProvider.GetRequiredService<SbomExplorerQuery>();

        var detail = await query.DetailAsync(world.ProjectId, world.Sha, world.RetiredVexPurl);

        // Retirement is the soft-delete semantic. A retired statement stays for
        // audit history but stops being the current disposition.
        Assert.Null(detail.Single().VexStatus);
    }

    [SkippableFact]
    public async Task A_version_bare_statement_matches_the_versioned_purl()
    {
        Skip.IfNot(_fx.Available);

        // SbomComponent.Purl carries the version; VexStatement.Purl is bare
        // with the version in its own column. If the explorer compared them
        // directly it would find nothing and every CVE would read "no VEX".
        var world = await SeedAsync();
        using var scope = _fx.Scope();
        var query = scope.ServiceProvider.GetRequiredService<SbomExplorerQuery>();

        var detail = await query.DetailAsync(world.ProjectId, world.Sha, world.VulnerablePurl);

        Assert.All(detail, v => Assert.NotNull(v.VexStatus));
    }

    // ---- Coverage -----------------------------------------------------------

    [SkippableFact]
    public async Task Coverage_files_sort_worst_first()
    {
        Skip.IfNot(_fx.Available);

        var world = await SeedAsync();
        using var scope = _fx.Scope();
        var query = scope.ServiceProvider.GetRequiredService<CoverageAndTestsQuery>();

        var files = (await query.CoverageTreeAsync(world.ProjectId, world.Sha))
            .SelectMany(m => m.Files).ToArray();

        // The reader is looking for what is UNTESTED. Sorting the well-covered
        // files to the top would bury the answer.
        Assert.True(files[0].Percent <= files[^1].Percent);
        Assert.Equal("src/Untested.cs", files[0].Path);
    }

    [SkippableFact]
    public async Task The_line_map_unions_every_class_in_the_file()
    {
        Skip.IfNot(_fx.Available);

        var world = await SeedAsync();
        using var scope = _fx.Scope();
        var query = scope.ServiceProvider.GetRequiredService<CoverageAndTestsQuery>();

        var map = await query.CoverageDetailAsync(world.ProjectId, world.Sha, "src/Covered.cs");

        Assert.NotNull(map);
        // Two classes share this file; line 1 comes from one and line 5 from
        // the other.
        Assert.Contains(1, map!.Visited);
        Assert.Contains(5, map.Visited);
    }

    [SkippableFact]
    public async Task A_line_covered_by_any_class_is_covered()
    {
        Skip.IfNot(_fx.Available);

        // Line 3 is visited by one partial class and unvisited by the other.
        // Reporting it as uncovered would tint a line the tests demonstrably
        // executed.
        var world = await SeedAsync();
        using var scope = _fx.Scope();
        var query = scope.ServiceProvider.GetRequiredService<CoverageAndTestsQuery>();

        var map = await query.CoverageDetailAsync(world.ProjectId, world.Sha, "src/Covered.cs");

        Assert.Contains(3, map!.Visited);
        Assert.DoesNotContain(3, map.Unvisited);
    }

    [SkippableFact]
    public async Task A_file_with_no_stored_source_returns_null_rather_than_an_empty_viewer()
    {
        Skip.IfNot(_fx.Available);

        var world = await SeedAsync();
        using var scope = _fx.Scope();
        var query = scope.ServiceProvider.GetRequiredService<CoverageAndTestsQuery>();

        Assert.Null(await query.CoverageDetailAsync(world.ProjectId, world.Sha, "src/DoesNotExist.cs"));
    }

    // ---- Tests --------------------------------------------------------------

    [SkippableFact]
    public async Task Assemblies_with_failures_sort_first_and_skips_second()
    {
        Skip.IfNot(_fx.Available);

        var world = await SeedAsync();
        using var scope = _fx.Scope();
        var query = scope.ServiceProvider.GetRequiredService<CoverageAndTestsQuery>();

        var groups = await query.TestTreeAsync(world.ProjectId, world.Sha);

        Assert.True(groups[0].Failed > 0);
        // A skipped test is not a passing test, so the assembly carrying skips
        // sorts ahead of the fully green one.
        Assert.True(groups[1].Skipped > 0);
        Assert.Equal(0, groups[^1].Failed + groups[^1].Skipped);
    }

    [SkippableFact]
    public async Task Cases_show_failures_first_then_skips()
    {
        Skip.IfNot(_fx.Available);

        var world = await SeedAsync();
        using var scope = _fx.Scope();
        var query = scope.ServiceProvider.GetRequiredService<CoverageAndTestsQuery>();

        var cases = await query.TestDetailAsync(world.ProjectId, world.Sha, "Broken.Suite");

        Assert.Equal(TestOutcome.Failed, cases[0].Outcome);
        Assert.Equal(TestOutcome.Skipped, cases[1].Outcome);
    }

    [SkippableFact]
    public async Task A_skip_reason_survives_to_the_table()
    {
        Skip.IfNot(_fx.Available);

        // "Nobody wrote down why" is a finding of its own, and the table can
        // only say so if the reason actually reaches it.
        var world = await SeedAsync();
        using var scope = _fx.Scope();
        var query = scope.ServiceProvider.GetRequiredService<CoverageAndTestsQuery>();

        var cases = await query.TestDetailAsync(world.ProjectId, world.Sha, "Broken.Suite");
        var skipped = cases.Single(c => c.Outcome == TestOutcome.Skipped);

        Assert.Equal("needs a live database", skipped.Note);
    }

    // ---- Seed ---------------------------------------------------------------

    private sealed record World(Guid ProjectId, string Sha, string VulnerablePurl, string RetiredVexPurl);

    private async Task<World> SeedAsync()
    {
        using var scope = _fx.Scope();
        var db = _fx.Db(scope);

        var suffix = Guid.NewGuid().ToString("N")[..8];
        var sha = suffix + "bbbbbb";
        var client = new Client { Name = $"sp-client-{suffix}" };
        var project = new Project { ClientId = client.Id, Name = $"sp-project-{suffix}" };
        var component = new Component { ProjectId = project.Id, Name = $"sp-component-{suffix}" };
        var version = new ComponentVersion
        {
            ComponentId = component.Id, VersionString = "0.1.0", CommitSha = sha,
        };

        db.Clients.Add(client);
        db.Projects.Add(project);
        db.Components.Add(component);
        db.ComponentVersions.Add(version);

        // --- SBOM ---
        var snapshot = new SbomSnapshot { ComponentVersionId = version.Id, ToolName = "syft", SpecVersion = "1.5" };
        db.SbomSnapshots.Add(snapshot);

        SbomComponent Dep(string purl, string name, string versionString)
        {
            var dep = new SbomComponent
            {
                SbomSnapshotId = snapshot.Id, Purl = purl, Name = name, Version = versionString,
            };
            db.SbomComponents.Add(dep);
            return dep;
        }

        var vulnerable = Dep("pkg:nuget/Vulnerable.Lib@1.0.0", "Vulnerable.Lib", "1.0.0");
        var clean = Dep("pkg:nuget/Clean.Lib@2.0.0", "Clean.Lib", "2.0.0");
        var retired = Dep("pkg:npm/retired-lib@3.0.0", "retired-lib", "3.0.0");
        _ = clean;

        void Vuln(SbomComponent dep, string advisory, Severity severity, double? cvss = null) =>
            db.Vulnerabilities.Add(new Vulnerability
            {
                SbomComponentId = dep.Id,
                AdvisoryId = advisory,
                Severity = severity,
                Title = $"{advisory} in {dep.Name}",
                CvssScore = cvss,
                Source = ScannerKind.Trivy,
            });

        Vuln(vulnerable, "CVE-2024-00001", Severity.Critical, 9.8);
        Vuln(vulnerable, "CVE-2024-00002", Severity.Medium, 5.4);
        Vuln(retired, "CVE-2024-00003", Severity.High, 7.1);

        // The MEDIUM one is the KEV entry, so the ordering assertion can only
        // pass if KEV genuinely outranks severity.
        //
        // KEV is a GLOBAL list keyed on the CVE id, not a per-project table, so
        // the row is shared across every seeded world rather than duplicated —
        // which is also why it is added only when it is not already there.
        if (await db.KevAdvisories.FindAsync("CVE-2024-00002") is null)
        {
            db.KevAdvisories.Add(new KevAdvisory
            {
                CveId = "CVE-2024-00002",
                VendorProject = "Vendor",
                Product = "Product",
                VulnerabilityName = "Exploited thing",
                DateAdded = new DateOnly(2024, 1, 1),
                DueDate = new DateOnly(2024, 2, 1),
            });
        }

        // Bare purl on the statement, versioned purl on the component — the
        // mismatch the explorer has to normalise away.
        db.VexStatements.Add(new VexStatement
        {
            ProjectId = project.Id,
            Purl = "pkg:nuget/Vulnerable.Lib",
            AdvisoryId = "CVE-2024-00001",
            Status = VexStatementStatus.NotAffected,
            Justification = VexJustification.VulnerableCodeNotInExecutePath,
        });
        db.VexStatements.Add(new VexStatement
        {
            ProjectId = project.Id,
            Purl = "pkg:nuget/Vulnerable.Lib",
            AdvisoryId = "CVE-2024-00002",
            Status = VexStatementStatus.NotAffected,
            Justification = VexJustification.None,
        });
        db.VexStatements.Add(new VexStatement
        {
            ProjectId = project.Id,
            Purl = "pkg:npm/retired-lib",
            AdvisoryId = "CVE-2024-00003",
            Status = VexStatementStatus.Fixed,
            RetiredAt = new DateTimeOffset(2024, 6, 1, 0, 0, 0, TimeSpan.Zero),
        });

        // --- Coverage ---
        var report = new CoverageReport { ComponentVersionId = version.Id, ToolName = "Coverlet" };
        db.CoverageReports.Add(report);

        var module = new CoverageModule
        {
            CoverageReportId = report.Id, Name = "Sp.Module", SequenceCoverage = 55,
        };
        db.CoverageModules.Add(module);

        CoverageSourceFile File(string path, string text)
        {
            var file = new CoverageSourceFile
            {
                CoverageReportId = report.Id, RelativePath = path, SourceText = text,
                LineCount = text.Split('\n').Length,
            };
            db.CoverageSourceFiles.Add(file);
            return file;
        }

        var covered = File("src/Covered.cs", string.Join('\n', Enumerable.Repeat("var x = 1;", 6)));
        var untested = File("src/Untested.cs", string.Join('\n', Enumerable.Repeat("var y = 2;", 4)));

        void Class(CoverageSourceFile file, string name, int[] visited, int[] unvisited) =>
            db.CoverageClasses.Add(new CoverageClass
            {
                CoverageModuleId = module.Id,
                CoverageSourceFileId = file.Id,
                FullName = name,
                VisitedLines = visited,
                UnvisitedLines = unvisited,
            });

        // Line 3 is visited by one partial class and unvisited by the other.
        Class(covered, "Sp.Covered.PartA", [1, 3], [2]);
        Class(covered, "Sp.Covered.PartB", [5], [3, 6]);
        Class(untested, "Sp.Untested", [], [1, 2, 3, 4]);

        // --- Tests ---
        var run = new TestRunReport { ComponentVersionId = version.Id, ToolName = "dotnet test (trx)" };
        db.TestRunReports.Add(run);

        TestSuiteResult Suite(string assembly, string className, int passed, int failed, int skipped)
        {
            var suite = new TestSuiteResult
            {
                TestRunReportId = run.Id,
                AssemblyName = assembly,
                ClassName = className,
                TotalCount = passed + failed + skipped,
                PassedCount = passed,
                FailedCount = failed,
                SkippedCount = skipped,
                DurationMs = 12,
            };
            db.TestSuiteResults.Add(suite);
            return suite;
        }

        var broken = Suite("Sp.Broken.dll", "Broken.Suite", passed: 1, failed: 1, skipped: 1);
        Suite("Sp.Skippy.dll", "Skippy.Suite", passed: 2, failed: 0, skipped: 1);
        Suite("Sp.Green.dll", "Green.Suite", passed: 3, failed: 0, skipped: 0);

        void Case(TestSuiteResult suite, string name, TestOutcome outcome, string? message = null) =>
            db.TestCaseResults.Add(new TestCaseResult
            {
                TestSuiteResultId = suite.Id,
                Name = name,
                Outcome = outcome,
                DurationMs = 4,
                ErrorMessage = message,
            });

        Case(broken, "A_passing_case", TestOutcome.Passed);
        Case(broken, "B_failing_case", TestOutcome.Failed, "expected 1, got 2");
        Case(broken, "C_skipped_case", TestOutcome.Skipped, "needs a live database");

        await db.SaveChangesAsync();
        return new World(project.Id, sha, vulnerable.Purl, retired.Purl);
    }
}
