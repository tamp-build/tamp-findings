using Tamp;
using Tamp.Findings.Build.Adapters;
using Tamp.Findings.Build.Ingest;
using Tamp.Grype;
using Tamp.NetCli.V10;
using Tamp.Sarif;
using Tamp.Sbom;
using Tamp.Security.Pipeline;

// tamp.findings self-hosted build script. Run with:
//   dotnet run --project build -- <target>
// e.g. `dotnet run --project build -- Compile` or `... -- Ci`.
class Build : SecurityPipelineBuild
{
    public static int Main(string[] args) => Execute<Build>(args);

    [Parameter("Build configuration")]
    Configuration Configuration = IsLocalBuild ? Configuration.Debug : Configuration.Release;

    [Solution] readonly Solution Solution = null!;
    [GitRepository] readonly GitRepository Git = null!;

    [Parameter("tamp.findings API URL", EnvironmentVariable = "TAMP_FINDINGS_URL")]
    readonly string IngestUrl = "http://localhost:5080";

    // Grype binary resolved off PATH (winget install Anchore.Grype).
    [FromPath("grype")] readonly Tool GrypeTool = null!;

    // CycloneDX SBOM enriched with the Vulnerabilities array — Grype's
    // cyclonedx-json output reads the source SBOM and re-emits it with
    // CVE annotations under top-level vulnerabilities. Our existing
    // SbomIngestMapper already folds those into per-component vuln lists.
    AbsolutePath SbomWithCvesFile => RootDirectory / "artifacts" / "security" / "tamp.findings.cves.cdx.json";

    AbsolutePath Artifacts => RootDirectory / "artifacts";
    AbsolutePath CoverageDir => Artifacts / "coverage";
    AbsolutePath TestResults => Artifacts / "test-results";

    // ----- SecurityPipelineBuild overrides --------------------------------

    protected override string SecurityProductName => "tamp.findings";
    protected override string SecuritySolutionPath => Solution.Path;

    // OpenGrep CLI install on Windows is upstream-blocked (TAM-262).
    // No-op the target so the dependency chain still runs; SecurityScan
    // will merge whatever SARIFs exist.
    protected override Target SecurityScanOpenGrep => _ => _
        .Description("OpenGrep skipped pending TAM-262 (CLI not winget/scoop/pipx-installable on Windows).")
        .Executes(() => Console.WriteLine("[security] OpenGrep skipped — see TAM-262"));

    // Roslyn analyzer scan must skip the build project itself: dotnet build
    // of the whole solution would try to overwrite our own Build.exe while
    // we're running. Restricting to src/ also keeps test projects out of the
    // SARIF (Directory.Build.props condition handles IsTestProject).
    protected override Target SecurityScanRoslyn => _ => _
        .Description("Roslyn SARIF leg — builds each src/ project with /p:IncludeSecurityAnalyzers=true. Excludes build/ to avoid the build orchestrator overwriting itself; excludes tests/ via Directory.Build.props condition.")
        .DependsOn(SbomDependencies)
        .Executes(() =>
        {
            SecurityArtifactsDir.CreateDirectory();
            SecuritySarifRoslynDir.CreateDirectory();
            foreach (var f in SecuritySarifRoslynDir.GlobFiles("*.sarif")) f.Delete();

            return (RootDirectory / "src").GlobFiles("**/*.csproj")
                .Select(proj => DotNet.Build(s => s
                    .SetProject(proj)
                    .SetProperty("IncludeSecurityAnalyzers", "true")
                    .SetProperty("TreatWarningsAsErrors", "false")
                    .SetNoIncremental(true)));
        });

    // ----- .NET-side targets ----------------------------------------------

    Target Info => _ => _
        .Description("Print build context — useful at the top of CI logs.")
        .Executes(() =>
        {
            Console.WriteLine($"  Product:       tamp.findings");
            Console.WriteLine($"  Branch:        {Git.Branch ?? "<detached>"}");
            Console.WriteLine($"  Commit:        {Git.Commit[..7]}");
            Console.WriteLine($"  Configuration: {Configuration}");
            Console.WriteLine($"  Solution:      {Solution.Name} ({Solution.Projects.Count} project{(Solution.Projects.Count == 1 ? "" : "s")})");
            Console.WriteLine($"  Local build:   {IsLocalBuild}");
            Console.WriteLine($"  Ingest URL:    {IngestUrl}");
        });

    Target Clean => _ => _
        .Description("Delete bin/obj across the tree and the artifacts directory.")
        .Executes(() => CleanArtifacts());

    Target Restore => _ => _
        .Description("dotnet restore the solution.")
        .Executes(() => DotNet.Restore(s => s.SetProject(Solution.Path)));

    Target Compile => _ => _
        .DependsOn(nameof(Restore))
        .Description("dotnet build the solution.")
        .Executes(() => DotNet.Build(s => s
            .SetProject(Solution.Path)
            .SetConfiguration(Configuration)
            .SetNoRestore(true)));

    Target Test => _ => _
        .DependsOn(nameof(Compile))
        .Description("Run all tests with XPlat Code Coverage (OpenCover format for downstream tooling).")
        .Executes(() => DotNet.Test(s => s
            .SetProject(Solution.Path)
            .SetConfiguration(Configuration)
            .SetNoBuild(true)
            .AddLogger("trx;LogFileName=test-results.trx")
            .AddDataCollector("XPlat Code Coverage")
            .SetSettings((RootDirectory / "build" / "coverlet.runsettings").Value)
            .SetResultsDirectory(TestResults)));

    Target Coverage => _ => _
        .DependsOn(nameof(Test))
        .Description("Aggregate coverage reports across test projects into artifacts/coverage/.")
        .Executes(() =>
        {
            CoverageDir.CreateDirectory();
            Console.WriteLine($"  Coverage outputs landed under {TestResults.Value}");
        });

    // ----- Grype CVE enrichment -------------------------------------------

    Target SecurityScanGrype => _ => _
        .DependsOn(nameof(Sbom))
        .Description("Run Grype against the CycloneDX SBOM, emit an enriched CycloneDX file with CVEs folded in. First run downloads Grype's vuln DB (~5 min); subsequent runs are seconds.")
        .Executes(() => Grype.Scan(GrypeTool, s => s
            .SetSbomSource(SecuritySbomFile.Value)
            .AddOutput($"cyclonedx-json={SbomWithCvesFile.Value}")
            .SetWorkingDirectory(RootDirectory)));

    // ----- Ingestion -------------------------------------------------------

    Target Ingest => _ => _
        .Description("POST every artifact under artifacts/security/ to the running tamp.findings API. Run ScanAll first to produce the artifacts; the API process must be up.")
        .Executes(async () =>
        {
            var ctx = BuildIngestContext();
            Console.WriteLine($"[ingest] target: {IngestUrl}  context: {ctx.Client}/{ctx.Project}/{ctx.Component} {ctx.Version} @{ctx.CommitSha?[..7]}");

            var client = new IngestClient(IngestUrl);

            // SBOM: post the original CycloneDx (full component metadata) and,
            // when Grype produced an enriched file, splice its vulnerabilities
            // into the in-memory bom before mapping. Grype's cyclonedx-json
            // output drops hashes/authors/externalRefs, so we don't want it as
            // the canonical SBOM — just as a source of CVEs.
            if (File.Exists(SecuritySbomFile))
            {
                var bom = SbomReader.LoadFromFile(SecuritySbomFile);
                int grypeVulns = 0;
                if (File.Exists(SbomWithCvesFile))
                {
                    var grypeBom = SbomReader.LoadFromFile(SbomWithCvesFile);
                    if (grypeBom.Vulnerabilities is { Count: > 0 } gv)
                    {
                        bom = bom with { Vulnerabilities = gv };
                        grypeVulns = gv.Count;
                    }
                }
                var payload = SbomIngestMapper.Map(bom, ctx);
                var resp = await client.PostSbomAsync(payload);
                Console.WriteLine($"[ingest] SBOM       → snapshot {resp.GetProperty("sbomSnapshotId")}  components={resp.GetProperty("componentsCount")}  deps={resp.GetProperty("dependenciesCount")}  vulns={resp.GetProperty("vulnerabilitiesCount")} (grype matches={grypeVulns})");
            }
            else
            {
                Console.WriteLine($"[ingest] SBOM       — file not found at {SecuritySbomFile.Value}, skipping");
            }

            await PostSarifAsync(client, ctx, SecuritySarifSastFile, "SAST");
            await PostSarifAsync(client, ctx, SecuritySarifCveFile, "CVE");
            await PostSarifAsync(client, ctx, SecuritySarifTrivyFile, "Trivy");
        });

    Target ScanAll => _ => _
        .DependsOn(nameof(Sbom), nameof(SecurityScanGrype), nameof(SecurityScan), nameof(SecurityScanCveSbom), nameof(SecurityScanTrivy))
        .Description("Run every scan in artifacts/security/. The API process MUST be stopped first — the Roslyn scan rebuilds with /p:NoIncremental=true and will fight a running API for the DLL locks. Follow up with the Ingest target after the API is back up.");

    Target Ci => _ => _
        .DependsOn(nameof(Info), nameof(Compile), nameof(Test), nameof(Coverage))
        .Description("Local CI: build, test, coverage. Run ScanAll for the full ingestion sweep.");

    // ----- Helpers ---------------------------------------------------------

    IngestBuildContext BuildIngestContext()
    {
        // Walking up the solution → per-csproj decomposition is V2 work.
        // For now, treat the whole repo as one ingestable component named
        // "tamp.findings"; specific scanners can override at adapter time
        // if their output addresses individual projects.
        var sha = Git.Commit;
        var version = $"0.1.0-alpha+{(sha is null ? "local" : sha[..7])}";
        return new IngestBuildContext(
            Client: "BrewingCoder",
            Project: "tamp.findings",
            Component: "Solution",
            ComponentKind: "solution",
            Flavor: "net10",
            Version: version,
            CommitSha: sha,
            Branch: Git.Branch,
            BuildId: IsLocalBuild ? "local" : Environment.GetEnvironmentVariable("CI_BUILD_ID"),
            PullRequestRef: null);
    }

    static async Task PostSarifAsync(IngestClient client, IngestBuildContext ctx, AbsolutePath path, string label)
    {
        if (!File.Exists(path))
        {
            Console.WriteLine($"[ingest] {label,-10} — file not found at {path.Value}, skipping");
            return;
        }
        var log = SarifReader.LoadFromFile(path);
        var totalPosted = 0;
        foreach (var payload in SarifIngestMapper.Map(log, ctx))
        {
            var resp = await client.PostFindingsAsync(payload);
            totalPosted += resp.GetProperty("findingsInserted").GetInt32() + resp.GetProperty("findingsUpdated").GetInt32();
            Console.WriteLine($"[ingest] {label,-10} → scanner={payload.Scanner,-12} inserted={resp.GetProperty("findingsInserted")}  updated={resp.GetProperty("findingsUpdated")}");
        }
        if (totalPosted == 0)
        {
            Console.WriteLine($"[ingest] {label,-10} — file present but no findings to post");
        }
    }
}
