using Tamp;
using Tamp.Findings.Build;
using Tamp.Findings.Build.Adapters;
using Tamp.Findings.Build.Ingest;
using Tamp.Grype;
using Tamp.NetCli.V10;
using Tamp.Sarif;
using Tamp.Sbom;
using Tamp.Security.Pipeline;
using Tamp.Syft.V1;
using Tamp.TruffleHog.V3;
using SyftCli = Tamp.Syft.V1.Syft;
using TrufflehogCli = Tamp.TruffleHog.V3.TruffleHog;
using OpenGrepCli = Tamp.OpenGrep.OpenGrep;
using Tamp.Eslint.V9;
using EslintCli = Tamp.Eslint.V9.Eslint;
using Tamp.AxeCore;
using AxeCoreCli = Tamp.AxeCore.AxeCore;

// tamp.findings self-hosted build script. Run with:
//   dotnet run --project build -- <target>
// e.g. `dotnet run --project build -- Compile` or `... -- Ci`.
class Build : SecurityPipelineBuild
{
    public static int Main(string[] args)
    {
        // Load repo-root .env into process env BEFORE Execute<Build> kicks
        // off Nuke's parameter binding — that's when [Parameter(
        // EnvironmentVariable = ...)] resolves. Keeps the bearer token
        // for ingest out of every contributor's shell profile.
        DotEnvLoader.LoadFromRepoRoot();
        return Execute<Build>(args);
    }

    [Parameter("Build configuration")]
    Configuration Configuration = IsLocalBuild ? Configuration.Debug : Configuration.Release;

    [Solution] readonly Solution Solution = null!;
    [GitRepository] readonly GitRepository Git = null!;

    [Parameter("tamp.findings API URL", EnvironmentVariable = "TAMP_FINDINGS_URL")]
    readonly string IngestUrl = "http://localhost:5080";

    // Bearer token for /ingest/*. Mint per client/project in the SPA's
    // settings dialog; store in repo-root .env (gitignored) as
    // TAMP_FINDINGS_INGEST_TOKEN=cli_... or prj_... The .env file is
    // loaded into the process env at startup (see DotEnvLoader).
#pragma warning disable CS0649
    [Parameter("Ingest bearer token (cli_/prj_)", EnvironmentVariable = "TAMP_FINDINGS_INGEST_TOKEN")]
    readonly string? IngestToken;
#pragma warning restore CS0649

    // Grype binary resolved off PATH (winget install Anchore.Grype). The
    // Grype satellite uses the newer "pass Tool explicitly" wrapper style.
#pragma warning disable CS0649
    [FromPath("grype", Optional = true)] readonly Tool? GrypeTool;

    // TruffleHog v3 binary resolved off PATH (scoop install trufflehog).
    // Optional so targets that don't need it (Ingest, Compile, Test) can
    // run from a shell where scoop's shims aren't on PATH.
    [FromPath("trufflehog", Optional = true)] readonly Tool? TrufflehogTool;
#pragma warning restore CS0649

    // CycloneDX SBOM enriched with the Vulnerabilities array — Grype's
    // cyclonedx-json output reads the source SBOM and re-emits it with
    // CVE annotations under top-level vulnerabilities. Our existing
    // SbomIngestMapper already folds those into per-component vuln lists.
    AbsolutePath SbomWithCvesFile => RootDirectory / "artifacts" / "security" / "tamp.findings.cves.cdx.json";

    // TruffleHog JSON: one finding per line (jsonl). The wrapper writes
    // raw secret material here when scanning, so make sure this path is
    // gitignored (it already is under artifacts/).
    AbsolutePath TrufflehogJsonFile => RootDirectory / "artifacts" / "security" / "trufflehog.jsonl";

    AbsolutePath Artifacts => RootDirectory / "artifacts";
    AbsolutePath CoverageDir => Artifacts / "coverage";
    AbsolutePath TestResults => Artifacts / "test-results";
    AbsolutePath SpaTestResults => Artifacts / "test-results-spa";
    AbsolutePath SpaProjectDir => RootDirectory / "web";
    // ReSharper InspectCode SARIF. Output lives next to roslyn/opengrep so
    // the SAST merge step finds it consistently.
    AbsolutePath SecuritySarifResharperFile => RootDirectory / "artifacts" / "security" / "resharper.sarif";
    // ESLint SARIF — TS/JS style + best-practice for the SPA. The TS
    // equivalent of ReSharper for C#; covers what OpenGrep's security-only
    // packs intentionally don't.
    AbsolutePath SecuritySarifEslintFile => RootDirectory / "artifacts" / "security" / "eslint.sarif";
    // TFND-27 / TAM-277: axe-core a11y scan against a deployed SPA URL.
    // axe-core's CLI emits JSON natively; axe-sarif-converter wraps it into
    // SARIF 2.1.0 — same shape /ingest/findings already accepts for ESLint
    // and Trivy.
    AbsolutePath SecurityJsonAxeCoreFile => RootDirectory / "artifacts" / "security" / "axe-core.json";
    AbsolutePath SecuritySarifAxeCoreFile => RootDirectory / "artifacts" / "security" / "axe-core.sarif";

    // The deployed (or locally running) SPA URL axe-core scans. Defaults to
    // the Vite dev server; set TAMP_FINDINGS_AXE_TARGET_URL in CI to point
    // at the staging URL. Empty value → SecurityScanAxeCore skips with a
    // clear log line instead of failing.
#pragma warning disable CS0649
    [Parameter("Target URL for axe-core a11y scan (defaults to local dev SPA)", EnvironmentVariable = "TAMP_FINDINGS_AXE_TARGET_URL")]
    readonly string? AxeTargetUrl;
#pragma warning restore CS0649

    // ----- SecurityPipelineBuild overrides --------------------------------

    protected override string SecurityProductName => "tamp.findings";
    protected override string SecuritySolutionPath => Solution.Path;

    // Replace dotnet-CycloneDX (.NET-only) with Syft so the SBOM also covers
    // web/'s npm tree. Syft handles both ecosystems via the directory source
    // and pnpm-lock.yaml support. Trade-off: Syft's .NET cataloger is slightly
    // less precise than dotnet-CycloneDX's project graph traversal, but the
    // cross-ecosystem coverage is the bigger win.
    protected override Target Sbom => _ => _
        .DependsOn(SbomDependencies)
        .Description("Cross-ecosystem CycloneDX SBOM via Syft (.NET + npm + anything else Syft catalogs).")
        .Executes(() =>
        {
            SecurityArtifactsDir.CreateDirectory();
            return SyftCli.ScanDirectory(s => s
                .SetPath(RootDirectory.Value)
                .SetFormat(SyftFormat.CycloneDxJson)
                .SetOutputFile(SecuritySbomFile.Value)
                .AddExcludePattern("./artifacts")
                .AddExcludePattern("./**/bin")
                .AddExcludePattern("./**/obj")
                .AddExcludePattern("./**/node_modules")
                .AddExcludePattern("./.git")
                .SetQuiet(true)
                .SetWorkingDirectory(RootDirectory));
        });

    // TAM-262 update: OpenGrep v1.22.0 (2026-05-19) ships an official
    // standalone Windows binary + install.ps1; resolves as `opengrep` once
    // %USERPROFILE%\.opengrep\cli\latest is on PATH. We let the base class
    // SecurityScanOpenGrep run — it builds the CommandPlan via Tool.FromPath
    // and ProcessRunner.Execute. The override is kept defensive in case the
    // binary disappears: if Tool.TryFromPath returns null, no-op like before.
    protected override Target SecurityScanOpenGrep => _ => _
        .Description("OpenGrep SAST scan (SARIF). Skipped only when opengrep.exe is not on PATH.")
        .Executes(() =>
        {
            var resolved = Tool.TryFromPath("opengrep", RootDirectory.Value);
            if (resolved is null)
            {
                Console.WriteLine("[security] OpenGrep skipped — opengrep.exe not on PATH (install via https://github.com/opengrep/opengrep install.ps1)");
                return;
            }
            SecurityArtifactsDir.CreateDirectory();
            // Policy packs: `auto` is the language-detection baseline, then we
            // stack security-focused packs to broaden coverage for the langs
            // we actually ship. p/csharp + p/dotnet for the API/Data/Domain
            // tree; p/typescript + p/javascript for the SPA; the cross-cutters
            // (security-audit, owasp-top-ten, cwe-top-25, secrets, sql-
            // injection, jwt) catch patterns that aren't language-specific.
            var plan = OpenGrepCli.Scan(s => s
                .AddTarget((RootDirectory / "src").Value)
                .AddTarget((RootDirectory / "web" / "src").Value)
                .AddConfig("auto")
                .AddConfig("p/security-audit")
                .AddConfig("p/owasp-top-ten")
                .AddConfig("p/cwe-top-25")
                .AddConfig("p/csharp")
                // p/dotnet is a 404 on semgrep.dev — p/csharp is the closest peer.
                .AddConfig("p/typescript")
                .AddConfig("p/javascript")
                // React-specific (dangerouslySetInnerHTML, untrusted JSX
                // href/src, refs) + cross-cutting XSS rules. Both stay
                // quiet on clean React code; cheap insurance for when
                // someone reaches for innerHTML or a templated URL.
                .AddConfig("p/react")
                .AddConfig("p/xss")
                .AddConfig("p/secrets")
                .AddConfig("p/sql-injection")
                .AddConfig("p/jwt")
                .SetSarif(true)
                .SetOutputFile(SecuritySarifOpenGrepFile.Value)
                .SetQuiet(true)
                .SetDisableVersionCheck(true)
                .SetWorkingDirectory(RootDirectory.Value));
            var rc = ProcessRunner.Execute(plan, Console.Out, Console.Error);
            // opengrep exits 0 = clean, 1 = findings reported, both fine for ingest.
            if (rc != 0 && rc != 1) throw new Exception($"opengrep exited with {rc}");
        });

    // JetBrains InspectCode — runs the same ~2200-rule ReSharper inspection
    // engine the IDE uses. SARIF output. Excludes test projects (their bugs
    // are noise) and the build orchestrator itself (would re-invoke us).
    Target SecurityScanResharper => _ => _
        .Description("InspectCode SARIF over the full solution. Requires JetBrains.ReSharper.GlobalTools (dotnet tool install -g JetBrains.ReSharper.GlobalTools).")
        .Executes(() =>
        {
            SecurityArtifactsDir.CreateDirectory();
            var resolved = Tool.TryFromPath("jb", RootDirectory.Value);
            if (resolved is null)
            {
                Console.WriteLine("[security] ReSharper InspectCode skipped — `jb` not on PATH (dotnet tool install -g JetBrains.ReSharper.GlobalTools)");
                return;
            }
            // Severity SUGGESTION matches the default IDE-on-save behavior;
            // matches what the user sees in Rider/ReSharper inspections panel.
            var plan = resolved.Plan(
                "inspectcode",
                Solution.Path,
                $"--output={SecuritySarifResharperFile.Value}",
                "--format=Sarif",
                "--severity=SUGGESTION",
                "--exclude=**/Tests/**;**/bin/**;**/obj/**;**/artifacts/**;build/**");
            var rc = ProcessRunner.Execute(plan, Console.Out, Console.Error);
            if (rc != 0) throw new Exception($"jb inspectcode exited with {rc}");
        });

    // TAM-276: ESLint v9 over web/src — style + best-practice for the SPA.
    // The TS analogue of ReSharper for C# (which only walks .sln C# projects
    // and never enters the pnpm workspace). Skips cleanly when no ESLint
    // install is found, same posture as OpenGrep / ReSharper.
    Target SecurityScanEslint => _ => _
        .Description("ESLint v9 SARIF over web/src. Requires eslint + @microsoft/eslint-formatter-sarif in web/'s devDependencies (or globally).")
        .Executes(() =>
        {
            SecurityArtifactsDir.CreateDirectory();
            if (!EslintBinaryResolver.IsAvailable(SpaProjectDir.Value))
            {
                Console.WriteLine($"[security] ESLint skipped — no install found at {SpaProjectDir} (pnpm add -D eslint @microsoft/eslint-formatter-sarif).");
                return;
            }
            var plan = EslintCli.Scan(s => s
                .SetWorkingDirectory(SpaProjectDir.Value)
                .AddTarget("src")
                .SetSarif()
                .SetOutputFile(SecuritySarifEslintFile.Value)
                .SetQuiet());
            var rc = ProcessRunner.Execute(plan, Console.Out, Console.Error);
            // ESLint: 0 clean, 1 = findings (still a successful scan), 2+ = error.
            if (rc > 1) throw new Exception($"eslint exited with {rc}");
        });

    // TFND-27 / TAM-277: axe-core a11y scan via Tamp.AxeCore 0.1.0. Two
    // verbs because axe-core's CLI emits JSON natively — Scan produces
    // axe.json, ConvertToSarif wraps it into SARIF 2.1.0 via the
    // axe-sarif-converter npm tool. The SARIF then plugs into the same
    // /ingest/findings path Trivy / OpenGrep / ESLint already use, with
    // scanner=AxeCore and sub-category=accessibility.
    //
    // Skip cases:
    //   - Both npm tools must be in web/'s devDependencies (resolver
    //     handles project-local → pnpm exec → npm exec → global).
    //   - AxeTargetUrl empty → no deployed/dev SPA to scan; log and skip.
    //
    // CI: needs headless Chromium. The wrapper's SetNoSandbox() handles
    // the Docker / restricted-runner case; first-time runs may need
    // `npx playwright install chromium` as a one-off pre-step.
    Target SecurityScanAxeCore => _ => _
        .Description("axe-core a11y SARIF against a deployed SPA URL. Requires @axe-core/cli + axe-sarif-converter in web/'s devDependencies.")
        .Executes(() =>
        {
            SecurityArtifactsDir.CreateDirectory();
            var url = string.IsNullOrWhiteSpace(AxeTargetUrl) ? IngestUrl.Replace(":5080", ":5173") : AxeTargetUrl;
            if (string.IsNullOrWhiteSpace(url))
            {
                Console.WriteLine("[security] AxeCore skipped — no target URL (set TAMP_FINDINGS_AXE_TARGET_URL).");
                return;
            }
            if (!AxeCoreBinaryResolver.IsAvailable(SpaProjectDir.Value))
            {
                Console.WriteLine($"[security] AxeCore skipped — @axe-core/cli + axe-sarif-converter not installed at {SpaProjectDir} (pnpm add -D @axe-core/cli axe-sarif-converter).");
                return;
            }

            var scanPlan = AxeCoreCli.Scan(s => s
                .SetWorkingDirectory(SpaProjectDir.Value)
                .AddUrl(url)
                .SetOutputFile(SecurityJsonAxeCoreFile.Value)
                .AddTag("wcag2a").AddTag("wcag2aa").AddTag("wcag21aa").AddTag("best-practice")
                .SetBrowser("chromium")
                .SetNoSandbox()
                .SetTimeoutSeconds(60)
                .SetLoadDelayMs(2000));
            var scanRc = ProcessRunner.Execute(scanPlan, Console.Out, Console.Error);
            // axe-core: 0 = no violations, 1 = violations found (still a
            // successful scan), 2+ = tool error. Mirrors ESLint posture.
            if (scanRc > 1) throw new Exception($"axe-core exited with {scanRc}");

            var sarifPlan = AxeCoreCli.ConvertToSarif(s => s
                .SetWorkingDirectory(SpaProjectDir.Value)
                .SetInputFile(SecurityJsonAxeCoreFile.Value)
                .SetOutputFile(SecuritySarifAxeCoreFile.Value));
            var convertRc = ProcessRunner.Execute(sarifPlan, Console.Out, Console.Error);
            if (convertRc != 0) throw new Exception($"axe-sarif-converter exited with {convertRc}");
        });

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

    Target TestSpa => _ => _
        .Description("Run the Vitest suite in web/ with coverage. Output: artifacts/test-results-spa/lcov.info, consumed by VitestCoverageIngestMapper at Ingest time.")
        .Executes(() =>
        {
            // Vitest's pnpm script is configured (in web/package.json) to drop
            // lcov + json-summary + html under ../artifacts/test-results-spa.
            // pnpm on Windows is a .CMD shim, so we invoke through cmd /c with
            // direct stdio so the user sees the run + test output inline.
            var isWindows = System.Runtime.InteropServices.RuntimeInformation
                .IsOSPlatform(System.Runtime.InteropServices.OSPlatform.Windows);
            var psi = new System.Diagnostics.ProcessStartInfo
            {
                FileName = isWindows ? "cmd.exe" : "pnpm",
                Arguments = isWindows ? "/c pnpm run test:coverage" : "run test:coverage",
                WorkingDirectory = SpaProjectDir.Value,
                UseShellExecute = false,
                RedirectStandardOutput = false,
                RedirectStandardError = false,
            };
            using var proc = System.Diagnostics.Process.Start(psi)
                ?? throw new Exception("Failed to launch pnpm — is it on PATH?");
            proc.WaitForExit();
            if (proc.ExitCode != 0) throw new Exception($"pnpm run test:coverage exited with {proc.ExitCode}");
        });

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
        .Requires(() => GrypeTool is not null)
        .Description("Run Grype against the CycloneDX SBOM, emit an enriched CycloneDX file with CVEs folded in. First run downloads Grype's vuln DB (~5 min); subsequent runs are seconds.")
        .Executes(() => Grype.Scan(GrypeTool!, s => s
            .SetSbomSource(SecuritySbomFile.Value)
            .AddOutput($"cyclonedx-json={SbomWithCvesFile.Value}")
            .SetWorkingDirectory(RootDirectory)));

    // ----- TruffleHog secrets ---------------------------------------------

    Target SecurityScanSecrets => _ => _
        .Requires(() => TrufflehogTool is not null)
        .Description("TruffleHog filesystem scan emitting JSONL findings (one per line). --no-verification keeps this offline and fast; verification can be re-enabled in CI when network egress is allowed. NOTE: bypasses Tamp.TruffleHog.V3.SetOutput due to TAM-263 — TruffleHog v3 has no --output flag, so we capture stdout to a file directly.")
        .Executes(() => RunTrufflehog());

    void RunTrufflehog()
    {
        SecurityArtifactsDir.CreateDirectory();
        var excludeFile = (RootDirectory / "build" / ".trufflehogignore").Value;
        var psi = new System.Diagnostics.ProcessStartInfo(TrufflehogTool!.Executable.Value)
        {
            // --exclude-paths skips node_modules, .git, artifacts, build outputs.
            // Without this TruffleHog walks the full web/node_modules tree and
            // never returns — every file gets every detector regex applied.
            ArgumentList =
            {
                "filesystem", ".",
                "--json", "--no-verification", "--no-update",
                "--exclude-paths", excludeFile,
            },
            WorkingDirectory = RootDirectory.Value,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false,
        };
        using var proc = System.Diagnostics.Process.Start(psi)!;
        using (var sw = File.CreateText(TrufflehogJsonFile.Value))
        {
            sw.Write(proc.StandardOutput.ReadToEnd());
        }
        // Drain stderr so the buffer doesn't deadlock; ignore the
        // contents — trufflehog logs progress there.
        proc.StandardError.ReadToEnd();
        proc.WaitForExit();
        if (proc.ExitCode != 0)
        {
            Console.WriteLine($"[security] TruffleHog exited {proc.ExitCode} — output may be partial.");
        }
    }

    // ----- Ingestion -------------------------------------------------------

    Target Ingest => _ => _
        .Description("POST every artifact under artifacts/security/ to the running tamp.findings API. Run ScanAll first to produce the artifacts; the API process must be up.")
        .Executes(async () =>
        {
            var ctx = BuildIngestContext();
            Console.WriteLine($"[ingest] target: {IngestUrl}  context: {ctx.Client}/{ctx.Project}/{ctx.Component} {ctx.Version} @{ctx.CommitSha?[..7]}");

            if (string.IsNullOrWhiteSpace(IngestToken))
            {
                throw new InvalidOperationException(
                    "TAMP_FINDINGS_INGEST_TOKEN is not set. Mint a cli_/prj_ token via the SPA's "
                  + "client settings dialog and put it in repo-root .env (gitignored).");
            }
            var client = new IngestClient(IngestUrl, IngestToken);

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
                var snapshotId = resp.GetProperty("sbomSnapshotId").GetGuid();
                Console.WriteLine($"[ingest] SBOM       → snapshot {snapshotId}  components={resp.GetProperty("componentsCount")}  deps={resp.GetProperty("dependenciesCount")}  vulns={resp.GetProperty("vulnerabilitiesCount")} (grype matches={grypeVulns})");

                // Registry enrichment populates LatestVersion for the just-
                // ingested components by hitting nuget.org / registry.npmjs.org.
                // ~3-4s for ~300 deps at 8 concurrent. Errors are individual-
                // component failures that don't stop the batch.
                var enrichResp = await client.EnrichSbomVersionsAsync(snapshotId);
                Console.WriteLine($"[ingest] Enrich     → checked={enrichResp.GetProperty("checked")} updated={enrichResp.GetProperty("updated")} cleared={enrichResp.GetProperty("cleared")} skipped={enrichResp.GetProperty("skipped")} errors={enrichResp.GetProperty("errors")}");

                // TFND-16: OsvScanner SARIF → Vulnerability upserts. After
                // Grype already enriched the SBOM, OSV-Scanner's findings get
                // matched back to SbomComponents by (Name, Version) so the
                // SBOM ring's "vulnerable" bucket reflects every known CVE,
                // not just the Grype-matched ones.
                var osvVulns = OsvScannerCveSarifMapper.Map(SecuritySarifCveFile.Value);
                if (osvVulns.Count > 0)
                {
                    var osvPayload = new OsvVulnerabilityUpsertRequestDto(
                        SnapshotId: snapshotId,
                        Vulnerabilities: osvVulns);
                    var osvResp = await client.PostOsvVulnerabilityUpsertAsync(osvPayload);
                    Console.WriteLine($"[ingest] OsvCveMatch → matched {osvResp.GetProperty("matched")} / {osvVulns.Count}  inserted {osvResp.GetProperty("inserted")}  updated {osvResp.GetProperty("updated")}  unmatched {osvResp.GetProperty("unmatched")}");
                }
                else
                {
                    Console.WriteLine("[ingest] OsvCveMatch — no parseable CVE rows in cve.sarif (clean scan or 0 matches)");
                }
            }
            else
            {
                Console.WriteLine($"[ingest] SBOM       — file not found at {SecuritySbomFile.Value}, skipping");
            }

            await PostSarifAsync(client, ctx, SecuritySarifSastFile, "SAST");
            await PostSarifAsync(client, ctx, SecuritySarifResharperFile, "ReSharper");
            await PostSarifAsync(client, ctx, SecuritySarifCveFile, "CVE");
            await PostSarifAsync(client, ctx, SecuritySarifTrivyFile, "Trivy");
            // ESLint findings target web/src — post to the "web" flavor so
            // they attach to the same ComponentVersion as the SPA coverage
            // (VitestCoverageIngestMapper also writes Flavor="web").
            var webCtx = ctx with { Flavor = "web" };
            await PostSarifAsync(client, webCtx, SecuritySarifEslintFile, "ESLint");
            // TFND-27: axe-core a11y findings also target the SPA → "web" flavor.
            await PostSarifAsync(client, webCtx, SecuritySarifAxeCoreFile, "AxeCore");

            // TruffleHog jsonl is not SARIF — its own adapter.
            var trufflehog = TrufflehogIngestMapper.Map(TrufflehogJsonFile.Value, ctx);
            if (trufflehog is null)
            {
                Console.WriteLine("[ingest] TruffleHog — no secrets in jsonl (file missing or empty)");
            }
            else
            {
                var resp = await client.PostFindingsAsync(trufflehog);
                Console.WriteLine($"[ingest] TruffleHog → +{resp.GetProperty("findingsInserted")} ~{resp.GetProperty("findingsUpdated")} ↺{resp.GetProperty("findingsReopened")} ✓{resp.GetProperty("findingsClosed")} ⊘{resp.GetProperty("findingsSuppressed")}");
            }

            // Coverage (.NET / Coverlet OpenCover): scan every opencover.xml
            // under artifacts/test-results, aggregate, POST. Skips when the
            // Test target hasn't run.
            var coverage = CoverageIngestMapper.Map(TestResults.Value, ctx, RootDirectory.Value);
            if (coverage is null)
            {
                Console.WriteLine($"[ingest] Coverage   — no opencover.xml under {TestResults.Value}, skipping");
            }
            else
            {
                var resp = await client.PostCoverageAsync(coverage);
                Console.WriteLine($"[ingest] Coverage   → {coverage.SequenceCoverage:F1}% sequence  ({resp.GetProperty("modulesCount")} modules, {coverage.CoveredSequences}/{coverage.TotalSequences} points)");
            }

            // Coverage (SPA / Vitest lcov): same DTO shape, posts as a separate
            // ComponentVersion via Flavor="web" so the dashboard rolls up both
            // flavors but each is independently replaceable.
            var lcov = SpaTestResults / "lcov.info";
            var spaCoverage = VitestCoverageIngestMapper.Map(lcov.Value, ctx, RootDirectory.Value, SpaProjectDir.Value);
            if (spaCoverage is null)
            {
                Console.WriteLine($"[ingest] CoverageSPA — no lcov.info at {lcov.Value}, skipping (run nuke TestSpa first)");
            }
            else
            {
                var resp = await client.PostCoverageAsync(spaCoverage);
                Console.WriteLine($"[ingest] CoverageSPA → {spaCoverage.SequenceCoverage:F1}% sequence  ({resp.GetProperty("modulesCount")} modules, {spaCoverage.CoveredSequences}/{spaCoverage.TotalSequences} points)");
            }

            // Test results (TFND-20): TRX → TestRunReport. Same artifacts dir
            // as coverage; same replace-on-ingest semantic.
            var trxPayload = TestResultsIngestMapper.Map(TestResults.Value, ctx);
            if (trxPayload is null)
            {
                Console.WriteLine($"[ingest] TestResults — no *.trx under {TestResults.Value}, skipping");
            }
            else
            {
                var resp = await client.PostTestResultsAsync(trxPayload);
                Console.WriteLine($"[ingest] TestResults → {trxPayload.PassedCount}p / {trxPayload.FailedCount}f / {trxPayload.SkippedCount}s ({resp.GetProperty("suitesCount")} suites, {resp.GetProperty("casesCount")} cases)");
            }

            // Scan-run receipts (TFND-15): one row per scanner that left an
            // artifact on disk, regardless of whether it found anything. The
            // dashboard uses these to distinguish "ran clean" from "never ran".
            var receipts = new List<ScanRunReceiptDto>();
            // OpenGrep has its own SARIF in addition to being merged into
            // sast.sarif. Reading both ensures a clean OpenGrep run (0 findings,
            // sometimes dropped from the merge) still gets a receipt.
            receipts.AddRange(ScanRunReceiptBuilder.FromSarif(SecuritySarifOpenGrepFile.Value));
            receipts.AddRange(ScanRunReceiptBuilder.FromSarif(SecuritySarifSastFile.Value));
            receipts.AddRange(ScanRunReceiptBuilder.FromSarif(SecuritySarifResharperFile.Value));
            receipts.AddRange(ScanRunReceiptBuilder.FromSarif(SecuritySarifCveFile.Value));
            receipts.AddRange(ScanRunReceiptBuilder.FromSarif(SecuritySarifTrivyFile.Value));
            receipts.AddRange(ScanRunReceiptBuilder.FromSarif(SecuritySarifEslintFile.Value));
            // TFND-27: axe-core receipt — same SARIF shape as the others.
            receipts.AddRange(ScanRunReceiptBuilder.FromSarif(SecuritySarifAxeCoreFile.Value));
            var thReceipt = ScanRunReceiptBuilder.FromTrufflehogJsonl(TrufflehogJsonFile.Value);
            if (thReceipt is not null) receipts.Add(thReceipt);
            // Dedup by scanner (the merged sast.sarif may have already
            // emitted a Roslyn receipt that resharper.sarif would re-emit).
            // Keep the entry with the latest CompletedAt.
            var dedup = receipts
                .GroupBy(r => r.Scanner)
                .Select(g => g.OrderByDescending(r => r.CompletedAt).First())
                .ToList();
            // Receipts represent the build cycle, not the flavor. A single
            // OpenGrep run scans both src/ AND web/src/; splitting by
            // flavor (so ESLint went to web, OpenGrep went to net10)
            // makes the dashboard look like OpenGrep skipped the SPA.
            // All receipts attach to the canonical (default-flavor) CV;
            // the UI presents one row per commit aggregating all scanners.
            if (dedup.Count > 0)
            {
                var payload = new ScanRunIngestRequestDto(
                    Client: ctx.Client,
                    Project: ctx.Project,
                    Component: ctx.Component,
                    ComponentKind: ctx.ComponentKind,
                    Flavor: ctx.Flavor,
                    Version: ctx.Version,
                    CommitSha: ctx.CommitSha,
                    Branch: ctx.Branch,
                    BuildId: ctx.BuildId,
                    PullRequestRef: ctx.PullRequestRef,
                    Receipts: dedup);
                var resp = await client.PostScanRunsAsync(payload);
                Console.WriteLine($"[ingest] ScanRuns   → {resp.GetProperty("receiptsUpserted")} receipt(s) ({string.Join(", ", dedup.Select(r => $"{r.Scanner}={r.FindingsCount}"))})");
            }
            else
            {
                Console.WriteLine("[ingest] ScanRuns   — no scan artifacts to receipt");
            }
        });

    Target ScanAll => _ => _
        .DependsOn(nameof(Sbom), nameof(SecurityScanGrype), nameof(SecurityScan), nameof(SecurityScanCveSbom), nameof(SecurityScanTrivy), nameof(SecurityScanSecrets))
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
            Project: "Tamp",
            Component: "tamp.findings",
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
            Console.WriteLine($"[ingest] {label,-10} → scanner={payload.Scanner,-12} +{resp.GetProperty("findingsInserted")} ~{resp.GetProperty("findingsUpdated")} ↺{resp.GetProperty("findingsReopened")} ✓{resp.GetProperty("findingsClosed")} ⊘{resp.GetProperty("findingsSuppressed")}");
        }
        if (totalPosted == 0)
        {
            Console.WriteLine($"[ingest] {label,-10} — file present but no findings to post");
        }
    }
}
