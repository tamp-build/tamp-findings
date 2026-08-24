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
using Tamp.Zap;
using ZapCli = Tamp.Zap.Zap;
using Tamp.Nuclei;
using NucleiCli = Tamp.Nuclei.Nuclei;
using System.Text.Json;
using Tamp.Docker.V27;
using DockerCli = Tamp.Docker.V27.Docker;
using Tamp.Kubectl;
using KubectlCli = Tamp.Kubectl.Kubectl;

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
    // Where the Node-based scanners live.
    //
    // It used to be web/, whose devDependencies carried @axe-core/cli and
    // eslint. TFND-128 retired web/ — and took the accessibility scan with it,
    // silently: AxeCoreBinaryResolver simply reported "not installed" and the
    // target skipped, so a scan that had been running stopped running and
    // nothing said so.
    //
    // build/tools/node/ has no application in it, only the two CLIs the build
    // shells out to. That is the honest home for them now: this repository has
    // no JavaScript application, but it still has a browser-rendered UI that
    // Section 508 applies to.
    AbsolutePath NodeToolsDir => RootDirectory / "build" / "tools" / "node";
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
    // TFND-38 / TAM-278 / TAM-280: DAST SARIF against a deployed target.
    // Both scanners emit SARIF natively, so unlike axe-core there's no
    // converter leg.
    AbsolutePath SecuritySarifZapFile => RootDirectory / "artifacts" / "security" / "zap.sarif";
    AbsolutePath SecuritySarifNucleiFile => RootDirectory / "artifacts" / "security" / "nuclei.sarif";

    // The deployed (or locally running) SPA URL axe-core scans. Defaults to
    // the Vite dev server; set TAMP_FINDINGS_AXE_TARGET_URL in CI to point
    // at the staging URL. Empty value → SecurityScanAxeCore skips with a
    // clear log line instead of failing.
#pragma warning disable CS0649
    [Parameter("Target URL for axe-core a11y scan (defaults to local dev SPA)", EnvironmentVariable = "TAMP_FINDINGS_AXE_TARGET_URL")]
    readonly string? AxeTargetUrl;

    // TFND-38: deployed target for the DAST leg. Separate from AxeTargetUrl
    // because axe-core scans the SPA specifically while ZAP/Nuclei scan the
    // whole running service. Empty → both DAST targets skip with a clear log
    // line rather than failing the build.
    [Parameter("Target URL for the DAST scan (ZAP / Nuclei)", EnvironmentVariable = "TAMP_FINDINGS_DAST_TARGET_URL")]
    readonly string? DastTargetUrl;

    // ZAP runs in a container and bind-mounts its work directory, so that path
    // has to be one the Docker daemon can actually mount. The repo checkout
    // isn't always: Docker Desktop file sharing may not cover the drive, and
    // restricted CI runners often only allow mounts under a scratch path.
    // Override to relocate the scan's scratch space; the SARIF is copied back
    // into artifacts/security either way, so nothing downstream changes.
    [Parameter("Host directory ZAP bind-mounts as its work dir (default: artifacts/security)", EnvironmentVariable = "TAMP_FINDINGS_ZAP_WORK_DIR")]
    readonly string? ZapWorkDirOverride;

    // Which ZAP plan to run. Default "anonymous" is spider + passive rules
    // only, safe against any environment. "active" adds the AJAX spider and a
    // full active scan, which SUBMITS FORMS AND FUZZES PARAMETERS — it will
    // create, modify and delete data through whatever endpoints answer. It is
    // opt-in by name for that reason: nobody should reach it by leaving an
    // env var set from a previous run.
    [Parameter("ZAP scan profile: anonymous (default, passive) | active (DESTRUCTIVE, disposable targets only)", EnvironmentVariable = "TAMP_FINDINGS_ZAP_PROFILE")]
    readonly string? ZapProfile;

    // Hierarchy overrides. The dogfood path scans this repo and posts under
    // BrewingCoder/tamp/tamp-findings, but a dynamic scan can target ANY
    // deployed app — that's the point of the dashboard being multi-tenant.
    // Set these to file a scan of an external target under its own hierarchy
    // instead of silently attributing it to this repo.
    [Parameter("Docker --network for the ZAP container. Defaults to 'host' on Linux; unset elsewhere.",
        EnvironmentVariable = "TAMP_FINDINGS_ZAP_NETWORK")]
    readonly string? ZapNetworkMode;

    [Parameter("Ingest client name override", EnvironmentVariable = "TAMP_FINDINGS_INGEST_CLIENT")]
    readonly string? IngestClientOverride;

    [Parameter("Ingest project name override", EnvironmentVariable = "TAMP_FINDINGS_INGEST_PROJECT")]
    readonly string? IngestProjectOverride;

    [Parameter("Ingest component name override", EnvironmentVariable = "TAMP_FINDINGS_INGEST_COMPONENT")]
    readonly string? IngestComponentOverride;
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
                // web/ was retired with the SPA (TFND-128). The target stayed
                // behind pointing at a directory that no longer exists — which
                // OpenGrep tolerates silently, so nothing said so.
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

            // A clean scan still has to leave evidence it happened.
            //
            // Nuclei writes no SARIF when it finds nothing, so the receipt
            // builder — which reads receipts OUT of the SARIF — produced
            // nothing either, and the dashboard showed Nuclei as "never ran".
            // That is the precise defect this product exists to make visible,
            // occurring in its own pipeline: a scan that ran clean and a scan
            // that never happened looked identical.
            //
            // Writing the empty-but-valid report is how every other scanner in
            // the chain already behaves (OpenGrep reports 0 findings and gets a
            // receipt saying so).
            if (rc == 0 && !File.Exists(SecuritySarifNucleiFile.Value))
            {
                Console.WriteLine("[security] Nuclei found nothing — writing an empty SARIF so the run still gets a receipt.");
                File.WriteAllText(SecuritySarifNucleiFile.Value, EmptySarif("nuclei"));
            }
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
        .Description("ESLint v9 SARIF. Skips unless a JavaScript/TypeScript source tree and an eslint install are present — there is none in this repository since TFND-128, and the target stays for tenants that have one.")
        .Executes(() =>
        {
            SecurityArtifactsDir.CreateDirectory();
            if (!EslintBinaryResolver.IsAvailable(NodeToolsDir.Value))
            {
                Console.WriteLine($"[security] ESLint skipped — no install found at {NodeToolsDir}. This repository has no JavaScript application since TFND-128; the target stays wired for tenants that do.");
                return;
            }
            var plan = EslintCli.Scan(s => s
                .SetWorkingDirectory(NodeToolsDir.Value)
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
        .Description("axe-core a11y SARIF against the running app (TFND-27 / TFND-131). Requires @axe-core/cli + axe-sarif-converter under build/tools/node.")
        .Executes(() =>
        {
            SecurityArtifactsDir.CreateDirectory();
            // The app and the API are one host since TFND-128 retired the
            // separate Vite dev server on :5173, so the ingest URL IS the URL
            // to scan. Rewriting the port here used to point axe at a server
            // that is no longer started.
            var url = string.IsNullOrWhiteSpace(AxeTargetUrl) ? IngestUrl : AxeTargetUrl;
            if (string.IsNullOrWhiteSpace(url))
            {
                Console.WriteLine("[security] AxeCore skipped — no target URL (set TAMP_FINDINGS_AXE_TARGET_URL).");
                return;
            }
            if (!AxeCoreBinaryResolver.IsAvailable(NodeToolsDir.Value))
            {
                Console.WriteLine($"[security] AxeCore skipped — @axe-core/cli + axe-sarif-converter not installed at {NodeToolsDir} (pnpm install --dir build/tools/node).");
                return;
            }

            var scanPlan = AxeCoreCli.Scan(s => s
                .SetWorkingDirectory(NodeToolsDir.Value)
                .AddUrl(url)
                .SetOutputFile(SecurityJsonAxeCoreFile.Value)
                .AddTag("wcag2a").AddTag("wcag2aa").AddTag("wcag21aa").AddTag("best-practice")
                // "chrome-headless", not "chromium": @axe-core/cli 4.13 throws
                // "Unknown browser chromium" outright. Headless because CI has
                // no display, and the GitHub runners ship Chrome.
                .SetBrowser("chrome-headless")
                // No SetNoSandbox: @axe-core/cli 4.10 rejects --no-sandbox
                // outright ("error: unknown option"). It exited 1, which the
                // check below used to read as "violations found", so a
                // rejected argument looked like a completed scan.
                .SetTimeoutSeconds(60)
                .SetLoadDelayMs(2000));
            var scanRc = ProcessRunner.Execute(scanPlan, Console.Out, Console.Error);
            // axe-core: 0 = no violations, 1 = violations found (still a
            // successful scan), 2+ = tool error. Mirrors ESLint posture.
            if (scanRc > 1) throw new Exception($"axe-core exited with {scanRc}");

            // Exit code alone is not enough. A CLI that rejects an argument
            // also exits 1, and "1" here is supposed to mean "violations
            // found" — so the only trustworthy evidence that a scan happened
            // is the file it was asked to write. Without this, a broken
            // invocation reads as a clean run and the converter is handed
            // nothing, which is exactly how this failed in CI.
            if (!File.Exists(SecurityJsonAxeCoreFile.Value))
            {
                throw new Exception(
                    $"axe-core exited {scanRc} but wrote no results to {SecurityJsonAxeCoreFile.Value}. "
                  + "That is a tool error, not a clean scan — check the arguments above.");
            }

            var sarifPlan = AxeCoreCli.ConvertToSarif(s => s
                .SetWorkingDirectory(NodeToolsDir.Value)
                .SetInputFile(SecurityJsonAxeCoreFile.Value)
                .SetOutputFile(SecuritySarifAxeCoreFile.Value));
            var convertRc = ProcessRunner.Execute(sarifPlan, Console.Out, Console.Error);
            if (convertRc != 0) throw new Exception($"axe-sarif-converter exited with {convertRc}");
        });

    // TFND-38 / TAM-278: ZAP DAST via Tamp.Zap 0.1.0.
    //
    // Runs the Automation Framework rather than the packaged zap-baseline.py:
    // the framework composes contexts/auth, spec import, spidering, scanning
    // and reporting as one declarative plan, and the packaged scripts have no
    // way to express an authentication context.
    //
    // Anonymous profile deliberately. It spiders and runs passive rules only,
    // so it is safe against any environment, and its job is to assert that
    // nothing outside the intended public allow-list answers without
    // credentials. The authenticated + active profiles need a disposable
    // target and a session/token, which is a separate opt-in target.
    /// <summary>
    /// A valid SARIF 2.1.0 log with no results.
    ///
    /// For scanners that write nothing when they find nothing. The receipt is
    /// built from the SARIF, so "no file" and "no findings" are the same thing
    /// downstream — and they must not be, because one of them means nobody
    /// looked.
    /// </summary>
    static string EmptySarif(string toolName) =>
        """
        {
          "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
          "version": "2.1.0",
          "runs": [
            { "tool": { "driver": { "name": "TOOL_NAME" } }, "results": [] }
          ]
        }
        """.Replace("TOOL_NAME", toolName);

    Target SecurityScanZap => _ => _
        .Description("ZAP DAST (anonymous baseline) against the deployed app; SARIF for /ingest/findings. Requires Docker.")
        .Executes(() =>
        {
            SecurityArtifactsDir.CreateDirectory();
            if (string.IsNullOrWhiteSpace(DastTargetUrl))
            {
                Console.WriteLine("[security] ZAP skipped — no target URL (set TAMP_FINDINGS_DAST_TARGET_URL).");
                return;
            }

            var workDir = string.IsNullOrWhiteSpace(ZapWorkDirOverride)
                ? SecurityArtifactsDir
                : AbsolutePath.Create(ZapWorkDirOverride!);
            workDir.CreateDirectory();

            // Fingerprinted bundles are excluded: their filenames change every
            // SPA build, so a finding against one gets a new identity on each
            // deploy and can never be triaged or trended. The first real scan
            // put four of five discovered routes on /assets/index-<hash>.*.
            var excludes = ZapAutomationPlan.DefaultAssetExcludes;
            var active = string.Equals(ZapProfile, "active", StringComparison.OrdinalIgnoreCase);
            if (active)
            {
                Console.WriteLine($"[security] ZAP profile=ACTIVE against {DastTargetUrl} — this submits forms and fuzzes parameters; it WILL write through any endpoint that answers.");
            }

            var planFile = ZapAutomationPlan.Write(
                workDir / (active ? "zap-active.yaml" : "zap-anon.yaml"),
                active
                    ? ZapAutomationPlan.Active(DastTargetUrl!, SecuritySarifZapFile.Name, excludePaths: excludes)
                    : ZapAutomationPlan.Anonymous(DastTargetUrl!, SecuritySarifZapFile.Name, excludePaths: excludes));

            // ZAP runs in a CONTAINER, so 127.0.0.1 inside it is ZAP's own
            // loopback — not the host. Against a target on the build machine
            // that is a flat "Connection refused", which is how the first CI
            // run failed even though the app was up and answering.
            //
            // On Linux, --network host puts ZAP in the host's namespace and
            // 127.0.0.1 means what the caller meant. Elsewhere (Docker Desktop)
            // there is no host networking and the target should be addressed
            // as host.docker.internal instead, so the mode is left unset.
            var networkMode = string.IsNullOrWhiteSpace(ZapNetworkMode)
                ? (OperatingSystem.IsLinux() ? "host" : null)
                : ZapNetworkMode;

            if (networkMode is not null)
                Console.WriteLine($"[security] ZAP container network: {networkMode}");

            var plan = ZapCli.Automation(s => s
                .SetWorkingDirectory(RootDirectory)
                .SetWorkDirectory(workDir)
                .SetNetworkMode(networkMode)
                .SetPlanFile(planFile));

            var rc = ProcessRunner.Execute(plan, Console.Out, Console.Error);
            // The Automation Framework exits 0 when the plan completes,
            // regardless of what it found — findings live in the report. A
            // non-zero exit means the plan itself failed (bad YAML, target
            // unreachable, unknown report template), which is a real failure.
            if (rc != 0) throw new Exception($"zap exited with {rc}");

            // Bring the report back under artifacts/security so the Ingest
            // target finds it at the usual path regardless of where the scan
            // ran — and resolve the name through the wrapper, because ZAP
            // appends the template extension (zap.sarif -> zap.sarif.json).
            var produced = workDir / ZapAutomationPlan.SarifReportFileOnDisk(SecuritySarifZapFile.Name);
            if (!File.Exists(produced))
                throw new Exception($"zap reported success but produced no report at {produced}");
            if (produced.Value != SecuritySarifZapFile.Value)
            {
                produced.CopyTo(SecuritySarifZapFile, overwrite: true);
                Console.WriteLine($"[security] ZAP report {produced.Name} -> {SecuritySarifZapFile}");
            }
        });

    // TFND-38 / TAM-280: Nuclei DAST via Tamp.Nuclei 0.1.0.
    //
    // Template-driven probing, not fuzzing: -dast is deliberately NOT set
    // here. Fuzzing templates submit crafted payloads to every parameter they
    // find, which creates/modifies/deletes data through whatever endpoints
    // answer — fine against a disposable target, not something the default
    // pipeline should do. Info severity is excluded because the corpus emits a
    // large volume of fingerprinting notes that would swamp the findings list.
    //
    // -duc pins the template set for this run: the corpus moves daily, and an
    // unpinned scan can report a finding today it didn't yesterday with no
    // code change to explain it. -ni keeps out-of-band callbacks off a
    // third-party interactsh server.
    Target SecurityScanNuclei => _ => _
        .Description("Nuclei template scan against the deployed app; SARIF for /ingest/findings. Requires the nuclei binary on PATH.")
        .Executes(() =>
        {
            SecurityArtifactsDir.CreateDirectory();
            if (string.IsNullOrWhiteSpace(DastTargetUrl))
            {
                Console.WriteLine("[security] Nuclei skipped — no target URL (set TAMP_FINDINGS_DAST_TARGET_URL).");
                return;
            }
            if (Tool.TryFromPath("nuclei", RootDirectory.Value) is null)
            {
                Console.WriteLine("[security] Nuclei skipped — nuclei not on PATH (go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest).");
                return;
            }

            // Pre-flight the target from THIS host, because nuclei's failure
            // mode here is silent: when it can't resolve or reach a target it
            // logs "Skipped ... found unresponsive permanently", reports
            // "No results found", writes no SARIF, and exits 0. A scan that
            // never ran is then indistinguishable from a clean one — the worst
            // possible outcome for a security gate. Observed with
            // http://localhost:3000, which nuclei failed to resolve while curl
            // on the same box was fine.
            using (var probe = new HttpClient { Timeout = TimeSpan.FromSeconds(15) })
            {
                try
                {
                    var resp = probe.GetAsync(DastTargetUrl!).GetAwaiter().GetResult();
                    Console.WriteLine($"[security] Nuclei pre-flight {DastTargetUrl} -> {(int)resp.StatusCode}");
                }
                catch (Exception ex)
                {
                    throw new Exception(
                        $"Nuclei target {DastTargetUrl} is not reachable from the build host ({ex.Message}). " +
                        "Refusing to run: nuclei would report a clean scan for an unreachable target. " +
                        "If the app is on this machine, prefer 127.0.0.1 over localhost — nuclei does not always resolve it.");
                }
            }

            var plan = NucleiCli.Scan(s => s
                .SetWorkingDirectory(RootDirectory)
                .AddTarget(DastTargetUrl!)
                .SetSarifExportFile(SecuritySarifNucleiFile.Value)
                .AddExcludeSeverity(NucleiSeverity.Info)
                .SetNoInteractsh()
                .SetDisableUpdateCheck()
                .SetSilent()
                .SetNoColor());

            var rc = ProcessRunner.Execute(plan, Console.Out, Console.Error);
            // Nuclei exits 0 on a completed scan whether or not it found
            // anything. Non-zero means the scan failed — do NOT copy the
            // `rc > 1` pattern used for OpenGrep/ESLint here.
            if (rc != 0) throw new Exception($"nuclei exited with {rc}");
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

    // TestSpa is gone with web/ (TFND-128 / TFND-131). It ran Vitest in a
    // directory that no longer exists, so it could only ever fail — and it
    // would have failed at "pnpm: not found" on a machine with no Node, which
    // reads as a tooling problem rather than as a target that should not exist.

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

    Target InspectContainerImage => _ => _
        .Description("TFND-134: inspect the built image and its base, then POST both to /ingest/container-image. Requires trivy on PATH and the API up. Run DockerBuildImage first.")
        .Executes(async () =>
        {
            // FIRST, before the token check and before trivy runs. Being told
            // where this is aimed is only useful before the work, not after a
            // scan has already happened.
            WarnIfRemote();

            var ctx = BuildIngestContext();

            if (string.IsNullOrWhiteSpace(IngestToken))
            {
                throw new InvalidOperationException(
                    "TAMP_FINDINGS_INGEST_TOKEN is not set. Mint a cli_/prj_ token under the "
                  + "project's Settings > Ingest tokens and put it in repo-root .env (gitignored).");
            }

            if (Tool.TryFromPath("trivy", RootDirectory.Value) is null)
            {
                throw new InvalidOperationException(
                    "trivy is not on PATH. Install it (winget/brew/apt) — this target reads image "
                  + "metadata, so it needs no vulnerability database and runs in about a second.");
            }

            SecurityArtifactsDir.CreateDirectory();

            // The image we just built. LOCAL on purpose: it may not be pushed
            // yet, so there is nothing in a registry to read.
            var appReport = (SecurityArtifactsDir / "container-image.json").Value;
            RunTrivy(ContainerImageInspector.InspectArgs(ImageRefShaTag, appReport, remoteOnly: false));
            var app = ContainerImageInspector.Parse(File.ReadAllText(appReport));

            Console.WriteLine($"[image] {app.Reference}  built {app.Created:yyyy-MM-dd}  {app.OsFamily} {app.OsVersion}");

            // The base image, from the Dockerfile's FINAL stage — the earlier
            // SDK stage is a compiler that never ships, and scoring its age
            // would report a number about something nobody deploys.
            var baseRef = ContainerImageInspector.BaseImageOf(File.ReadAllText(RootDirectory / "Dockerfile"));

            ImageFacts? baseImage = null;
            if (baseRef is null)
            {
                Console.WriteLine("[image] base   — could not read a base image from the Dockerfile; reporting it as unidentified rather than guessing");
            }
            else
            {
                // REMOTE on purpose, and this is the one that bites. Trivy
                // prefers a local daemon copy, so a cached tag answers with the
                // date the cache was filled rather than the date the tag points
                // at now. Measured here: aspnet:10.0-alpine read 2026-05-12
                // from the daemon and 2026-08-10 from the registry — ninety
                // days, in the direction of making a current base look
                // neglected.
                var baseReport = (SecurityArtifactsDir / "container-base-image.json").Value;
                RunTrivy(ContainerImageInspector.InspectArgs(baseRef, baseReport, remoteOnly: true));
                baseImage = ContainerImageInspector.Parse(File.ReadAllText(baseReport));

                Console.WriteLine($"[image] base   {baseRef}  published {baseImage.Created:yyyy-MM-dd}  {baseImage.OsFamily} {baseImage.OsVersion}");
            }

            var client = new IngestClient(IngestUrl, IngestToken);
            var payload = new ContainerImageIngestRequestDto(
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
                Reference: app.Reference ?? ImageRefShaTag,
                Digest: app.Digest,
                CreatedAt: app.Created,
                OsFamily: app.OsFamily,
                OsVersion: app.OsVersion,
                SizeBytes: app.SizeBytes,
                BaseImageReference: baseRef,
                BaseImageDigest: baseImage?.Digest,
                BaseImageCreatedAt: baseImage?.Created);

            var resp = await client.PostContainerImageAsync(payload);

            var age = resp.TryGetProperty("baseImageAgeInDays", out var a) && a.ValueKind != JsonValueKind.Null
                ? a.GetInt32().ToString()
                : "unknown";
            Console.WriteLine($"[ingest] Image      → base age {age} day(s)");

            // The API says what is MISSING rather than only returning 200. A
            // pipeline author who thinks they wired this up and did not should
            // find out from the call that was supposed to do it, not from a
            // gate reading Unknown three weeks later.
            if (resp.TryGetProperty("note", out var note) && note.ValueKind == JsonValueKind.String)
                Console.WriteLine($"[ingest] Image      ! {note.GetString()}");
        });

    /// <summary>
    /// Run trivy with the argv Tamp.Trivy.InspectImage produces.
    ///
    /// Direct rather than through the wrapper only because the InspectImage API
    /// is unreleased (TAM-282, Tamp.Trivy 1.11.2). Switch to
    /// <c>Trivy.InspectImage(s =&gt; s.SetImageRef(r).SetRemoteOnly())</c> and
    /// delete ContainerImageInspector once the package ships.
    /// </summary>
    void RunTrivy(string[] args)
    {
        // A CommandPlan rather than a Tool invocation, because ONE of these
        // arguments is the empty string (--scanners "") and that is what makes
        // this a metadata read rather than a scan. Joining argv into a command
        // line would drop it, Trivy would fall back to its default scanners,
        // and the "instant" inspect would quietly become a full vulnerability
        // scan with a database download attached.
        var plan = new CommandPlan
        {
            Executable = "trivy",
            Arguments = args,
            WorkingDirectory = RootDirectory.Value,
        };

        var rc = ProcessRunner.Execute(plan, Console.Out, Console.Error);
        if (rc == 0) return;

        // The overwhelmingly likely cause is a target that was never built,
        // and Trivy reports that as four stacked socket errors (docker,
        // containerd, podman, remote) which bury the one line that matters.
        // Naming the fix beats making somebody read all four.
        throw new Exception(
            $"trivy exited with {rc}. If the image was not found, build it first: "
          + "`dotnet run --project build -- DockerBuildImage`. If a BASE image was not found, "
          + "check the reference resolves from the registry — this target reads bases remotely "
          + "on purpose, so a stale local copy cannot answer with the wrong publish date.");
    }

    /// <summary>
    /// Say loudly when an ingest is aimed somewhere that is not this machine.
    ///
    /// The repo-root .env used to set TAMP_FINDINGS_URL to the cluster, which
    /// made PROD the default for every local run — an ingest target run by
    /// accident wrote to a shared instance. The default is local now, but a
    /// forgotten uncomment puts it back, and the failure is silent: the run
    /// succeeds, against the wrong instance.
    ///
    /// A banner rather than a prompt, deliberately. A prompt would hang CI,
    /// and posting to a remote instance is a legitimate thing to do on purpose
    /// — it just should not be a thing that happens without being noticed.
    /// </summary>
    void WarnIfRemote()
    {
        if (Uri.TryCreate(IngestUrl, UriKind.Absolute, out var uri)
            && (uri.IsLoopback || string.Equals(uri.Host, "localhost", StringComparison.OrdinalIgnoreCase)))
        {
            return;
        }

        Console.WriteLine();
        Console.WriteLine("  ┌──────────────────────────────────────────────────────────────┐");
        Console.WriteLine("  │  INGESTING TO A REMOTE INSTANCE                              │");
        Console.WriteLine("  └──────────────────────────────────────────────────────────────┘");
        Console.WriteLine($"  {IngestUrl}");
        Console.WriteLine("  Not localhost. If that was not deliberate, stop now and comment");
        Console.WriteLine("  TAMP_FINDINGS_URL back out of .env (see .env.example).");
        Console.WriteLine();
    }

    Target Ingest => _ => _
        .Description("POST every artifact under artifacts/security/ to the running tamp.findings API. Run ScanAll first to produce the artifacts; the API process must be up.")
        .Executes(async () =>
        {
            var ctx = BuildIngestContext();
            WarnIfRemote();
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
            // The "web" flavor is the BROWSER-RENDERED SURFACE, which since
            // TFND-128 is served by the API project rather than by a separate
            // application. It is still a distinct flavor because what these
            // scanners look at — rendered markup and client assets — is a
            // different artefact from the compiled service, even though one
            // process now serves both.
            var webCtx = ctx with { Flavor = "web" };
            await PostSarifAsync(client, webCtx, SecuritySarifEslintFile, "ESLint");
            // TFND-27 / TFND-131: axe-core scans the rendered UI.
            await PostSarifAsync(client, webCtx, SecuritySarifAxeCoreFile, "AxeCore");

            // TFND-38: DAST findings attach to a "deployed" flavor rather than
            // "web". ESLint and axe-core scan web ASSETS; ZAP and Nuclei scan
            // the running SERVICE — API and SPA as one deployed unit — so
            // folding them into "web" would conflate two different things and
            // leave nowhere to hang which environment was scanned.
            var deployedCtx = ctx with { Flavor = "deployed" };
            await PostSarifAsync(client, deployedCtx, SecuritySarifZapFile, "ZAP");
            await PostSarifAsync(client, deployedCtx, SecuritySarifNucleiFile, "Nuclei");

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

            // No SPA coverage leg any more (TFND-128 / TFND-131). It posted a
            // separate ComponentVersion under Flavor="web" from a Vitest lcov
            // that nothing produces now. Leaving it in would have kept a
            // "web" flavor alive on the dashboard whose coverage silently
            // stopped updating — a stale number is worse than an absent one.

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
            // TFND-38: DAST receipts. These are what flip RanDast, which in
            // turn is what lets SSDF PW.8.1 answer "Yes" instead of capping at
            // "Partial — no dynamic analysis".
            receipts.AddRange(ScanRunReceiptBuilder.FromSarif(SecuritySarifZapFile.Value));
            receipts.AddRange(ScanRunReceiptBuilder.FromSarif(SecuritySarifNucleiFile.Value));
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

    // ----- TFND-43 lab cluster deploy -------------------------------------
    //
    // Three-step roll, all driven by Tamp.* wrappers:
    //   1. DockerBuildImage — `docker buildx build` against repo root,
    //      tags <registry>/tamp-findings:{sha,latest}.
    //   2. DockerPushImage  — push both tags to the lab registry.
    //   3. Deploy           — `kubectl apply -f deploy/k8s/` then
    //      `kubectl set image deploy/tamp-findings-api api=<image>:<sha>`
    //      followed by `kubectl rollout status` to wait for healthy.
    //
    // Image registry is `registry.home.local/tamp-findings:<tag>` —
    // referencing by node-IP fails ImagePullBackOff because containerd's
    // mirror config is keyed on `localhost:32000` (per microk8s agent).
    //
    // KUBECONFIG flows as an env var through Tamp.Kubectl's posture —
    // never as a --kubeconfig CLI flag (keeps the path out of the process
    // table). The Build inherits the env from the user's shell.

    [Parameter("Container image registry", EnvironmentVariable = "TAMP_FINDINGS_REGISTRY")]
    readonly string ImageRegistry = "registry.home.local";

    [Parameter("Container image name (without registry prefix)", EnvironmentVariable = "TAMP_FINDINGS_IMAGE_NAME")]
    readonly string ImageName = "tamp-findings";

    [Parameter("Cluster namespace", EnvironmentVariable = "TAMP_FINDINGS_NAMESPACE")]
    readonly string DeployNamespace = "tamp-findings";

    string ImageTag => Git.Commit is { Length: >= 7 } ? Git.Commit[..7] : "dev";
    string ImageRefShaTag => $"{ImageRegistry}/{ImageName}:{ImageTag}";
    string ImageRefLatestTag => $"{ImageRegistry}/{ImageName}:latest";

    Target DockerBuildImage => _ => _
        .Description("Build the multi-stage container image: pnpm build SPA → dotnet publish API → ASP.NET 10 alpine runtime. Tags both :<short-sha> and :latest.")
        .Executes(() =>
        {
            // Tamp.Docker.V27 resolves the docker binary internally — no
            // Tool parameter on the verb. We rely on `docker` being on
            // PATH; Docker Desktop / Rancher Desktop both put it there.
            var plan = DockerCli.Build(s => s
                .SetWorkingDirectory(RootDirectory)
                .SetDockerfile((RootDirectory / "Dockerfile").Value)
                .AddTag(ImageRefShaTag)
                .AddTag(ImageRefLatestTag)
                // SetLoad puts the image in the local engine's image
                // store so the subsequent Push step has something to
                // tag-and-push. Push-direct skips local but blocks a
                // local smoke `docker run`.
                .SetLoad(true)
                .SetContext("."));
            var rc = ProcessRunner.Execute(plan, Console.Out, Console.Error);
            if (rc != 0) throw new Exception($"docker build exited with {rc}");
            Console.WriteLine($"[deploy] built {ImageRefShaTag} (+ :latest)");
        });

    Target DockerPushImage => _ => _
        .DependsOn(nameof(DockerBuildImage))
        .Description("Push both tags to the lab registry.")
        .Executes(() =>
        {
            foreach (var tag in new[] { ImageRefShaTag, ImageRefLatestTag })
            {
                var plan = DockerCli.Push(s => s
                    .SetWorkingDirectory(RootDirectory)
                    .SetImage(tag));
                var rc = ProcessRunner.Execute(plan, Console.Out, Console.Error);
                if (rc != 0) throw new Exception($"docker push {tag} exited with {rc}");
                Console.WriteLine($"[deploy] pushed {tag}");
            }
        });

    Target Deploy => _ => _
        .DependsOn(nameof(DockerPushImage))
        .Description("Apply deploy/k8s/ then pin the api Deployment to the just-pushed image SHA and wait for rollout. KUBECONFIG flows from env.")
        .Executes(() =>
        {
            var kubectlTool = Tool.TryFromPath("kubectl", RootDirectory.Value)
                ?? throw new InvalidOperationException("kubectl not on PATH — install kubectl and point KUBECONFIG at the lab cluster.");

            // Apply ALL manifests under deploy/k8s/. Today that's just
            // api.yaml; future manifests (NetworkPolicy, HPA, etc.) drop
            // in here without changing the target.
            var applyPlan = KubectlCli.Apply(kubectlTool, s => s
                .SetWorkingDirectory(RootDirectory)
                .AddFile((RootDirectory / "deploy" / "k8s").Value)
                .SetRecursive(true)
                .SetNamespace(DeployNamespace));
            var applyRc = ProcessRunner.Execute(applyPlan, Console.Out, Console.Error);
            if (applyRc != 0) throw new Exception($"kubectl apply exited with {applyRc}");

            // Pin the api container to the just-pushed SHA tag. The apply
            // step uses whatever the YAML says (`:latest`); set-image
            // immediately overrides with the unique SHA so the pod
            // identifier matches the build that produced it. This is the
            // path that lets a fresh `:latest` push trigger a rollout
            // even when imagePullPolicy is honoured.
            var setImagePlan = KubectlCli.SetImage(kubectlTool, s => s
                .SetWorkingDirectory(RootDirectory)
                .SetNamespace(DeployNamespace)
                .SetResource("deployment/tamp-findings-api")
                .SetContainerImage("api", ImageRefShaTag));
            var setRc = ProcessRunner.Execute(setImagePlan, Console.Out, Console.Error);
            if (setRc != 0) throw new Exception($"kubectl set image exited with {setRc}");

            // Wait for the rollout to finish so Ci/CD knows when the new
            // pod is serving. Default 5m timeout is plenty for a single-
            // replica deployment; bump via Tamp.Kubectl's timeout knob if
            // migrations grow.
            var statusPlan = KubectlCli.RolloutStatus(kubectlTool, s => s
                .SetWorkingDirectory(RootDirectory)
                .SetNamespace(DeployNamespace)
                .SetResource("deployment/tamp-findings-api"));
            var statusRc = ProcessRunner.Execute(statusPlan, Console.Out, Console.Error);
            if (statusRc != 0) throw new Exception($"kubectl rollout status exited with {statusRc}");

            Console.WriteLine($"[deploy] ✓ tamp-findings-api now running {ImageRefShaTag} in ns/{DeployNamespace}");
        });

    Target ScanAll => _ => _
        .DependsOn(nameof(Sbom), nameof(SecurityScanGrype), nameof(SecurityScan), nameof(SecurityScanCveSbom), nameof(SecurityScanTrivy), nameof(SecurityScanSecrets))
        .Description("Run every scan in artifacts/security/. The API process MUST be stopped first — the Roslyn scan rebuilds with /p:NoIncremental=true and will fight a running API for the DLL locks. Follow up with the Ingest target after the API is back up.");

    // Deliberately NOT part of ScanAll. ScanAll's own description says the API
    // process must be stopped first (the Roslyn leg rebuilds and fights the
    // running API for DLL locks) — and DAST needs the exact opposite: a
    // deployed, running target. They're mutually exclusive by nature, so the
    // dynamic scans get their own aggregate.
    Target ScanDast => _ => _
        .DependsOn(nameof(SecurityScanZap), nameof(SecurityScanNuclei))
        .Description("Run the dynamic scans (ZAP + Nuclei) against TAMP_FINDINGS_DAST_TARGET_URL. Requires a DEPLOYED, running target — unlike ScanAll, which requires the API stopped. Follow with Ingest.");

    // Posts ONLY the dynamic-scan artifacts. The full Ingest target sweeps
    // every artifact in artifacts/security — correct when scanning this repo,
    // wrong when the DAST target is somebody else's app, because it would file
    // this repo's SBOM, coverage and SAST findings under that hierarchy.
    Target IngestDast => _ => _
        .Description("POST only the DAST SARIF + scan receipts. Use with the INGEST_CLIENT/PROJECT/COMPONENT overrides when the scan target isn't this repo.")
        .Executes(async () =>
        {
            var ctx = BuildIngestContext() with { Flavor = "deployed" };
            WarnIfRemote();
            Console.WriteLine($"[ingest] target: {IngestUrl}  context: {ctx.Client}/{ctx.Project}/{ctx.Component} ({ctx.Flavor})");
            var client = new IngestClient(IngestUrl, IngestToken);

            await PostSarifAsync(client, ctx, SecuritySarifZapFile, "ZAP");
            await PostSarifAsync(client, ctx, SecuritySarifNucleiFile, "Nuclei");

            var receipts = new List<ScanRunReceiptDto>();
            receipts.AddRange(ScanRunReceiptBuilder.FromSarif(SecuritySarifZapFile.Value));
            receipts.AddRange(ScanRunReceiptBuilder.FromSarif(SecuritySarifNucleiFile.Value));
            if (receipts.Count > 0)
            {
                var dedup = receipts
                    .GroupBy(r => r.Scanner)
                    .Select(g => g.OrderByDescending(r => r.CompletedAt).First())
                    .ToList();
                var payload = new ScanRunIngestRequestDto(
                    Client: ctx.Client,
                    Project: ctx.Project,
                    Component: ctx.Component,
                    ComponentKind: ctx.ComponentKind,
                    // Receipts attach to the canonical (default-flavor) CV so
                    // the build row aggregates every scanner for the commit.
                    Flavor: null,
                    Version: ctx.Version,
                    CommitSha: ctx.CommitSha,
                    Branch: ctx.Branch,
                    BuildId: ctx.BuildId,
                    PullRequestRef: ctx.PullRequestRef,
                    Receipts: dedup);
                var resp = await client.PostScanRunsAsync(payload);
                Console.WriteLine($"[ingest] ScanRuns   → {resp.GetProperty("receiptsUpserted")} receipt(s) ({string.Join(", ", dedup.Select(r => $"{r.Scanner}={r.FindingsCount}"))})");
            }
        });

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
            Client: IngestClientOverride ?? "BrewingCoder",
            Project: IngestProjectOverride ?? "tamp",
            Component: IngestComponentOverride ?? "tamp-findings",
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
