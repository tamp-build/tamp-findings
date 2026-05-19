using Tamp;
using Tamp.NetCli.V10;
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

    AbsolutePath Artifacts => RootDirectory / "artifacts";
    AbsolutePath CoverageDir => Artifacts / "coverage";
    AbsolutePath TestResults => Artifacts / "test-results";

    // ----- SecurityPipelineBuild overrides --------------------------------

    protected override string SecurityProductName => "tamp.findings";
    protected override string SecuritySolutionPath => Solution.Path;

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
            // Per-project coverage XML lives under artifacts/test-results/<guid>/coverage.opencover.xml
            // — leave aggregation to ReportGenerator when we wire it in.
            Console.WriteLine($"  Coverage outputs landed under {TestResults.Value}");
        });

    Target Ci => _ => _
        .DependsOn(nameof(Info), nameof(Compile), nameof(Test), nameof(Coverage))
        .Description("Local CI: build, test, coverage. Security target runs separately for now (needs scanner CLIs).");
}
