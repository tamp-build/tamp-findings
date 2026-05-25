namespace Tamp.Findings.Domain.Values;

public enum ScannerKind
{
    Unknown = 0,
    OpenGrep = 1,
    TruffleHog = 2,
    CodeQL = 3,
    Trivy = 4,
    Checkov = 5,
    Tfsec = 6,
    Kics = 7,
    Zap = 8,
    Spectral = 9,
    Oasdiff = 10,
    Cosign = 11,
    NetArchTest = 12,
    DependencyCruiser = 13,
    Stryker = 14,
    Coverlet = 15,
    OsvScanner = 16,
    Roslyn = 17,
    Syft = 18,
    Grype = 19,
    ReSharper = 20,
    ESLint = 21,
    // TFND-27: axe-core a11y scanner via Tamp.AxeCore 0.1.0. Standalone
    // CLI scan of a deployed SPA URL; SARIF emitted by axe-sarif-converter.
    AxeCore = 22,
}
