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
    // DAST via Tamp.Nuclei 0.1.0 (TAM-280). Template-driven probing of a
    // deployed target, plus fuzzing templates under -dast. Zap (8) has been
    // in the vocabulary since v1 but had no producer until Tamp.Zap
    // (TAM-278); both now feed the dast sub-category.
    // TODO(TAM-280): add Nuclei to the tamp-ingest-v1 ScannerKind vocabulary
    // (spec §3.1) — until then the typed client maps it to Unknown, so the
    // build posts the wire value directly.
    Nuclei = 23,
}
