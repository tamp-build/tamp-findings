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
}
