using Tamp.Findings.Domain.Entities;
using Tamp.Findings.Domain.Values;

namespace Tamp.Findings.Domain.Compliance;

// The shipped operational + supply-chain mandate pack (TFND-188 / ADR 0010 §7). The
// partition (confirmed with the tamp agent 2026-09-28) is by DERIVATION SOURCE:
//   - Findings' lane = build-evidence-derived supply-chain (SSDF / secure-software
//     attestation lineage).
//   - ztt's lane = operational-posture from ADR/config (encryption, MFA, IPv6) PLUS
//     logging/EL maturity (M-21-31) — operational, not build-derived.
// Each mandate crosswalks back to an EO directive (ADR 0011); the registry is the single
// source of truth for whether that directive is live as of a date. Admin-tunable; seeded
// idempotently by Version.
public static class MandatePackDefaults
{
    public const string PackVersion = "2026-09-28";

    public static MandatePack Build() => new()
    {
        Version = PackVersion,
        IsCurrent = true,
        IsSeeded = true,
        Mandates =
        [
            // ── ztt operational lane ──
            new() { MandateId = "encrypt-at-rest", Title = "Encrypt data at rest", Tool = MandateTool.Ztt,
                    ApplicabilityRule = "has-data-store", DerivationRuleRef = "encrypt-at-rest",
                    PoamSeverity = Severity.High, SourceDirectiveRef = "M-22-09-encrypt-rest" },
            new() { MandateId = "encrypt-in-transit", Title = "Encrypt data in transit", Tool = MandateTool.Ztt,
                    ApplicabilityRule = "has-network-surface", DerivationRuleRef = "encrypt-in-transit",
                    PoamSeverity = Severity.High, SourceDirectiveRef = "M-22-09-encrypt-transit" },
            new() { MandateId = "mfa", Title = "Phishing-resistant multi-factor authentication", Tool = MandateTool.Ztt,
                    ApplicabilityRule = "has-users", DerivationRuleRef = "mfa",
                    PoamSeverity = Severity.High, SourceDirectiveRef = "M-22-09-mfa" },
            new() { MandateId = "ipv6", Title = "IPv6 capability (where applicable)", Tool = MandateTool.Ztt,
                    ApplicabilityRule = "has-network-surface", DerivationRuleRef = "ipv6",
                    PoamSeverity = Severity.Medium, SourceDirectiveRef = "M-21-07-ipv6" },
            new() { MandateId = "logging-maturity", Title = "Event logging maturity (EL)", Tool = MandateTool.Ztt,
                    ApplicabilityRule = null, DerivationRuleRef = "logging-maturity",
                    PoamSeverity = Severity.Medium, SourceDirectiveRef = "M-21-31-logging" },

            // ── findings supply-chain lane ──
            new() { MandateId = "secure-software-attestation", Title = "Secure-software development self-attestation",
                    Tool = MandateTool.Findings, ApplicabilityRule = null, DerivationRuleRef = "secure-software-attestation",
                    PoamSeverity = Severity.High, SourceDirectiveRef = "M-22-18-attestation" },
        ],
    };
}
