namespace Tamp.Findings.Domain.Entities;

// Instance-wide settings. One row.
//
// Created for the separation-of-duties switch (TFND-72); the rest of the System
// panel's settings landed with TFND-113 on this entity rather than in a second
// table.
public sealed class InstanceSettings
{
    // Fixed id: there is exactly one row, and giving it a known key means the
    // read is a point lookup and a second row cannot be created by accident.
    public static readonly Guid SingletonId = new("00000000-0000-0000-0000-000000000001");

    public Guid Id { get; set; } = SingletonId;

    // Turns the SoD advisory into a refusal. DEFAULT OFF, deliberately: a
    // three-person team genuinely needs one person to hold two conflicting
    // roles, and refusing by default would make the product unusable for
    // exactly the organisation it is aimed at. Larger programs turn it on.
    public bool EnforceSeparationOfDuties { get; set; }

    // ---- TFND-113 ---------------------------------------------------------

    // How this deployment refers to itself in anything that leaves it: the
    // curl example on the settings screen, an attestation footer, an outbound
    // mail link. Inferred from the request when unset, which is right for a
    // single-host install and wrong the moment a reverse proxy is involved.
    public string? InstanceUrl { get; set; }

    // Retention, in days. Null means keep forever, which is the honest default
    // for a compliance tool: an attestation signed three years ago cites
    // findings from three years ago, and a retention job that quietly removed
    // them would make the signature unverifiable.
    public int? FindingRetentionDays { get; set; }
    public int? BuildRetentionDays { get; set; }

    // How long a sign-in lasts. Separate from the cookie's own lifetime so an
    // operator can shorten it without redeploying.
    public int SessionLifetimeHours { get; set; } = 24 * 7;

    // Outbound mail. Null host = no mail is sent at all, and the UI says so
    // rather than silently dropping notifications.
    public string? SmtpHost { get; set; }
    public int? SmtpPort { get; set; }
    public string? SmtpFrom { get; set; }

    // Scanners this deployment EXPECTS to receive.
    //
    // The point of the list, per the brief: a registered-but-never-seen scanner
    // is what makes "no scan" distinguishable from "clean". Without it, a
    // scanner that silently stopped reporting looks exactly like one that was
    // never part of the pipeline.
    //
    // Stored as ScannerKind names rather than ints so a reordered enum cannot
    // silently re-point an expectation at a different scanner.
    public List<string> ExpectedScanners { get; set; } = new();

    // ---- Sign-in policy (TFND-111) ----------------------------------------

    // Email domains allowed to register, as bare domains ("example.com").
    //
    // EMPTY MEANS NO RESTRICTION, and that is the honest default: a
    // self-hosted instance behind a VPN often has no need for one, and a
    // restriction nobody chose is a support call the first time a contractor
    // signs in.
    //
    // It gates REGISTRATION, not sign-in for existing users. Removing a domain
    // must not lock out people who already have accounts and roles — that is
    // what suspending a user is for, and doing it as a side effect of a policy
    // edit would be an access change nobody recorded as one.
    public List<string> AllowedEmailDomains { get; set; } = new();

    // Roles that must have signed in through a provider asserting MFA.
    //
    // Stored as ProjectRole names plus the literal "Admin" for the instance
    // flag, which is not a ProjectRole. Enforcement depends on the provider
    // being ABLE to assert it: an OIDC issuer returns `amr`, GitHub OAuth does
    // not. A requirement against a provider that cannot assert MFA would be a
    // control that silently does nothing.
    public List<string> MfaRequiredRoles { get; set; } = new();

    // ---- GitHub App (TFND-23) ---------------------------------------------

    // The App's numeric id. Public information — it is in the App's own URL —
    // so it is not protected.
    public string? GitHubAppId { get; set; }

    // The App's RSA private key, PEM, encrypted at rest under its own Data
    // Protection purpose. This is the credential that lets this instance ACT AS
    // the App against every installation, so it is the most powerful secret the
    // deployment holds.
    public string? GitHubAppPrivateKeyProtected { get; set; }

    // What the check run is called on the commit. Configurable because branch
    // protection rules are written against the name, and an operator who has
    // already written one should not have to rewrite it to match ours.
    public string GitHubCheckName { get; set; } = "tamp.findings";

    // Publish check runs at all. Separate from having credentials: an operator
    // rotating a key, or debugging a noisy check, needs to stop publishing
    // without destroying the configuration.
    public bool GitHubChecksEnabled { get; set; }

    // Telemetry is OFF and there is no switch. Self-hosted means self-hosted;
    // a compliance tool that phoned home would be reporting its customers'
    // security posture to a third party. The System panel states this as a
    // fact rather than offering it as a preference.

    public DateTimeOffset UpdatedAt { get; set; } = DateTimeOffset.UtcNow;
}
