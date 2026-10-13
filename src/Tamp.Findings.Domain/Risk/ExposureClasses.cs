using Tamp.Findings.Domain.Values;

namespace Tamp.Findings.Domain.Risk;

/// <summary>
/// How serious one class of discoverable information is (TFND-213).
///
/// <para>
/// The split exists so the gate can block without becoming a regime. RA-5(4) asks for
/// two things — determine what is discoverable, AND take corrective action — and they
/// want different machinery. A disclosed credential or a stack trace is a defect to fix
/// before shipping. A <c>Server:</c> banner or a timestamp in a response is information
/// an adversary can collect and we would rather they could not, but failing a build over
/// one is how a team learns to turn the gate off.
/// </para>
/// <para>
/// So <see cref="Disclosure"/> blocks and <see cref="Fingerprint"/> is reported. Both are
/// counted, because the DETERMINATION half of the control is the whole list, not the
/// blocking subset.
/// </para>
/// </summary>
public enum ExposureTier
{
    /// <summary>Something about the system is actually disclosed. Blocks.</summary>
    Disclosure,

    /// <summary>Something is identifiable or collectable. Counted and reported, never blocks.</summary>
    Fingerprint,
}

/// <summary>
/// One class of discoverable information: what an adversary can learn about this system
/// from the evidence we already ingest (TFND-213, RA-5(4)).
/// </summary>
/// <param name="Id">Stable key, used by the gate detail and the roll-up.</param>
/// <param name="Title">What a reader sees.</param>
/// <param name="Description">What is discoverable, and what corrective action means here.</param>
/// <param name="Tier">Whether this class blocks — see <see cref="ExposureTier"/>.</param>
/// <param name="ControlRefs">The controls this class provides evidence for.</param>
public sealed record ExposureClass(
    string Id,
    string Title,
    string Description,
    ExposureTier Tier,
    IReadOnlyList<string> ControlRefs);

/// <summary>
/// One ingested finding, reduced to what classification needs.
/// </summary>
public readonly record struct ExposureSignal(
    ScannerKind Scanner,
    string RuleId,
    Severity Severity,
    string? SubCategory);

/// <summary>
/// The registry of discoverable-information classes, and the rule ids that evidence them
/// (TFND-213).
///
/// <para>
/// RA-5(4) was dispositioned Gated[verifiedSecrets] during the ADR 0015 walk and flagged
/// as PARTIAL: a leaked credential is discoverable information, but it is one slice of a
/// control that asks what an adversary can learn about the system at all. This registry
/// is the rest of the slice we can actually answer — the disclosures and fingerprints
/// already sitting in the findings table, which nothing was reading as a class.
/// </para>
/// <para>
/// Findings-owned CONTENT, exactly like <see cref="PostureChecks"/>: the producer reports
/// raw findings, and findings owns which classes exist, which rule ids evidence them, what
/// blocks, and which controls they satisfy. Adding a signal is a one-line entry here.
/// </para>
/// <para>
/// What this deliberately does NOT claim: external reconnaissance — subdomain and DNS
/// enumeration, cloud metadata, exposed panels on hosts nobody declared as a target,
/// search-engine OSINT. None of it is in the findings table because nothing produces it,
/// and a class with no signal would be a row on a coverage matrix that means nothing. See
/// TODO(TAM-292) below; the remaining gap stays tracked rather than asserted.
/// </para>
/// </summary>
public static class ExposureClasses
{
    public const string LeakedCredential = "leaked-credential";
    public const string CandidateCredential = "candidate-credential";
    public const string DebugDiagnostics = "debug-diagnostics";
    public const string RequestMetadata = "request-metadata";
    public const string SourceOrConfig = "source-or-config";
    public const string PersonalData = "personal-data";
    public const string TechnologyFingerprint = "technology-fingerprint";
    public const string InternalTopology = "internal-topology";
    public const string IncidentalArtifact = "incidental-artifact";

    public static readonly IReadOnlyList<ExposureClass> All =
    [
        new(LeakedCredential,
            "Live credential disclosed",
            "A secret scanner verified that a credential found in the tree still authenticates. The most direct form of discoverable information there is: corrective action is rotation, not redaction.",
            ExposureTier.Disclosure,
            ["RA-5(4)", "IA-5"]),

        new(CandidateCredential,
            "Possible credential in the tree",
            "A secret-shaped match the scanner could not verify. Reported rather than blocking because the unverified bucket is where the false positives live — but each one is still something an adversary reading the source would try.",
            ExposureTier.Fingerprint,
            ["RA-5(4)"]),

        new(DebugDiagnostics,
            "Debug and diagnostic output reachable",
            "The running system returns stack traces, debug headers or developer diagnostics. It discloses internal structure — framework, file paths, query shapes — to anyone who can provoke an error.",
            ExposureTier.Disclosure,
            ["RA-5(4)", "SI-11"]),

        new(RequestMetadata,
            "Sensitive data carried in request metadata",
            "Identifiers, tokens or session state travel in the URL or leak through the Referer header, where they are recorded by proxies, logs and browser history well outside the system boundary.",
            ExposureTier.Disclosure,
            ["RA-5(4)", "SC-28(1)"]),

        new(SourceOrConfig,
            "Source or configuration served to clients",
            "Source files or configuration are retrievable from the deployed target. Everything in them — endpoints, internal hostnames, embedded keys — is discoverable without any further access.",
            ExposureTier.Disclosure,
            ["RA-5(4)", "CM-6"]),

        new(PersonalData,
            "Personal data in a response",
            "A response carried data that reads as personally identifiable. Corrective action is the only honest response; a count here is not a finding to triage away.",
            ExposureTier.Disclosure,
            ["RA-5(4)"]),

        new(TechnologyFingerprint,
            "Technology and version identifiable",
            "Response headers or banners name the server, framework or version. It does not breach anything on its own; it tells an adversary which published vulnerabilities to try first.",
            ExposureTier.Fingerprint,
            ["RA-5(4)"]),

        new(InternalTopology,
            "Internal addressing disclosed",
            "Private IP addresses or internal hostnames appear in responses, describing the network behind the boundary to anyone outside it.",
            ExposureTier.Fingerprint,
            ["RA-5(4)", "SC-7"]),

        new(IncidentalArtifact,
            "Incidental artefacts in responses",
            "Developer comments, timestamps, hashes and oversized redirects — each individually minor, collectively a description of how the system is built and when.",
            ExposureTier.Fingerprint,
            ["RA-5(4)"]),
    ];

    public static ExposureClass? ById(string id) =>
        All.FirstOrDefault(c => string.Equals(c.Id, id, StringComparison.OrdinalIgnoreCase));

    /// <summary>
    /// ZAP alert (plugin) id → class.
    ///
    /// <para>
    /// Rule ids rather than titles: the id is ZAP's stable identity for an alert and the
    /// title is prose that has been reworded between releases. Only ids that genuinely
    /// describe discoverable information are listed — the header-hardening and
    /// informational alerts that make up most of a ZAP run (10015, 10021, 10055, 10109,
    /// 10112 …) are absent on purpose, because a class nobody would take corrective
    /// action on is noise in an RA-5(4) determination.
    /// </para>
    /// </summary>
    private static readonly Dictionary<string, string> ZapAlerts = new(StringComparer.Ordinal)
    {
        // Disclosure.
        ["10023"] = DebugDiagnostics,          // Information Disclosure - Debug Error Messages
        ["10052"] = DebugDiagnostics,          // X-ChromeLogger-Data header information leak
        ["10024"] = RequestMetadata,           // Information Disclosure - Sensitive Information in URL
        ["10025"] = RequestMetadata,           // Information Disclosure - Sensitive Information in HTTP Referrer Header
        ["3"] = RequestMetadata,               // Session ID in URL Rewrite
        ["10045"] = SourceOrConfig,            // Source Code Disclosure - /WEB-INF folder
        ["10062"] = PersonalData,              // PII Disclosure

        // Fingerprint.
        ["10036"] = TechnologyFingerprint,     // Server leaks version information via the Server header
        ["10037"] = TechnologyFingerprint,     // Server leaks information via X-Powered-By
        ["10061"] = TechnologyFingerprint,     // X-AspNet-Version response header
        ["2"] = InternalTopology,              // Private IP disclosure
        ["10027"] = IncidentalArtifact,        // Information Disclosure - Suspicious Comments
        ["10096"] = IncidentalArtifact,        // Timestamp disclosure
        ["10097"] = IncidentalArtifact,        // Hash disclosure
        ["10044"] = IncidentalArtifact,        // Big Redirect Detected (Potential Sensitive Information Leak)
    };

    // TODO(TAM-292): Nuclei's exposures / exposed-panels template families are the
    // reconnaissance half of RA-5(4) — an exposed .env, a .git directory, an admin panel
    // on a host nobody declared. They are deliberately absent here: Nuclei identifies a
    // finding by TEMPLATE ID, there are thousands of them, and no Nuclei receipt has
    // landed in a live instance yet, so every entry would be a guess at a string. The
    // upstream ask is that the producer report the template's TAGS on the wire — then one
    // tag check replaces a thousand ids, and this registry grows by a line rather than a
    // table. One id is listed because it is stable and already appears in fixtures.
    private static readonly Dictionary<string, string> NucleiTemplates = new(StringComparer.Ordinal)
    {
        ["tech-detect"] = TechnologyFingerprint,
    };

    /// <summary>
    /// The scanners that can produce any signal at all — the query filter, so classifying
    /// never means reading every finding on a build.
    /// </summary>
    public static readonly IReadOnlySet<ScannerKind> Scanners = new HashSet<ScannerKind>
    {
        ScannerKind.TruffleHog,
        ScannerKind.Trivy,      // secret sub-category only
        ScannerKind.Zap,
        ScannerKind.Nuclei,
    };

    /// <summary>
    /// Which class of discoverable information this finding evidences, or null when it
    /// evidences none.
    /// </summary>
    public static ExposureClass? Classify(ExposureSignal signal)
    {
        var id = ClassIdFor(signal);
        return id is null ? null : ById(id);
    }

    private static string? ClassIdFor(ExposureSignal signal)
    {
        // Secrets. The verified/unverified split is carried on severity by the ingest
        // (Critical = the scanner authenticated with it), which is the same distinction
        // the verifiedSecrets gate reads — so the two never disagree about which secrets
        // are live.
        if (signal.Scanner == ScannerKind.TruffleHog
            || (signal.Scanner == ScannerKind.Trivy && signal.SubCategory == "secret"))
        {
            return signal.Severity switch
            {
                Severity.Critical => LeakedCredential,
                Severity.High => CandidateCredential,
                _ => null,
            };
        }

        var ruleId = signal.RuleId?.Trim();
        if (string.IsNullOrEmpty(ruleId)) return null;

        return signal.Scanner switch
        {
            ScannerKind.Zap => ZapAlerts.GetValueOrDefault(ruleId),
            ScannerKind.Nuclei => NucleiTemplates.GetValueOrDefault(ruleId),
            _ => null,
        };
    }

    /// <summary>
    /// Roll a build's findings up into per-class counts. The gate reads the tiers; the
    /// class breakdown is what makes the gate's verdict say what was discovered.
    /// </summary>
    public static ExposureRollup Roll(IEnumerable<(ExposureSignal Signal, int Count)> findings)
    {
        var byClass = new Dictionary<string, int>(StringComparer.Ordinal);
        var disclosure = 0;
        var fingerprint = 0;

        foreach (var (signal, count) in findings)
        {
            if (Classify(signal) is not { } cls) continue;
            byClass[cls.Id] = byClass.GetValueOrDefault(cls.Id) + count;
            if (cls.Tier == ExposureTier.Disclosure) disclosure += count;
            else fingerprint += count;
        }

        return new ExposureRollup(disclosure, fingerprint, byClass);
    }
}

/// <summary>What a build discloses, by tier and by class.</summary>
public sealed record ExposureRollup(
    int Disclosure,
    int Fingerprint,
    IReadOnlyDictionary<string, int> ByClass)
{
    public static ExposureRollup Empty { get; } =
        new(0, 0, new Dictionary<string, int>(StringComparer.Ordinal));
}
