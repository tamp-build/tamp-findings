using Microsoft.EntityFrameworkCore;
using Tamp.Findings.Api.Services;
using Tamp.Findings.Data;
using Tamp.Findings.Domain.Entities;
using Tamp.Findings.Domain.Risk;
using Tamp.Findings.Domain.Values;

namespace Tamp.Findings.Api.Endpoints;

// CISA Secure Software Development Attestation, structured to match the
// NIST SSDF (SP 800-218) practice taxonomy that M-22-18 / EO 14028
// reference. Four practice families:
//   PO  Prepare the Organization     (mostly organizational — manual)
//   PS  Protect the Software         (integrity, SBOM, provenance)
//   PW  Produce Well-Secured Software (SAST, secrets, IaC, code review)
//   RV  Respond to Vulnerabilities   (CVE handling, VEX, POA&M)
//
// This endpoint generates the *evidence-backed* attestation: for every
// practice we map to data we ingest, we emit Yes/Partial/No plus the
// concrete evidence (counts, dates, gate status). Organizational-only
// practices (PO.1.1 "Define security requirements", etc.) are emitted
// as Manual so the AO / signing officer fills in their attestation
// status from policy artifacts outside the tool.
//
// Federal use: the JSON doc this returns is the input to the actual
// signed attestation form. SPA renders to print/PDF; the JSON is a
// machine-readable artifact for the FedRAMP package.
public static class SsdfAttestationEndpoints
{
    public static IEndpointRouteBuilder MapSsdfAttestation(this IEndpointRouteBuilder app)
    {
        app.MapGet("/projects/{projectId:guid}/ssdf-attestation", BuildAsync)
           .WithName("SsdfAttestation")
           .WithTags("Attestation")
           .WithSummary("CISA SSDF (SP 800-218) attestation doc populated from ingest data — risk score, gate state, KEV exposure, VEX coverage, POA&M lifecycle, SBOM hygiene.");
        return app;
    }

    private static async Task<IResult> BuildAsync(
        Guid projectId,
        FindingsDbContext db,
        RiskInputsBuilder inputsBuilder,
        CancellationToken ct)
    {
        var project = await db.Projects.AsNoTracking()
            .Include(p => p.Client)
            .FirstOrDefaultAsync(p => p.Id == projectId, ct);
        if (project is null) return Results.NotFound("project not found");

        // Latest canonical CV set, same shape the build-evaluator uses.
        var canonical = await db.ComponentVersions.AsNoTracking()
            .Where(v => v.Component!.ProjectId == projectId
                     && v.PullRequestRef == null
                     && (v.BranchName == null || v.BranchName == "main" || v.BranchName == "master"))
            .OrderByDescending(v => v.CreatedAt)
            .Select(v => new { v.Id, v.CommitSha, v.VersionString, v.CreatedAt })
            .ToListAsync(ct);

        if (canonical.Count == 0)
            return Results.Ok(BuildEmpty(project));

        var topCommit = canonical[0].CommitSha ?? canonical[0].VersionString;
        var build = canonical
            .Where(c => (c.CommitSha ?? c.VersionString) == topCommit)
            .Select(c => c.Id)
            .ToList();
        var buildSig = canonical.First(c => build.Contains(c.Id));

        var policyId = project.RiskPolicyId ?? project.Client?.RiskPolicyId;
        RiskPolicy? policy = null;
        if (policyId is { } pid) policy = await db.RiskPolicies.AsNoTracking().FirstOrDefaultAsync(p => p.Id == pid, ct);
        policy ??= await db.RiskPolicies.AsNoTracking().FirstOrDefaultAsync(p => p.IsDefault, ct);
        if (policy is null) return Results.Conflict("no default risk policy seeded");

        // TFND-32: VDP metadata drives RV.3.1 evidence.
        var vdp = new VdpEvidence(project.VdpPolicyUrl, project.VdpContactEmail, project.VdpReportingFormUrl);

        var inputs = await inputsBuilder.BuildAsync(build, policy.Config, projectId, ct);
        var result = RiskScorer.Compute(policy.Config, inputs);
        var gates = project.GatesConfig ?? ProjectGatesDefaults.Empty();
        var gateEval = GateEvaluator.Evaluate(gates, inputs, result.Score, prior: null, priorScore: null);

        // Sub-counts pulled outside the scorer for the practice evidence:
        // VEX coverage, POA&M lifecycle counts, sbom signing evidence.
        var vexCounts = await db.VexStatements.AsNoTracking()
            .Where(v => v.ProjectId == projectId && v.RetiredAt == null)
            .GroupBy(v => v.Status)
            .Select(g => new { Status = g.Key, Count = g.Count() })
            .ToDictionaryAsync(x => x.Status, x => x.Count, ct);

        var poamCounts = await db.PoamItems.AsNoTracking()
            .Where(p => p.ProjectId == projectId)
            .GroupBy(p => new { p.Status, ClosedAt = p.ClosedAt == null })
            .Select(g => new { g.Key.Status, IsOpen = g.Key.ClosedAt, Count = g.Count() })
            .ToListAsync(ct);
        var liveOpen = poamCounts.Where(p => p.IsOpen && p.Status == PoamStatus.Open).Sum(p => p.Count);
        var liveInProgress = poamCounts.Where(p => p.IsOpen && p.Status == PoamStatus.InProgress).Sum(p => p.Count);
        var completed = poamCounts.Where(p => p.Status == PoamStatus.Completed).Sum(p => p.Count);
        var riskAccepted = poamCounts.Where(p => p.Status == PoamStatus.RiskAccepted).Sum(p => p.Count);

        // SBOM signing evidence — Tfnd21 stashes metadata.tools on the
        // snapshot. A signed SBOM has at least one tool entry. Full
        // SLSA/Cosign provenance is TFND-29; for now we attest on
        // presence + tool count.
        var latestSbomTools = await db.SbomSnapshots.AsNoTracking()
            .Where(s => build.Contains(s.ComponentVersionId))
            .OrderByDescending(s => s.IngestedAt)
            .Select(s => new
            {
                s.MetadataTools,
                s.IngestedAt,
                s.ProvenanceType,
                s.ProvenanceUploadedAt,
            })
            .FirstOrDefaultAsync(ct);
        var sbomToolsPresent = latestSbomTools?.MetadataTools is not null;

        // Scanner receipts → which PW.* practices have evidence.
        var receipts = await db.ScanRunReceipts.AsNoTracking()
            .Where(r => build.Contains(r.ComponentVersionId))
            .Select(r => new { r.Scanner, r.Status, r.CompletedAt })
            .ToListAsync(ct);
        var succeeded = receipts.Where(r => r.Status == ScanRunStatus.Succeeded).Select(r => r.Scanner).ToHashSet();

        var doc = new SsdfAttestationDoc
        {
            Generated = DateTimeOffset.UtcNow,
            Project = new(project.Id, project.Name, project.Client?.Name ?? ""),
            Build = new(
                CommitSha: buildSig.CommitSha,
                VersionString: buildSig.VersionString,
                LatestCreatedAt: buildSig.CreatedAt),
            Risk = new(
                Score: Math.Round(result.Score, 1),
                Band: result.Band,
                PolicyName: policy.Name),
            Gates = new(
                // Derived on the evaluation, not reconstructed here. The old
                // Failed + Passed arithmetic is what let the attestation state
                // an enabled-gate count that contradicted the computed one,
                // and it now also drops every Unknown.
                Enabled: gateEval.Enabled,
                Passed: gateEval.Passed,
                Failed: gateEval.Failed,
                Unknown: gateEval.Unknown,
                Results: gateEval.Results
                    .Where(r => r.Enabled)
                    .Select(r => new SsdfGateLine(r.Key, r.Verdict.ToString(), r.Blocks, r.Observed))
                    .ToList()),
            Practices = BuildPractices(
                inputs, succeeded, sbomToolsPresent, latestSbomTools?.IngestedAt,
                latestSbomTools?.ProvenanceType, latestSbomTools?.ProvenanceUploadedAt,
                vexCounts, liveOpen, liveInProgress, completed, riskAccepted,
                gateEval, vdp),
        };
        doc.Summary = SummariseAttestation(doc);
        return Results.Ok(doc);
    }

    private static IResult BuildEmpty(Project project) =>
        Results.Ok(new SsdfAttestationDoc
        {
            Generated = DateTimeOffset.UtcNow,
            Project = new(project.Id, project.Name, project.Client?.Name ?? ""),
            Build = null,
            Risk = null,
            Gates = null,
            Practices = new(),
            Summary = new(0, 0, 0, 0, "no canonical builds yet — no attestation evidence to report"),
        });

    // Practice list. Each practice has an Id, family, label, intent
    // (verbatim from SP 800-218), our attestation status, and a short
    // evidence string. Status:
    //   Yes        — automated evidence supports the attestation
    //   No         — automated evidence contradicts (e.g. gate failing)
    //   Partial    — evidence exists but incomplete
    //   Manual     — no automated evidence; signing officer must answer
    private static List<SsdfPractice> BuildPractices(
        RiskInputs inputs, HashSet<ScannerKind> succeeded,
        bool sbomToolsPresent, DateTimeOffset? sbomCreatedAt,
        string? provenanceType, DateTimeOffset? provenanceUploadedAt,
        Dictionary<VexStatementStatus, int> vexCounts,
        int poamOpen, int poamInProgress, int completed, int riskAccepted,
        GateEvaluation gates, VdpEvidence vdp)
    {
        var p = new List<SsdfPractice>();

        // PO — Prepare the Organization. Mostly manual; we can attest
        // the existence of a risk policy and configured gates.
        p.Add(P("PO.1.1", "PO", "Define Security Requirements",
            "Define security requirements for software development",
            "Manual", "Org policy artifacts outside the tool"));
        p.Add(P("PO.2.1", "PO", "Implement Roles and Responsibilities",
            "Define roles + responsibilities; provide training",
            "Manual", "Org policy artifacts outside the tool"));
        p.Add(P("PO.3.1", "PO", "Implement Supporting Toolchains",
            "Use automated security tooling consistently",
            inputs.RanSast || inputs.RanSecrets || inputs.RanIac || inputs.RanSbom || inputs.RanDast ? "Yes" : "No",
            ScannerEvidence(inputs, succeeded)));
        p.Add(P("PO.4.1", "PO", "Define Criteria for Software Security Checks",
            "Define and use criteria to evaluate security",
            gates.Enabled > 0 ? "Yes" : "Partial",
            $"{gates.Enabled} gates enabled — risk policy + acceptance gates configured"));
        p.Add(P("PO.5.1", "PO", "Implement and Maintain Secure Environments",
            "Protect the production-equivalent build env",
            "Manual", "CI/CD posture not introspected by tamp.findings"));

        // PS — Protect the Software (integrity, distribution).
        p.Add(P("PS.1.1", "PS", "Protect All Code from Unauthorized Access",
            "Protect source + artifacts against tampering",
            "Manual", "VCS access controls outside the tool"));
        p.Add(P("PS.2.1", "PS", "Provide a Mechanism for Verifying Software Release Integrity",
            "Provide cryptographic verification for releases",
            ProvenanceStatusAndEvidence(provenanceType, provenanceUploadedAt, sbomToolsPresent, sbomCreatedAt)));
        p.Add(P("PS.3.1", "PS", "Archive and Protect Each Software Release",
            "Preserve evidence for each release",
            inputs.SbomComponents > 0 ? "Yes" : "Partial",
            inputs.SbomComponents > 0
                ? $"SBOM snapshot retained per build ({inputs.SbomComponents} components); receipts + findings retained per CV"
                : "no SBOM in scope"));
        p.Add(P("PS.3.2", "PS", "Maintain Software Bill of Materials (SBOM)",
            "Capture an SBOM for each release",
            inputs.RanSbom ? "Yes" : "No",
            inputs.RanSbom
                ? $"CycloneDX SBOM ingested; {inputs.SbomComponents} components, {inputs.SbomOutdated} outdated, {inputs.SbomStale} stale (>180d)"
                : "no SBOM ingest receipt"));

        // PW — Produce Well-Secured Software.
        p.Add(P("PW.1.1", "PW", "Design Software to Meet Security Requirements",
            "Threat-model + design for security",
            "Manual", "Design artifacts outside the tool"));
        p.Add(P("PW.2.1", "PW", "Review Software Design",
            "Design review against security requirements",
            "Manual", "PR review records outside the tool"));
        p.Add(P("PW.4.1", "PW", "Reuse Existing, Well-Secured Software",
            "Reuse trusted third-party components",
            LicenseEvidence(inputs)));
        p.Add(P("PW.5.1", "PW", "Create Source Code Adhering to Secure Practices",
            "Enforce secure coding practices",
            inputs.RanSast ? GateBased(inputs.SastCritical, inputs.SastHigh, "SAST") : ("No", "no SAST ingest receipt")));
        p.Add(P("PW.6.1", "PW", "Configure the Compilation, Build, and Interpretation Processes",
            "Harden build configuration; reproducible builds",
            "Manual", "Build pipeline config outside the tool"));
        p.Add(P("PW.7.1", "PW", "Review and/or Analyze Human-Readable Code",
            "SAST / code review",
            inputs.RanSast ? GateBased(inputs.SastCritical, inputs.SastHigh, "SAST") : ("No", "no SAST ingest receipt")));
        p.Add(P("PW.8.1", "PW", "Test Executable Code",
            "Test + dynamic analysis",
            TestAndDynamicAnalysisEvidence(inputs)));
        p.Add(P("PW.9.1", "PW", "Configure Software to Have Secure Settings by Default",
            "Ship secure-by-default configs",
            inputs.RanIac
                ? (inputs.IacCritical == 0 ? "Yes" : "Partial",
                   $"IaC scan run; {inputs.IacCritical} critical, {inputs.IacHigh} high misconfigs")
                : ("No", "no IaC scan receipt")));

        // RV — Respond to Vulnerabilities.
        var anyCves = inputs.CveCritical + inputs.CveHigh + inputs.CveMedium + inputs.CveLow;
        p.Add(P("RV.1.1", "RV", "Identify and Confirm Vulnerabilities on an Ongoing Basis",
            "Continuously detect vulns in production code",
            inputs.RanSbom ? "Yes" : "Partial",
            $"{anyCves} CVEs in SBOM ({inputs.CveCritical}c/{inputs.CveHigh}h/{inputs.CveMedium}m/{inputs.CveLow}l); {inputs.KevListedCves} CISA-KEV listed"));
        p.Add(P("RV.1.2", "RV", "Assess, Prioritize, and Remediate Vulnerabilities",
            "Triage + remediate vulnerabilities",
            poamOpen + poamInProgress + completed + riskAccepted > 0 ? "Yes" : "Partial",
            $"POA&M lifecycle: {poamOpen} open / {poamInProgress} in-progress / {completed} completed / {riskAccepted} risk-accepted"));
        p.Add(P("RV.2.1", "RV", "Analyze Vulnerabilities to Identify Their Root Causes",
            "Root-cause analysis on remediation",
            "Manual", "Post-mortem records outside the tool"));
        p.Add(P("RV.3.1", "RV", "Have a Process for Reporting and Communicating Vulnerabilities",
            "Coordinated vulnerability disclosure",
            VdpStatusAndEvidence(vdp)));
        p.Add(P("RV.3.2", "RV", "Document and Track Risk Acceptance Decisions",
            "Document VEX / accepted-risk decisions",
            VexAndAcceptedEvidence(vexCounts, riskAccepted)));

        return p;
    }

    // PW.8.1 is THE dynamic-analysis practice in SP 800-218, and the one an
    // assessor reads when a contract specifies DAST. Unit tests alone do not
    // satisfy it: answering "Yes" off a passing test suite would assert a
    // control that was never exercised. So a full "Yes" requires a DAST
    // receipt with no critical findings; tests-only caps at "Partial" and
    // says so in the evidence string.
    private static (string Status, string Evidence) TestAndDynamicAnalysisEvidence(RiskInputs i)
    {
        var testEvidence = i.TestsMeasured
            ? $"{i.TestsTotal} tests run, {i.TestsFailed} failed; coverage {i.SequenceCoveragePercent:F1}%"
            : "no test reports in scope";

        if (!i.RanDast)
        {
            return (i.TestsMeasured && i.TestsFailed == 0 ? "Partial" : "No",
                $"{testEvidence}; NO dynamic analysis (DAST) receipt — static testing alone does not satisfy PW.8.1");
        }

        var dastEvidence = i.DastCritical > 0
            ? $"DAST run; {i.DastCritical} critical, {i.DastHigh} high findings open"
            : i.DastHigh > 0
                ? $"DAST run; no critical, {i.DastHigh} high findings open"
                : "DAST run; no critical/high findings";

        if (!i.TestsMeasured) return ("Partial", $"{dastEvidence}; {testEvidence}");
        if (i.DastCritical > 0 || i.TestsFailed > 0) return ("Partial", $"{testEvidence}; {dastEvidence}");
        return ("Yes", $"{testEvidence}; {dastEvidence}");
    }

    private static (string Status, string Evidence) GateBased(int crit, int high, string label)
    {
        if (crit > 0) return ("No", $"{crit} critical {label} findings open");
        if (high > 0) return ("Partial", $"{high} high {label} findings open");
        return ("Yes", $"no critical/high {label} findings");
    }

    private static string ScannerEvidence(RiskInputs i, HashSet<ScannerKind> succeeded) =>
        $"SAST={B(i.RanSast)} DAST={B(i.RanDast)} Secrets={B(i.RanSecrets)} IaC={B(i.RanIac)} SBOM={B(i.RanSbom)} Coverage={B(i.RanCoverage)}"
        + $" ({succeeded.Count} succeeded scanners on latest build)";

    private static string B(bool b) => b ? "✓" : "—";

    private static (string Status, string Evidence) LicenseEvidence(RiskInputs i)
    {
        if (i.SbomComponents == 0) return ("No", "no SBOM ingested");
        if (i.LicenseDenied > 0) return ("No", $"{i.LicenseDenied} denied-tier licenses in SBOM");
        if (i.LicenseUnknown > i.SbomComponents / 4) return ("Partial", $"{i.LicenseUnknown}/{i.SbomComponents} unknown-license components");
        return ("Yes", $"{i.SbomComponents} components vetted; {i.LicenseUnknown} unknown licenses");
    }

    // PS.2.1 evidence — release integrity verification.
    //   Provenance attestation on file (SLSA / in-toto / DSSE) → Yes
    //   SBOM tool metadata but no provenance                   → Partial
    //   Nothing on file                                        → No
    private static (string Status, string Evidence) ProvenanceStatusAndEvidence(
        string? provenanceType, DateTimeOffset? uploadedAt,
        bool sbomToolsPresent, DateTimeOffset? sbomCreatedAt)
    {
        if (!string.IsNullOrEmpty(provenanceType))
        {
            var ev = $"provenance attestation on file (`{provenanceType}`), uploaded {uploadedAt:yyyy-MM-dd}";
            return ("Yes", ev);
        }
        if (sbomToolsPresent)
            return ("Partial",
                $"SBOM generated {sbomCreatedAt:yyyy-MM-dd} with tool metadata; no SLSA/in-toto provenance attestation uploaded yet");
        return ("No", "no SBOM tool metadata and no provenance attestation");
    }

    // RV.3.1 evidence — published VDP. Yes when a policy URL is on
    // file (the gold-standard artifact); Partial when only a contact
    // email is set (the minimum BOD 20-01 requirement); No otherwise.
    private static (string Status, string Evidence) VdpStatusAndEvidence(VdpEvidence v)
    {
        if (!string.IsNullOrWhiteSpace(v.PolicyUrl))
        {
            var bits = new List<string> { $"policy: {v.PolicyUrl}" };
            if (!string.IsNullOrWhiteSpace(v.ContactEmail)) bits.Add($"contact: {v.ContactEmail}");
            if (!string.IsNullOrWhiteSpace(v.ReportingFormUrl)) bits.Add($"form: {v.ReportingFormUrl}");
            return ("Yes", string.Join(" · ", bits));
        }
        if (!string.IsNullOrWhiteSpace(v.ContactEmail))
            return ("Partial", $"contact email on file ({v.ContactEmail}); publish a VDP page for full attestation");
        return ("No", "no VDP metadata configured — set the policy URL on the project settings dialog");
    }

    private static (string Status, string Evidence) VexAndAcceptedEvidence(
        Dictionary<VexStatementStatus, int> vex, int riskAccepted)
    {
        var notAffected = vex.GetValueOrDefault(VexStatementStatus.NotAffected, 0);
        var fixed_ = vex.GetValueOrDefault(VexStatementStatus.Fixed, 0);
        var affected = vex.GetValueOrDefault(VexStatementStatus.Affected, 0);
        if (notAffected + fixed_ + riskAccepted == 0)
            return ("Partial", "no VEX statements or risk-accepted POA&M entries on file");
        var ev = $"VEX: {notAffected} not-affected / {fixed_} fixed / {affected} affected;"
               + $" POA&M risk-accepted: {riskAccepted}";
        return ("Yes", ev);
    }

    private static SsdfPractice P(
        string id, string family, string label, string intent, string status, string evidence) =>
        new(id, family, label, intent, status, evidence);

    // Tuple overload — lets callers compose Status+Evidence in a helper
    // (GateBased / LicenseEvidence / VexAndAcceptedEvidence) and pass
    // the result through without unpacking.
    private static SsdfPractice P(
        string id, string family, string label, string intent, (string Status, string Evidence) sv) =>
        new(id, family, label, intent, sv.Status, sv.Evidence);

    // Counts buckets so the SPA can render "13 Yes / 4 Partial / 1 No / 8 Manual"
    // headline. Manual rows aren't a failure — they require human attestation.
    private static SsdfSummary SummariseAttestation(SsdfAttestationDoc doc)
    {
        int yes = 0, partial = 0, no = 0, manual = 0;
        foreach (var p in doc.Practices)
        {
            switch (p.Status)
            {
                case "Yes": yes++; break;
                case "Partial": partial++; break;
                case "No": no++; break;
                case "Manual": manual++; break;
            }
        }
        var headline = no > 0
            ? $"{no} practice(s) failing automated evidence — review before signing"
            : partial > 0
                ? $"{partial} practice(s) need additional evidence"
                : $"{yes} practice(s) attested by automated evidence";
        return new(yes, partial, no, manual, headline);
    }
}

// -------- DTOs (kept in this file because they're attestation-shaped) -----

public sealed class SsdfAttestationDoc
{
    public DateTimeOffset Generated { get; set; }
    public SsdfProject Project { get; set; } = new(Guid.Empty, "", "");
    public SsdfBuild? Build { get; set; }
    public SsdfRisk? Risk { get; set; }
    public SsdfGates? Gates { get; set; }
    public List<SsdfPractice> Practices { get; set; } = new();
    public SsdfSummary Summary { get; set; } = new(0, 0, 0, 0, "");
}

public sealed record SsdfProject(Guid Id, string Name, string ClientName);
public sealed record SsdfBuild(string? CommitSha, string VersionString, DateTimeOffset LatestCreatedAt);
public sealed record SsdfRisk(double Score, string Band, string PolicyName);
public sealed record SsdfGates(int Enabled, int Passed, int Failed, int Unknown, IReadOnlyList<SsdfGateLine> Results);
// Verdict is "Pass" | "Fail" | "Unknown" | "Error". An attestation must be
// able to say a gate was unanswerable — reporting it as passed is how the
// evidence becomes false.
public sealed record SsdfGateLine(string Key, string Verdict, bool Blocks, string Observed);
public sealed record SsdfPractice(string Id, string Family, string Label, string Intent, string Status, string Evidence);
public sealed record SsdfSummary(int Yes, int Partial, int No, int Manual, string Headline);

// Internal-only — feeds RV.3.1 evaluation.
internal sealed record VdpEvidence(string? PolicyUrl, string? ContactEmail, string? ReportingFormUrl);
