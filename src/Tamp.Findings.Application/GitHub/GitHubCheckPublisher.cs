using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;
using Tamp.Findings.Application.Auditing;
using Tamp.Findings.Application.Authorization;
using Tamp.Findings.Application.Risk;
using Tamp.Findings.Application.SystemAdmin;
using Tamp.Findings.Data;
using Tamp.Findings.Domain.Entities;
using Tamp.Findings.Domain.Risk;
using Tamp.Findings.Domain.Values;

namespace Tamp.Findings.Application.GitHub;

/// <summary>
/// Writing a check run back to the commit that was scanned (TFND-23).
///
/// The dashboard acting AS ITSELF toward GitHub — distinct from OIDC sign-in,
/// which is browser identity. Different credential (a private key on the
/// server), different lifecycle (installations, not OAuth grants), different
/// threat model.
///
/// The ticket recorded this as blocked on a public URL. That gating applies to
/// inbound WEBHOOKS; this is outbound only, triggered by ingest, and an
/// outbound call needs no routable origin. What genuinely cannot be exercised
/// here is an end-to-end against real GitHub, which is why every decision worth
/// getting right — the verdict mapping, the summary, the JWT — lives in pure
/// code with tests, and only the transport is untested.
/// </summary>
public sealed class GitHubCheckPublisher
{
    private readonly FindingsDbContext _db;
    private readonly RiskInputsBuilder _inputs;
    private readonly ProviderSecretProtector _protector;
    private readonly AuditLog _audit;
    private readonly HttpClient _http;
    private readonly ILogger<GitHubCheckPublisher> _log;
    private readonly TimeProvider _clock;

    public GitHubCheckPublisher(
        FindingsDbContext db, RiskInputsBuilder inputs, ProviderSecretProtector protector,
        AuditLog audit, HttpClient http, ILogger<GitHubCheckPublisher> log, TimeProvider clock)
    {
        _db = db;
        _inputs = inputs;
        _protector = protector;
        _audit = audit;
        _http = http;
        _log = log;
        _clock = clock;
    }

    /// <summary>
    /// Publish the check for one build, if this instance is configured to and
    /// this project maps to a repository.
    ///
    /// Returns why it did nothing rather than silently doing nothing: a check
    /// that never appears is indistinguishable from one that passed, and the
    /// reason belongs somewhere an operator can read it.
    /// </summary>
    public async Task<PublishOutcome> PublishAsync(
        Guid projectId, string commitSha, CancellationToken ct = default)
    {
        var settings = await _db.InstanceSettings.AsNoTracking()
            .SingleOrDefaultAsync(s => s.Id == InstanceSettings.SingletonId, ct);

        if (settings is null || !settings.GitHubChecksEnabled)
            return PublishOutcome.Skipped("GitHub checks are not enabled on this instance.");

        if (string.IsNullOrWhiteSpace(settings.GitHubAppId)
            || string.IsNullOrWhiteSpace(settings.GitHubAppPrivateKeyProtected))
            return PublishOutcome.Skipped("No GitHub App credentials are configured.");

        var project = await _db.Projects.AsNoTracking()
            .Include(p => p.Client)
            .SingleOrDefaultAsync(p => p.Id == projectId, ct);

        if (project?.GitHubRepository is not { Length: > 0 } repository)
        {
            // The common case, and not an error. Most projects have no GitHub
            // repository, and guessing one from a name would eventually post a
            // check to somebody else's repository.
            return PublishOutcome.Skipped("This project is not mapped to a GitHub repository.");
        }

        string privateKey;
        try
        {
            privateKey = _protector.Unprotect(
                ProviderSecretProtector.GitHubAppPurpose, settings.GitHubAppPrivateKeyProtected);
        }
        catch (System.Security.Cryptography.CryptographicException)
        {
            // The key ring that encrypted it is gone. Loud, because the next
            // symptom is checks silently not appearing on pull requests.
            _log.LogError("The GitHub App private key cannot be decrypted. Re-enter it in System settings.");
            return PublishOutcome.Failed("The stored GitHub App private key could not be decrypted.");
        }

        var evaluation = await EvaluateAsync(project, commitSha, ct);
        if (evaluation is null)
            return PublishOutcome.Skipped($"No build matching {commitSha} on this project.");

        var check = CheckRunComposer.Compose(
            settings.GitHubCheckName,
            evaluation.Gates, evaluation.Score, evaluation.Band, evaluation.PolicyName,
            DetailsUrl(settings.InstanceUrl, project, commitSha));

        try
        {
            var appJwt = GitHubAppTokens.CreateAppJwt(
                settings.GitHubAppId, privateKey, _clock.GetUtcNow());

            var token = await InstallationTokenAsync(appJwt, repository, ct);
            if (token is null)
                return PublishOutcome.Failed($"This App is not installed on {repository}.");

            await PostCheckAsync(token, repository, commitSha, check, ct);
        }
        catch (Exception ex) when (ex is HttpRequestException or TaskCanceledException)
        {
            // GitHub being unreachable must not fail an ingest. The findings
            // are stored; the check is a notification, and a notification that
            // takes the ingest down with it is worse than a missing one.
            _log.LogWarning(ex, "Could not publish a check run to {Repository} for {Commit}.",
                repository, commitSha);
            return PublishOutcome.Failed("GitHub was unreachable.");
        }

        // Audited as Other, not Risk or Access: publishing a check changes
        // nothing about this instance's posture or who can reach it. It is a
        // record that something left the building.
        _audit.Record(WorkflowActor, "github.check_published", AuditClass.Other,
            ScopeTarget.Project(project.ClientId, project.Id),
            subjectId: project.Id, subjectKind: nameof(Project),
            detail: $"{check.Conclusion} on {repository}@{Short(commitSha)}: {check.Title}");

        await _db.SaveChangesAsync(ct);

        return PublishOutcome.Published(check.Conclusion);
    }

    /// <summary>
    /// The principal a published check is recorded under.
    ///
    /// A named non-human actor rather than whoever's token happened to trigger
    /// the ingest. "The instance told GitHub" is a different fact from "Scott
    /// told GitHub", and an audit log that conflated them would be unusable.
    /// </summary>
    private static Principal WorkflowActor { get; } =
        Principal.For(Guid.Empty, "github-app", isAdmin: false, []);

    private async Task<Evaluation?> EvaluateAsync(Project project, string commitSha, CancellationToken ct)
    {
        var build = await _db.ComponentVersions.AsNoTracking()
            .Where(v => v.Component!.ProjectId == project.Id && v.CommitSha == commitSha)
            .Select(v => v.Id)
            .ToListAsync(ct);
        if (build.Count == 0) return null;

        var policyId = project.RiskPolicyId ?? project.Client?.RiskPolicyId;
        var policy = policyId is { } id
            ? await _db.RiskPolicies.AsNoTracking().FirstOrDefaultAsync(p => p.Id == id, ct)
            : null;
        policy ??= await _db.RiskPolicies.AsNoTracking().FirstOrDefaultAsync(p => p.IsDefault, ct);
        if (policy is null) return null;

        var inputs = await _inputs.BuildAsync(build, policy.Config, project.Id, ct);
        var result = RiskScorer.Compute(policy.Config, inputs);
        var gates = GateEvaluator.Evaluate(
            project.GatesConfig ?? ProjectGatesDefaults.Empty(),
            inputs, result.Score, prior: null, priorScore: null);

        return new Evaluation(gates, Math.Round(result.Score, 1), result.Band, policy.Name);
    }

    private async Task<string?> InstallationTokenAsync(
        string appJwt, string repository, CancellationToken ct)
    {
        // Resolved per REPOSITORY rather than stored: an App can be installed on
        // many orgs, installations come and go, and a cached id becomes wrong
        // the first time somebody reinstalls.
        using var lookup = new HttpRequestMessage(HttpMethod.Get, $"repos/{repository}/installation");
        Prepare(lookup, appJwt, bearer: true);

        using var lookupResponse = await _http.SendAsync(lookup, ct);
        if (!lookupResponse.IsSuccessStatusCode) return null;

        var installation = await lookupResponse.Content.ReadFromJsonAsync<JsonElement>(ct);
        var installationId = installation.GetProperty("id").GetInt64();

        using var mint = new HttpRequestMessage(
            HttpMethod.Post, $"app/installations/{installationId}/access_tokens");
        Prepare(mint, appJwt, bearer: true);

        using var mintResponse = await _http.SendAsync(mint, ct);
        mintResponse.EnsureSuccessStatusCode();

        var minted = await mintResponse.Content.ReadFromJsonAsync<JsonElement>(ct);
        return minted.GetProperty("token").GetString();
    }

    private async Task PostCheckAsync(
        string token, string repository, string commitSha, CheckRun check, CancellationToken ct)
    {
        using var request = new HttpRequestMessage(HttpMethod.Post, $"repos/{repository}/check-runs")
        {
            Content = JsonContent.Create(new Dictionary<string, object?>
            {
                ["name"] = check.Name,
                ["head_sha"] = commitSha,
                ["status"] = "completed",
                ["conclusion"] = check.Conclusion,
                ["completed_at"] = _clock.GetUtcNow(),
                ["details_url"] = check.DetailsUrl,
                ["output"] = new Dictionary<string, object?>
                {
                    ["title"] = check.Title,
                    ["summary"] = check.Summary,
                },
            }),
        };

        Prepare(request, token, bearer: false);

        using var response = await _http.SendAsync(request, ct);
        response.EnsureSuccessStatusCode();
    }

    private static void Prepare(HttpRequestMessage request, string token, bool bearer)
    {
        request.Headers.Authorization = new AuthenticationHeaderValue(bearer ? "Bearer" : "token", token);
        request.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/vnd.github+json"));
        // GitHub rejects requests without a UA, and pins behaviour to an API
        // version header — omitting it means a future GitHub change alters what
        // this code does without the code changing.
        request.Headers.UserAgent.ParseAdd("tamp.findings");
        request.Headers.Add("X-GitHub-Api-Version", "2022-11-28");
    }

    /// <summary>
    /// Where the check's "Details" link points.
    ///
    /// Null when this instance does not know its own URL, which is honest: a
    /// link built from a guess lands the reader on a host that does not answer,
    /// and a broken link on a pull request is worse than none.
    /// </summary>
    private static string? DetailsUrl(string? instanceUrl, Project project, string commitSha) =>
        string.IsNullOrWhiteSpace(instanceUrl) || project.Client is null
            ? null
            : $"{instanceUrl.TrimEnd('/')}/c/{Uri.EscapeDataString(project.Client.Name)}"
              + $"/p/{Uri.EscapeDataString(project.Name)}/build/{Uri.EscapeDataString(commitSha)}";

    private static string Short(string sha) => sha.Length <= 12 ? sha : sha[..12];

    private sealed record Evaluation(GateEvaluation Gates, double Score, string Band, string PolicyName);
}

/// <summary>
/// What a publish attempt did.
///
/// Skipped and Failed are distinguished because they mean opposite things to an
/// operator: skipped is configuration, failed is something to fix.
/// </summary>
public sealed record PublishOutcome(bool Success, string? Conclusion, string? Reason)
{
    public static PublishOutcome Published(string conclusion) => new(true, conclusion, null);
    public static PublishOutcome Skipped(string reason) => new(false, null, reason);
    public static PublishOutcome Failed(string reason) => new(false, null, reason);
}
