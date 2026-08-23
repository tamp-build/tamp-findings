using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Tamp.Findings.Application.GitHub;
using Tamp.Findings.Domain.Risk;

namespace Tamp.Findings.Application.Tests;

// Writing check runs back to the commit (TFND-23).
//
// The transport cannot be exercised without real GitHub, so everything that
// matters lives in pure code and is tested here: how a four-valued verdict maps
// onto GitHub's vocabulary, what the summary says, and whether the JWT is the
// shape GitHub accepts.
public class GitHubCheckTests
{
    private static GateResult Gate(string key, GateVerdict verdict, string observed = "0") =>
        new(key, Enabled: true, verdict, observed, Threshold: null, Reason: null);

    private static GateEvaluation Evaluation(params GateResult[] gates) =>
        new(CurrentScore: 12.5, PriorScore: null, DeltaPoints: null, gates);

    private static CheckRun Compose(params GateResult[] gates) =>
        CheckRunComposer.Compose(
            "tamp.findings", Evaluation(gates), 12.5, "yellow", "Tamp Federal v1", null);

    // ---- The verdict mapping ------------------------------------------------

    [Fact]
    public void All_gates_passing_is_a_success()
    {
        Assert.Equal("success", Compose(Gate("kevExposure", GateVerdict.Pass)).Conclusion);
    }

    [Fact]
    public void A_failing_gate_is_a_failure()
    {
        Assert.Equal("failure", Compose(Gate("criticalSast", GateVerdict.Fail, "3 critical")).Conclusion);
    }

    [Fact]
    public void An_unanswerable_gate_is_action_required_not_neutral()
    {
        // THE DECISION THIS FEATURE TURNS ON. GitHub has no "unknown", and
        // NEUTRAL DOES NOT BLOCK BRANCH PROTECTION — reporting a gate that
        // could not be evaluated as neutral would let a merge through, which is
        // precisely the defect the four-valued model was introduced to remove.
        var check = Compose(Gate("criticalDast", GateVerdict.Unknown, "no DAST scan on this build"));

        Assert.Equal("action_required", check.Conclusion);
        Assert.NotEqual("neutral", check.Conclusion);
        Assert.NotEqual("success", check.Conclusion);
    }

    [Fact]
    public void An_errored_gate_also_blocks()
    {
        // A gate whose evaluator is broken is not a gate that passed.
        Assert.Equal("action_required", Compose(Gate("bogus", GateVerdict.Error, "(unknown gate)")).Conclusion);
    }

    [Fact]
    public void A_real_failure_outranks_an_unanswerable_one()
    {
        // Both block, but "we measured and it is bad" is a different message
        // from "we could not measure", and the stronger one should be what the
        // check says.
        var check = Compose(
            Gate("criticalSast", GateVerdict.Fail, "3 critical"),
            Gate("criticalDast", GateVerdict.Unknown, "no DAST scan"));

        Assert.Equal("failure", check.Conclusion);
        Assert.Contains("1 gate failing, 1 unanswerable", check.Title, StringComparison.Ordinal);
    }

    [Fact]
    public void A_disabled_gate_does_not_block()
    {
        // Verdict is meaningless for a gate nobody enabled.
        var disabled = new GateResult("anyCves", Enabled: false, GateVerdict.Pass, "—", null, null);

        Assert.Equal("success", Compose(disabled).Conclusion);
    }

    // ---- What the check says ------------------------------------------------

    [Fact]
    public void No_gates_configured_never_reads_as_clear_to_ship()
    {
        // Crediting a project for a contract it never wrote is the same defect
        // as a clean score from a scan that never ran.
        var check = CheckRunComposer.Compose(
            "tamp.findings", Evaluation(), 12.5, "yellow", "Tamp Federal v1", null);

        Assert.Equal("success", check.Conclusion);
        Assert.DoesNotContain("Clear to ship", check.Title, StringComparison.Ordinal);
        Assert.Contains("No acceptance gates configured", check.Title, StringComparison.Ordinal);
        Assert.Contains("not the same as passing", check.Summary, StringComparison.Ordinal);
    }

    [Fact]
    public void The_score_never_appears_without_its_policy()
    {
        // Same rule as the screen, the PDF and the OSCAL package — and on a
        // pull request it is a number somebody will argue with.
        var check = Compose(Gate("kevExposure", GateVerdict.Pass));

        Assert.Contains("12.5", check.Summary, StringComparison.Ordinal);
        Assert.Contains("Tamp Federal v1", check.Summary, StringComparison.Ordinal);
    }

    [Fact]
    public void The_summary_names_the_blocking_gates_and_what_was_observed()
    {
        // "Unknown" alone tells a developer nothing. The observed value is what
        // tells them what to do next.
        var check = Compose(Gate("criticalDast", GateVerdict.Unknown, "no DAST scan on this build"));

        Assert.Contains("criticalDast", check.Summary, StringComparison.Ordinal);
        Assert.Contains("no DAST scan on this build", check.Summary, StringComparison.Ordinal);
    }

    [Fact]
    public void An_unanswerable_gate_is_explained_rather_than_just_reported()
    {
        var check = Compose(Gate("criticalDast", GateVerdict.Unknown, "no DAST scan"));

        Assert.Contains("not a clean result", check.Summary, StringComparison.Ordinal);
    }

    [Fact]
    public void A_pipe_in_an_observed_value_does_not_break_the_markdown_table()
    {
        // A DAST route with a query string carries one, and an unescaped pipe
        // breaks the row it lands in — so the gate that matters most becomes
        // the one nobody can read.
        var check = Compose(Gate("criticalDast", GateVerdict.Fail, "GET /search?q=a|b"));

        Assert.Contains(@"GET /search?q=a\|b", check.Summary, StringComparison.Ordinal);
    }

    [Fact]
    public void Passing_gates_are_not_listed_row_by_row()
    {
        // The check has a job: say what is stopping the merge. Twelve green
        // rows is where the one red one hides.
        var check = Compose(
            Gate("kevExposure", GateVerdict.Pass),
            Gate("anyCves", GateVerdict.Pass),
            Gate("criticalSast", GateVerdict.Fail, "3 critical"));

        Assert.Contains("criticalSast", check.Summary, StringComparison.Ordinal);
        Assert.DoesNotContain("kevExposure", check.Summary, StringComparison.Ordinal);
    }

    // ---- The App JWT --------------------------------------------------------

    [Fact]
    public void The_app_jwt_is_three_base64url_segments()
    {
        var jwt = GitHubAppTokens.CreateAppJwt("12345", TestKeyPem(), DateTimeOffset.UtcNow);

        var parts = jwt.Split('.');
        Assert.Equal(3, parts.Length);
        // base64url: no padding, and neither of the two substituted characters.
        Assert.All(parts, p => Assert.DoesNotContain('=', p));
        Assert.All(parts, p => Assert.DoesNotContain('+', p));
        Assert.All(parts, p => Assert.DoesNotContain('/', p));
    }

    [Fact]
    public void The_app_jwt_is_backdated_and_expires_within_ten_minutes()
    {
        // GitHub rejects a token whose iat is in the future by even a second,
        // and caps exp at ten minutes — asking for more makes every request
        // fail rather than getting a shorter token.
        var now = new DateTimeOffset(2026, 8, 23, 12, 0, 0, TimeSpan.Zero);

        var payload = Payload(GitHubAppTokens.CreateAppJwt("12345", TestKeyPem(), now));

        var iat = payload.GetProperty("iat").GetInt64();
        var exp = payload.GetProperty("exp").GetInt64();

        Assert.True(iat < now.ToUnixTimeSeconds(), "iat should be backdated for clock skew");
        Assert.True(exp - now.ToUnixTimeSeconds() <= 600, "exp must be within GitHub's ten-minute cap");
        Assert.True(exp > now.ToUnixTimeSeconds());
    }

    [Fact]
    public void The_app_jwt_is_issued_by_the_app_and_signed_with_its_key()
    {
        var now = DateTimeOffset.UtcNow;
        var pem = TestKeyPem();
        var jwt = GitHubAppTokens.CreateAppJwt("12345", pem, now);

        Assert.Equal("12345", Payload(jwt).GetProperty("iss").GetString());

        // The signature actually verifies. A token that merely has three
        // segments would pass every other assertion here and be rejected by
        // GitHub with no explanation.
        var parts = jwt.Split('.');
        using var rsa = RSA.Create();
        rsa.ImportFromPem(pem);

        Assert.True(rsa.VerifyData(
            Encoding.ASCII.GetBytes($"{parts[0]}.{parts[1]}"),
            FromBase64Url(parts[2]),
            HashAlgorithmName.SHA256,
            RSASignaturePadding.Pkcs1));
    }

    [Fact]
    public void The_header_declares_rs256()
    {
        // GitHub accepts RS256 only. Declaring anything else — including
        // "none" — is rejected.
        var jwt = GitHubAppTokens.CreateAppJwt("12345", TestKeyPem(), DateTimeOffset.UtcNow);
        var header = JsonDocument.Parse(FromBase64Url(jwt.Split('.')[0])).RootElement;

        Assert.Equal("RS256", header.GetProperty("alg").GetString());
        Assert.Equal("JWT", header.GetProperty("typ").GetString());
    }

    [Theory]
    [InlineData("")]
    [InlineData("   ")]
    public void An_absent_app_id_is_refused_rather_than_signed(string appId)
    {
        Assert.Throws<ArgumentException>(
            () => GitHubAppTokens.CreateAppJwt(appId, TestKeyPem(), DateTimeOffset.UtcNow));
    }

    // ---- Helpers ------------------------------------------------------------

    private static JsonElement Payload(string jwt) =>
        JsonDocument.Parse(FromBase64Url(jwt.Split('.')[1])).RootElement;

    private static byte[] FromBase64Url(string value)
    {
        var padded = value.Replace('-', '+').Replace('_', '/');
        return Convert.FromBase64String(padded.PadRight((padded.Length + 3) / 4 * 4, '='));
    }

    /// <summary>
    /// A throwaway key, generated per call. Never a fixture: a committed
    /// private key in a repository that scans repositories for committed
    /// secrets would be a finding this product should raise about itself.
    /// </summary>
    private static string TestKeyPem()
    {
        using var rsa = RSA.Create(2048);
        return rsa.ExportRSAPrivateKeyPem();
    }
}
