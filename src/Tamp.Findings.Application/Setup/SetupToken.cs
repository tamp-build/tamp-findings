using System.Security.Cryptography;

namespace Tamp.Findings.Application.Setup;

/// <summary>
/// The one-time token that claims the administrator seat on a fresh instance.
///
/// <para><b>Why this exists.</b> "The first person to sign in becomes admin" has
/// a race: between deploying and the operator signing in, the instance is
/// reachable with an unclaimed admin seat. Deploy, get distracted, and whoever
/// finds it first owns it. Requiring a token printed to the container log
/// closes that — possession of the logs is what proves you are the operator,
/// which is the same trust boundary Portainer, Jellyfin and Vaultwarden use.</para>
///
/// <para><b>The load-bearing rule</b> is that a WRONG token creates no account.
/// Without that, a failed attempt still writes a user row, which consumes the
/// "no users exist" condition and permanently breaks the bootstrap — leaving an
/// instance nobody can administer. That is the difference between a setup token
/// and a speed bump.</para>
///
/// <para>Held in memory and regenerated on every start while the instance is
/// unclaimed. It is deliberately NOT persisted: a claim token that survives in
/// the database outlives its purpose and becomes a standing credential.</para>
/// </summary>
public sealed class SetupToken
{
    /// <summary>
    /// Lets an operator pin the token instead of reading it from the log —
    /// for IaC deploys, and for platforms where getting at container output is
    /// awkward enough that people would otherwise skip the whole mechanism.
    /// </summary>
    public const string EnvironmentVariable = "TAMP_FINDINGS_SETUP_TOKEN";

    private string? _value;

    /// <summary>
    /// True while the instance has no users and a token must be presented.
    /// Safe to expose to an anonymous page — it says a token is REQUIRED, not
    /// what it is.
    /// </summary>
    public bool IsRequired => _value is not null;

    /// <summary>
    /// The token, for printing at startup only. Null once claimed.
    ///
    /// Nothing should render this in a response: whoever can read a log is the
    /// operator, whoever can read an HTTP response is anyone.
    /// </summary>
    public string? ValueForStartupLog => _value;

    /// <summary>
    /// Arm the token if the instance is unclaimed, or clear it if it is not.
    ///
    /// Called at startup with the current user count. Passing zero arms it;
    /// anything else disarms, so a restart of an in-use instance never prints
    /// a live claim token.
    /// </summary>
    public void Arm(int existingUserCount)
    {
        if (existingUserCount > 0)
        {
            _value = null;
            return;
        }

        // Trimmed: an operator setting this through a Kubernetes secret, a
        // .env file or a shell heredoc very easily ships a trailing newline,
        // and a token that differs from the one they typed by an invisible
        // character is the worst kind of wrong.
        _value = Environment.GetEnvironmentVariable(EnvironmentVariable)?.Trim() is { Length: > 0 } pinned
            ? pinned
            // 160 bits. Well past guessable, and short enough that someone can
            // copy it out of a terminal without wrapping.
            : Convert.ToHexString(RandomNumberGenerator.GetBytes(20)).ToLowerInvariant();
    }

    /// <summary>Mark the seat claimed. The token stops being valid immediately.</summary>
    public void Claim() => _value = null;

    /// <summary>
    /// Is this the token? Fixed-time, so the value cannot be recovered a byte
    /// at a time by timing the responses — a fresh deployment on a public
    /// address is exactly the thing bots scan for.
    /// </summary>
    public bool Validate(string? candidate)
    {
        if (_value is null) return false;

        // Surrounding whitespace is never part of the token — it is 40 hex
        // characters — so it can only have come from the clipboard. Copying it
        // out of a terminal banner or a `kubectl logs` line picks up a trailing
        // newline or a leading space remarkably often, and the resulting
        // rejection is indistinguishable from a wrong token: the operator sees
        // the right value on screen, pastes it, and is refused.
        //
        // Trimming loses nothing. Whitespace carries no entropy and cannot make
        // a wrong token right.
        candidate = candidate?.Trim();
        if (string.IsNullOrEmpty(candidate)) return false;

        var expected = System.Text.Encoding.UTF8.GetBytes(_value);
        var actual = System.Text.Encoding.UTF8.GetBytes(candidate);

        // FixedTimeEquals requires equal lengths, and returning early on a
        // length mismatch leaks the length. Compare a fixed-size hash instead
        // so every candidate costs the same.
        return CryptographicOperations.FixedTimeEquals(SHA256.HashData(expected), SHA256.HashData(actual));
    }
}
