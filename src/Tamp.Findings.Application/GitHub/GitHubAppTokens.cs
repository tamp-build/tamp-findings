using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace Tamp.Findings.Application.GitHub;

/// <summary>
/// Minting the credentials a GitHub App uses to act as itself (TFND-23).
///
/// Two steps, and the distinction matters:
///
///   1. An APP JWT, signed with the App's RSA private key. It proves "I am this
///      App" and can do almost nothing on its own — list installations, and
///      exchange itself for the second thing.
///   2. An INSTALLATION token, obtained with that JWT, scoped to one
///      installation and expiring in an hour. It is what actually writes a
///      check run.
///
/// Written by hand rather than pulling in a JWT library: the payload is three
/// claims and the signature is RS256 over two base64url segments. A dependency
/// for that would be a larger surface than the code it replaces, on the one
/// credential that lets this instance act as the App against every installation
/// it is on.
/// </summary>
public static class GitHubAppTokens
{
    /// <summary>
    /// A JWT proving this instance is the App.
    ///
    /// <paramref name="now"/> is passed rather than read from the clock so the
    /// expiry arithmetic is testable — the failure mode being guarded against
    /// is a token GitHub rejects for being seconds out, which is untestable
    /// against a live clock.
    /// </summary>
    public static string CreateAppJwt(string appId, string privateKeyPem, DateTimeOffset now)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(appId);
        ArgumentException.ThrowIfNullOrWhiteSpace(privateKeyPem);

        var header = new Dictionary<string, object> { ["alg"] = "RS256", ["typ"] = "JWT" };

        var payload = new Dictionary<string, object>
        {
            // Backdated 60 seconds. GitHub rejects a token whose iat is in the
            // future by even a second, and no two machines agree on the time to
            // better than that — this is GitHub's own documented advice, not
            // superstition.
            ["iat"] = now.AddSeconds(-60).ToUnixTimeSeconds(),
            // Ten minutes is the maximum GitHub accepts. Asking for more makes
            // every request fail rather than getting a shorter token.
            ["exp"] = now.AddMinutes(9).ToUnixTimeSeconds(),
            ["iss"] = appId,
        };

        var signingInput =
            $"{Base64Url(JsonSerializer.SerializeToUtf8Bytes(header))}." +
            $"{Base64Url(JsonSerializer.SerializeToUtf8Bytes(payload))}";

        using var rsa = RSA.Create();
        rsa.ImportFromPem(privateKeyPem);

        var signature = rsa.SignData(
            Encoding.ASCII.GetBytes(signingInput), HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);

        return $"{signingInput}.{Base64Url(signature)}";
    }

    /// <summary>
    /// base64url, per RFC 7515: no padding, and the two substituted characters.
    /// Ordinary base64 produces a token GitHub rejects without saying why.
    /// </summary>
    internal static string Base64Url(ReadOnlySpan<byte> bytes) =>
        Convert.ToBase64String(bytes).TrimEnd('=').Replace('+', '-').Replace('/', '_');
}
