using System.Reflection;
using Tamp.Findings.Api.Authentication;

namespace Tamp.Findings.Api.Tests;

/// <summary>
/// Placeholder OAuth credentials are not credentials (TFND-255).
///
/// The guard that existed only checked emptiness, and a templated value walks
/// past it: non-empty, so the handler registers, so the app builds a
/// well-formed authorize URL that GitHub answers with a bare 404. The operator
/// sees GitHub's 404 and gets no hint that the client id is the problem — and
/// example env files ship with placeholders, so this is the ordinary
/// misconfiguration rather than an exotic one.
///
/// Reflects over the private helper rather than standing up a host per case:
/// the decision is a pure string judgement and deserves to be tested as one.
/// </summary>
public class AppCovPlaceholderOAuthCredentialsTests
{
    private static bool LooksLikePlaceholder(string value) =>
        (bool)typeof(AuthExtensions)
            .GetMethod("LooksLikePlaceholder", BindingFlags.NonPublic | BindingFlags.Static)!
            .Invoke(null, [value])!;

    [Theory]
    // What example env files and hand-edited templates actually contain.
    [InlineData("placeholder-pending-oauth-app")]   // the reported value
    [InlineData("<your-client-id>")]
    [InlineData("YOUR_CLIENT_ID")]
    [InlineData("changeme")]
    [InlineData("change-me")]
    [InlineData("TODO")]
    [InlineData("replace-me")]
    [InlineData("xxxxxxxxxxxx")]
    [InlineData("dummy-secret")]
    [InlineData("not-set")]
    [InlineData("example-client-id")]
    public void Templated_values_are_recognised_as_placeholders(string value) =>
        Assert.True(LooksLikePlaceholder(value), $"'{value}' should read as a placeholder");

    [Theory]
    // Shapes GitHub has actually issued. A false positive here is worse than a
    // false negative: it would refuse to register a provider whose credentials
    // are real, locking an operator out of a working deployment.
    [InlineData("Iv1.8a61f9b3a7aba766")]
    [InlineData("Ov23liQ8N2mKpX1aZbCd")]
    [InlineData("23f1a9c4e7b2d6085a1c")]
    // Deliberately NOT a gho_/ghp_ token shape. The field under test is a
    // client ID, which never looks like that — and a token-shaped literal here
    // is a real finding for the secret scanner (TFND-172), which would mean a
    // test about false positives generating one of its own.
    [InlineData("Ov23liABCDEFGHIJ1234")]
    public void Real_looking_credentials_are_left_alone(string value) =>
        Assert.False(LooksLikePlaceholder(value), $"'{value}' is plausible and must not be rejected");

    [Theory]
    [InlineData("")]
    [InlineData("   ")]
    public void Empty_is_not_a_placeholder_because_it_is_its_own_case(string value)
    {
        // Emptiness already had a guard, and a correct one — it exists because
        // an empty ClientId makes OAuthOptions.Validate() throw on every
        // request including /health. Conflating the two would make the log
        // message wrong: "set but unusable" and "not set" are different
        // operator problems.
        Assert.False(LooksLikePlaceholder(value));
    }

    [Fact]
    public void The_helper_is_case_insensitive()
    {
        // Templates are written by people, who capitalise inconsistently.
        Assert.True(LooksLikePlaceholder("PLACEHOLDER"));
        Assert.True(LooksLikePlaceholder("PlaceHolder-Client"));
        Assert.True(LooksLikePlaceholder("ChangeMe"));
    }
}
