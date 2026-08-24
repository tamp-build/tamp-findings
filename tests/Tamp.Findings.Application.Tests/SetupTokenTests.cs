using Tamp.Findings.Application.Setup;

namespace Tamp.Findings.Application.Tests;

// The administrator claim token (TFND-126).
//
// "First to sign in wins" has a race: between deploying and the operator
// signing in, the instance is reachable with an unclaimed admin seat. The token
// closes it, and these pin the properties that make it worth having.
public class SetupTokenTests
{
    [Fact]
    public void An_instance_with_no_users_requires_a_token()
    {
        var token = new SetupToken();

        token.Arm(existingUserCount: 0);

        Assert.True(token.IsRequired);
        Assert.NotNull(token.ValueForStartupLog);
    }

    [Fact]
    public void An_instance_that_already_has_users_arms_nothing()
    {
        // Restarting an in-use instance must never print a live claim token.
        // Once anyone exists the instance is in use, and a token would be a
        // way to mint a second administrator out of the log.
        var token = new SetupToken();

        token.Arm(existingUserCount: 1);

        Assert.False(token.IsRequired);
        Assert.Null(token.ValueForStartupLog);
        Assert.False(token.Validate("anything"));
    }

    [Fact]
    public void Claiming_disarms_the_token_immediately()
    {
        var token = new SetupToken();
        token.Arm(0);
        var value = token.ValueForStartupLog!;

        token.Claim();

        // A claim token that outlives the claim is just a standing credential.
        Assert.False(token.IsRequired);
        Assert.False(token.Validate(value));
    }

    [Fact]
    public void The_right_token_validates_and_a_wrong_one_does_not()
    {
        var token = new SetupToken();
        token.Arm(0);

        Assert.True(token.Validate(token.ValueForStartupLog));
        Assert.False(token.Validate("not-the-token"));
        Assert.False(token.Validate(""));
        Assert.False(token.Validate(null));
    }

    [Fact]
    public void A_disarmed_token_rejects_everything_including_null()
    {
        var token = new SetupToken();

        // Never armed at all — the state a long-running instance is in.
        Assert.False(token.Validate(null));
        Assert.False(token.Validate("guess"));
    }

    [Fact]
    public void A_candidate_of_a_different_length_is_still_rejected_safely()
    {
        // FixedTimeEquals throws on length mismatch, so the implementation
        // compares hashes. If that ever regressed to a direct comparison, a
        // short guess would throw rather than return false — and an exception
        // on the sign-in path is its own outage.
        var token = new SetupToken();
        token.Arm(0);

        Assert.False(token.Validate("a"));
        Assert.False(token.Validate(new string('x', 500)));
    }

    [Fact]
    public void The_generated_token_is_long_enough_to_be_worth_generating()
    {
        // Bots scan fresh deployments on public addresses. 20 bytes of
        // randomness rendered as hex is 40 characters.
        var token = new SetupToken();
        token.Arm(0);

        Assert.Equal(40, token.ValueForStartupLog!.Length);
    }

    [Fact]
    public void Two_arms_produce_different_tokens()
    {
        var a = new SetupToken();
        var b = new SetupToken();

        a.Arm(0);
        b.Arm(0);

        Assert.NotEqual(a.ValueForStartupLog, b.ValueForStartupLog);
    }

    [Fact]
    public void An_operator_can_pin_the_token_through_the_environment()
    {
        // IaC deploys, and platforms where getting at container output is
        // awkward enough that people would otherwise skip the mechanism.
        Environment.SetEnvironmentVariable(SetupToken.EnvironmentVariable, "pinned-value-for-iac");
        try
        {
            var token = new SetupToken();
            token.Arm(0);

            Assert.Equal("pinned-value-for-iac", token.ValueForStartupLog);
            Assert.True(token.Validate("pinned-value-for-iac"));
        }
        finally
        {
            Environment.SetEnvironmentVariable(SetupToken.EnvironmentVariable, null);
        }
    }

    [Theory]
    [InlineData("  {0}")]
    [InlineData("{0}  ")]
    [InlineData("\n{0}\n")]
    [InlineData("\r\n{0}")]
    [InlineData("\t{0} ")]
    public void Whitespace_around_a_pasted_token_is_ignored(string template)
    {
        // The token is 40 hex characters, so surrounding whitespace can only
        // have come from the clipboard — and copying it out of a startup banner
        // or a `kubectl logs` line picks up a newline remarkably often.
        //
        // Without this the rejection is indistinguishable from a wrong token:
        // the operator is looking at the correct value on screen, pastes it,
        // and is refused with nothing to see. That is exactly how the first
        // real claim attempt against the cluster failed.
        var token = new SetupToken();
        token.Arm(0);
        var real = token.ValueForStartupLog!;

        Assert.True(token.Validate(string.Format(template, real)));
    }

    [Fact]
    public void Whitespace_cannot_make_a_wrong_token_right()
    {
        // Trimming is a convenience, not a loosening. Only the surrounding
        // whitespace is discarded; the value still has to match exactly.
        var token = new SetupToken();
        token.Arm(0);

        Assert.False(token.Validate("  not-the-token  "));
        Assert.False(token.Validate("   "));
        Assert.False(token.Validate(token.ValueForStartupLog![..^1] + " "));
    }

    [Fact]
    public void A_pinned_token_tolerates_a_trailing_newline_from_its_source()
    {
        // A Kubernetes secret, a .env file or a shell heredoc all ship one
        // easily, and the operator never sees it.
        Environment.SetEnvironmentVariable(SetupToken.EnvironmentVariable, "pinned-value-for-iac\n");
        try
        {
            var token = new SetupToken();
            token.Arm(0);

            Assert.Equal("pinned-value-for-iac", token.ValueForStartupLog);
            Assert.True(token.Validate("pinned-value-for-iac"));
        }
        finally
        {
            Environment.SetEnvironmentVariable(SetupToken.EnvironmentVariable, null);
        }
    }
}
