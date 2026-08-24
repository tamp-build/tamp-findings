using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.DataProtection.KeyManagement;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using Tamp.Findings.Application.SystemAdmin;

namespace Tamp.Findings.Api.Tests;

// TFND-137. The host key ring signs the authentication cookie and antiforgery
// tokens, and it was never configured — so ASP.NET fell back to an in-memory
// one and said so in a warning on every single start, for the life of the
// deployment, without anyone noticing.
//
// Unfixed this is two bugs wearing one hat. On a single replica every restart
// silently signs out every user, which reads as a random logout rather than as
// a deploy. On two replicas sign-in stops working altogether: each pod
// generates its own key, a cookie issued by one is undecryptable by the other,
// and behind a round-robin service a user is authenticated on roughly half
// their requests.
//
// The second failure only appears on the day someone scales the deployment,
// which is the worst possible day to find it. Hence a test rather than a second
// reading of the startup log.
//
// Asserts against the registration directly rather than through TestApiFactory,
// because that factory deliberately substitutes an in-memory ring — it points
// at a database that is not there. Going through it would test the substitute.
public class HostDataProtectionTests
{
    [Fact]
    public void The_key_ring_is_stored_in_the_database()
    {
        var options = Configured<KeyManagementOptions>();

        Assert.NotNull(options.XmlRepository);

        // By name because the repository is internal to the Application
        // assembly. What matters is that it is NOT one of the framework's
        // defaults — Ephemeral, FileSystem, or Registry — every one of which is
        // per-process or per-host and so cannot be shared by two pods.
        Assert.Equal("DatabaseXmlRepository", options.XmlRepository!.GetType().Name);
    }

    [Fact]
    public void The_application_discriminator_is_pinned()
    {
        // Left unset, the discriminator defaults to the content root path, and
        // it is part of the key derivation. Moving or renaming the deployment
        // directory would then invalidate every cookie the instance had ever
        // issued — the same symptom as the ephemeral ring, from a different
        // cause, and no more obvious.
        //
        // The value must also match ProviderSecretProtector: both rings live in
        // the same table, and a shared discriminator is what makes them read as
        // one ring rather than two that treat each other's keys as foreign.
        Assert.Equal("tamp.findings", Configured<DataProtectionOptions>().ApplicationDiscriminator);
    }

    [Fact]
    public void Configuring_the_ring_does_not_open_a_database_connection()
    {
        // The repository takes a scope factory and resolves its DbContext per
        // call, so building the options graph must stay inert. If it did not,
        // the host would refuse to start whenever Postgres was slow to come up
        // — the failure mode IdentityProviderStartup already goes out of its
        // way to avoid.
        //
        // There is no DbContext registered below at all: if constructing the
        // repository touched one, this would throw rather than pass.
        var repository = Configured<KeyManagementOptions>().XmlRepository;

        Assert.NotNull(repository);
    }

    private static T Configured<T>() where T : class, new() =>
        new ServiceCollection()
            .AddTampFindingsDataProtection()
            .BuildServiceProvider()
            .GetRequiredService<IOptions<T>>()
            .Value;
}
