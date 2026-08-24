using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.DataProtection.KeyManagement;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;

namespace Tamp.Findings.Application.SystemAdmin;

/// <summary>
/// Makes the HOST's data-protection key ring durable (TFND-137).
///
/// Unconfigured, ASP.NET falls back to an in-memory ring and says so on every
/// start:
///
///   Using an ephemeral key repository. Protected data will be unavailable
///   when application exits.
///
/// That ring signs the authentication cookie and antiforgery tokens, so:
///
///  - On one replica, every restart invalidates every session. A deploy signs
///    out everyone using the instance, and it reads as a random logout rather
///    than as a deploy.
///
///  - On two replicas it stops working altogether. Each pod generates its own
///    key, so a cookie issued by one is undecryptable by the other, and behind
///    a round-robin service a user is authenticated on roughly half their
///    requests. Intermittent, load-balancer dependent, and thoroughly
///    unpleasant to diagnose from the symptom.
///
/// The comment on <c>DatabaseXmlRepository</c> explains why the host ring was
/// originally left alone: PersistKeysToDbContext "would take the host's key
/// ring with it". That was right when the host had no configuration to take
/// over. Configuring it on purpose is the opposite situation.
/// </summary>
public static class HostDataProtection
{
    public static IServiceCollection AddTampFindingsDataProtection(this IServiceCollection services)
    {
        services
            .AddDataProtection()
            // Part of the key derivation, and pinned for the same reason the
            // provider-secret ring pins it: without this the discriminator
            // defaults to the content root path, so moving or renaming the
            // deployment directory silently invalidates every cookie the
            // instance ever issued.
            //
            // The value MATCHES ProviderSecretProtector deliberately. Both
            // rings live in the same table, and a shared discriminator means
            // they read as one ring rather than two that each treat the
            // other's keys as foreign.
            .SetApplicationName("tamp.findings");

        // Configured through options rather than an IDataProtectionBuilder
        // extension so the repository can take IServiceScopeFactory from the
        // container. Registered after AddDataProtection, so this runs after
        // the framework's own setup and its choice of repository wins.
        //
        // The scope factory matters: the key ring is read during request
        // handling, and resolving a scoped DbContext from the root provider
        // would either capture a singleton DbContext or throw.
        services
            .AddOptions<KeyManagementOptions>()
            .Configure<IServiceScopeFactory>((options, scopes) =>
                options.XmlRepository = new DatabaseXmlRepository(scopes));

        return services;
    }
}
