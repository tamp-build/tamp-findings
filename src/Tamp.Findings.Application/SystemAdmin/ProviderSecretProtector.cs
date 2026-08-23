using System.Xml.Linq;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.DataProtection.EntityFrameworkCore;
using Microsoft.AspNetCore.DataProtection.Repositories;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Tamp.Findings.Data;

namespace Tamp.Findings.Application.SystemAdmin;

/// <summary>
/// The key ring that protects identity-provider secrets (TFND-111).
///
/// A SEPARATE data-protection stack from the host's, and the separation is the
/// point.
///
/// Provider secrets must survive a restart, so their keys have to be durable —
/// the default store is the filesystem or the registry, which in a container
/// means a restart orphans every secret on the instance, discovered at the
/// moment sign-in stops working. So these keys live in the database.
///
/// But putting the HOST's data protection on the database would make every page
/// render depend on it: Blazor protects its render-mode payload, and the cookie
/// handler protects the auth ticket. A database outage would then be a 500 on
/// every URL instead of a screen that says "Unavailable" — and this product's
/// whole posture is that a screen which cannot measure something must say so
/// rather than fail opaquely.
///
/// So: two key rings, each durable in the way its own contents need.
///
/// NOTE, and it is a real one: the host's key ring is still per-instance, which
/// means auth cookies are not portable across replicas behind a load balancer.
/// That is a pre-existing condition rather than something this introduced, and
/// fixing it belongs with whoever decides to run more than one replica —
/// bundling it in here would change session behaviour under cover of an
/// unrelated ticket.
/// </summary>
public sealed class ProviderSecretProtector
{
    private readonly Lazy<IDataProtector> _protector;

    public const string Purpose = "tamp.findings.identity-provider-secret.v1";

    public ProviderSecretProtector(IServiceScopeFactory scopes)
    {
        // Lazy so that constructing this never touches the database. It is a
        // singleton resolved during DI graph construction, and a constructor
        // that opened a connection would make the host's startup depend on
        // Postgres being up.
        _protector = new Lazy<IDataProtector>(() =>
        {
            var inner = new ServiceCollection();
            inner.AddDataProtection()
                 // The application name is part of the key derivation. Pinning
                 // it means a rename of the host process does not silently make
                 // every stored secret undecryptable.
                 .SetApplicationName("tamp.findings")
                 .AddKeyManagementOptions(o => o.XmlRepository = new DatabaseXmlRepository(scopes));

            return inner.BuildServiceProvider()
                        .GetRequiredService<IDataProtectionProvider>()
                        .CreateProtector(Purpose);
        }, LazyThreadSafetyMode.ExecutionAndPublication);
    }

    public string Protect(string plaintext) => _protector.Value.Protect(plaintext);

    public string Unprotect(string protectedPayload) => _protector.Value.Unprotect(protectedPayload);
}

/// <summary>
/// Data Protection's key store, over this application's own DbContext.
///
/// Written directly against <see cref="IXmlRepository"/> — two methods — rather
/// than using the package's <c>PersistKeysToDbContext</c> extension, because
/// that extension registers itself into the host container and would take the
/// host's key ring with it. Reaching for the interface keeps the database
/// dependency confined to the one thing that needs it.
/// </summary>
internal sealed class DatabaseXmlRepository : IXmlRepository
{
    private readonly IServiceScopeFactory _scopes;

    public DatabaseXmlRepository(IServiceScopeFactory scopes) => _scopes = scopes;

    public IReadOnlyCollection<XElement> GetAllElements()
    {
        using var scope = _scopes.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<FindingsDbContext>();

        return db.DataProtectionKeys.AsNoTracking()
            .Select(k => k.Xml)
            .AsEnumerable()
            .Where(xml => !string.IsNullOrWhiteSpace(xml))
            .Select(xml => XElement.Parse(xml!))
            .ToArray();
    }

    public void StoreElement(XElement element, string friendlyName)
    {
        using var scope = _scopes.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<FindingsDbContext>();

        db.DataProtectionKeys.Add(new DataProtectionKey
        {
            FriendlyName = friendlyName,
            Xml = element.ToString(SaveOptions.DisableFormatting),
        });

        db.SaveChanges();
    }
}
