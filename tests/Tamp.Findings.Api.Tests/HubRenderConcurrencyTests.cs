using System.Net;
using System.Security.Claims;
using System.Text.Encodings.Web;
using System.Xml.Linq;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.DataProtection.KeyManagement;
using Microsoft.AspNetCore.DataProtection.Repositories;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.AspNetCore.TestHost;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Tamp.Findings.Api.Authentication;
using Tamp.Findings.Data;
using Tamp.Findings.Domain.Entities;

namespace Tamp.Findings.Api.Tests;

// The project hub renders against a REAL database (TFND: hub 500).
//
// Unlike the DB-less render suites, this one points the host at the test
// Postgres and signs in as a real seeded admin, so the hub renders its cards
// through the real pipeline. That is the only way to catch the failure the DB-
// less suites cannot: a child card's async query racing the circuit-scoped
// DbContext (and outliving the prerender scope) — "A second operation was
// started on this context" — which 500s the whole shell.
[Collection("hub-db")]
public sealed class HubRenderConcurrencyTests : IAsyncLifetime
{
    private static readonly Guid AdminUserId = new("11111111-1111-1111-1111-111111111111");
    private static string? ConnString =>
        Environment.GetEnvironmentVariable("TAMP_FINDINGS_TEST_DB");

    private DbHubFactory _factory = default!;
    private string _client = "";
    private string _project = "";
    private bool _available;

    public async Task InitializeAsync()
    {
        _available = !string.IsNullOrWhiteSpace(ConnString);
        if (!_available) return;

        _factory = new DbHubFactory();
        using var scope = _factory.Services.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<FindingsDbContext>();

        var suffix = Guid.NewGuid().ToString("N")[..8];
        _client = $"HubTest{suffix}";
        _project = $"hub{suffix}";

        if (!await db.Users.AnyAsync(u => u.Id == AdminUserId))
        {
            db.Users.Add(new User
            {
                Id = AdminUserId, Login = "hub-admin", DisplayName = "Hub Admin",
                Email = "hub-admin@example.test", IsApproved = true, IsAdmin = true,
            });
        }

        var client = new Client { Name = _client };
        var project = new Project { ClientId = client.Id, Name = _project };
        var component = new Component { ProjectId = project.Id, Name = $"cmp{suffix}" };
        var version = new ComponentVersion
        {
            ProjectId = component.ProjectId, ComponentId = component.Id, VersionString = "1.0.0",
            CommitSha = suffix + "aaaaaa", BranchName = "main",
        };
        db.Clients.Add(client);
        db.Projects.Add(project);
        db.Components.Add(component);
        db.ComponentVersions.Add(version);
        await db.SaveChangesAsync();
    }

    public Task DisposeAsync() { _factory?.Dispose(); return Task.CompletedTask; }

    [SkippableTheory]
    [InlineData("/build/latest")]    // the project hub — the reported 500 (renders ProjectKeyCard)
    [InlineData("/settings/keys")]   // the OTHER page that renders ProjectKeyCard
    [InlineData("/poam")]
    [InlineData("/vex")]
    [InlineData("/costs")]
    public async Task Project_pages_render_against_a_real_database(string suffix)
    {
        Skip.IfNot(_available, "TAMP_FINDINGS_TEST_DB not set");

        var http = _factory.CreateClient();
        var resp = await http.GetAsync($"/c/{_client}/p/{_project}{suffix}");

        // The bug reproduced as a 500 on the prerendered document when a
        // component's async DB work raced the circuit-shared context.
        Assert.Equal(HttpStatusCode.OK, resp.StatusCode);
    }

    // A host pointed at the real test Postgres, signed in as the seeded admin.
    // The connection string is supplied through HOST-LOCAL configuration, never a
    // process-global environment variable — the other factories in this assembly
    // deliberately point at a dead database via env vars, and a global set here
    // would race them (and be raced by them) across parallel collections.
    private sealed class DbHubFactory : WebApplicationFactory<Program>
    {
        internal const string Scheme = "HubTestAuth";

        protected override void ConfigureWebHost(IWebHostBuilder builder)
        {
            // UseSetting feeds builder.Configuration early enough for Program's
            // connection-string read, and it is HOST-LOCAL — unlike a global env
            // var, it cannot be raced by the DB-less factories running in parallel.
            builder.UseSetting("ConnectionStrings:Findings", ConnString);

            builder.ConfigureTestServices(services =>
            {
                services.AddOptions<KeyManagementOptions>()
                    .Configure(o => o.XmlRepository = new InMemoryXmlRepository());

                services.AddAuthentication(Scheme).AddScheme<AuthenticationSchemeOptions, HubAuthHandler>(Scheme, _ => { });
                services.PostConfigure<AuthenticationOptions>(o =>
                {
                    o.DefaultAuthenticateScheme = Scheme;
                    o.DefaultChallengeScheme = Scheme;
                    o.DefaultScheme = Scheme;
                });
            });
        }

        private sealed class InMemoryXmlRepository : IXmlRepository
        {
            private readonly List<XElement> _elements = [];
            public IReadOnlyCollection<XElement> GetAllElements() { lock (_elements) return _elements.ToArray(); }
            public void StoreElement(XElement element, string friendlyName) { lock (_elements) _elements.Add(element); }
        }
    }

    private sealed class HubAuthHandler : AuthenticationHandler<AuthenticationSchemeOptions>
    {
        public HubAuthHandler(IOptionsMonitor<AuthenticationSchemeOptions> o, ILoggerFactory l, UrlEncoder e)
            : base(o, l, e) { }

        protected override Task<AuthenticateResult> HandleAuthenticateAsync()
        {
            var identity = new ClaimsIdentity(
            [
                new Claim(ClaimTypes.Name, "hub-admin"),
                new Claim(ClaimTypes.NameIdentifier, AdminUserId.ToString()),
                new Claim(AuthExtensions.TampUserIdClaim, AdminUserId.ToString()),
                new Claim(AuthExtensions.TampIsAdminClaim, "True"),
            ], DbHubFactory.Scheme);
            return Task.FromResult(AuthenticateResult.Success(
                new AuthenticationTicket(new ClaimsPrincipal(identity), DbHubFactory.Scheme)));
        }
    }
}
