using System.Net.Http.Headers;
using System.Security.Claims;
using System.Text.Encodings.Web;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.AspNetCore.TestHost;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Tamp.Findings.Api.Authentication;
using Tamp.Findings.Application.Ingest;
using Tamp.Findings.Data;
using Tamp.Findings.Domain.Entities;
using Tamp.Findings.Domain.Values;

namespace Tamp.Findings.Integration.Tests;

/// <summary>
/// Shared plumbing for the ApiB tests: a signed-in client whose identity is chosen per request
/// (header-driven, so one client can act as several users), and small seeders.
/// </summary>
internal static class ApiBSupport
{
    public const string Scheme = "ApiBTest";
    public const string UserHeader = "X-ApiB-User";

    public static readonly System.Text.Json.JsonSerializerOptions Json = new(System.Text.Json.JsonSerializerDefaults.Web)
    {
        Converters = { new System.Text.Json.Serialization.JsonStringEnumConverter() },
    };

    public static string Suffix() => Guid.NewGuid().ToString("N")[..10];

    /// <summary>A client whose every request is authenticated as the user id in <see cref="UserHeader"/>.</summary>
    public static WebApplicationFactory<Program> WithTestAuth(this WebApplicationFactory<Program> factory) =>
        factory.WithWebHostBuilder(b => b.ConfigureTestServices(services =>
        {
            services.AddAuthentication(Scheme)
                .AddScheme<AuthenticationSchemeOptions, ApiBAuthHandler>(Scheme, _ => { });
            services.PostConfigure<AuthenticationOptions>(o =>
            {
                o.DefaultAuthenticateScheme = Scheme;
                o.DefaultChallengeScheme = Scheme;
                o.DefaultScheme = Scheme;
            });
        }));

    public static HttpClient As(this WebApplicationFactory<Program> authed, Guid? userId)
    {
        var c = authed.CreateClient();
        if (userId is { } id) c.DefaultRequestHeaders.Add(UserHeader, id.ToString());
        return c;
    }

    public static HttpClient Bearer(this WebApplicationFactory<Program> factory, string token)
    {
        var c = factory.CreateClient();
        c.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", token);
        return c;
    }

    public sealed record World(
        Guid ClientId, string ClientName, Guid ProjectId, string ProjectName,
        Guid AdminId, string AdminLogin, Guid ViewerId, Guid LeadId, Guid OutsiderId);

    /// <summary>One client + project with an admin, a no-role viewer, a LeadDev on the project, and an outsider on a sibling client.</summary>
    public static async Task<World> SeedWorldAsync(FindingsDbContext db, string s)
    {
        var admin = new User { Login = $"apib-admin-{s}", DisplayName = "admin", Email = $"a{s}@e.test", IsApproved = true, IsAdmin = true };
        var viewer = new User { Login = $"apib-view-{s}", DisplayName = "viewer", Email = $"v{s}@e.test", IsApproved = true };
        var lead = new User { Login = $"apib-lead-{s}", DisplayName = "lead", Email = $"l{s}@e.test", IsApproved = true };
        var outsider = new User { Login = $"apib-out-{s}", DisplayName = "out", Email = $"o{s}@e.test", IsApproved = true };
        db.Users.AddRange(admin, viewer, lead, outsider);

        var client = new Client { Name = $"apib-c-{s}" };
        var other = new Client { Name = $"apib-c2-{s}" };
        db.Clients.AddRange(client, other);
        var project = new Project { ClientId = client.Id, Name = $"apib-p-{s}" };
        var otherProject = new Project { ClientId = other.Id, Name = $"apib-p2-{s}" };
        db.Projects.AddRange(project, otherProject);

        db.ProjectRoleAssignments.Add(new ProjectRoleAssignment { UserId = lead.Id, Role = ProjectRole.LeadDev, ProjectId = project.Id });
        db.ProjectRoleAssignments.Add(new ProjectRoleAssignment { UserId = outsider.Id, Role = ProjectRole.LeadDev, ProjectId = otherProject.Id });
        await db.SaveChangesAsync();

        return new World(client.Id, client.Name, project.Id, project.Name,
            admin.Id, admin.Login, viewer.Id, lead.Id, outsider.Id);
    }

    public static async Task<string> MintProjectTokenAsync(IServiceProvider sp, Guid projectId, Guid userId) =>
        (await sp.GetRequiredService<IngestTokenService>().MintProjectTokenAsync(projectId, "apib", userId, default)).Plaintext;

    public static async Task<Guid> SeedBuildAsync(FindingsDbContext db, Guid projectId, string? branch = "main", string? flavor = null)
    {
        var cv = new ComponentVersion
        {
            ProjectId = projectId, VersionString = "1.0.0", CommitSha = Suffix(),
            BranchName = branch, Flavor = flavor,
        };
        db.ComponentVersions.Add(cv);
        await db.SaveChangesAsync();
        return cv.Id;
    }
}

internal sealed class ApiBAuthHandler : AuthenticationHandler<AuthenticationSchemeOptions>
{
    public ApiBAuthHandler(IOptionsMonitor<AuthenticationSchemeOptions> options, ILoggerFactory logger, UrlEncoder encoder)
        : base(options, logger, encoder) { }

    protected override async Task<AuthenticateResult> HandleAuthenticateAsync()
    {
        if (!Request.Headers.TryGetValue(ApiBSupport.UserHeader, out var raw) || !Guid.TryParse(raw.ToString(), out var id))
            return AuthenticateResult.NoResult();

        var db = Context.RequestServices.GetRequiredService<FindingsDbContext>();
        var user = await db.Users.AsNoTracking().FirstOrDefaultAsync(u => u.Id == id);
        var identity = new ClaimsIdentity(
        [
            new Claim(ClaimTypes.Name, user?.Login ?? "ghost"),
            new Claim(ClaimTypes.NameIdentifier, id.ToString()),
            new Claim(AuthExtensions.TampUserIdClaim, id.ToString()),
            new Claim(AuthExtensions.TampIsAdminClaim, (user?.IsAdmin ?? false).ToString()),
        ], ApiBSupport.Scheme);
        return AuthenticateResult.Success(new AuthenticationTicket(new ClaimsPrincipal(identity), ApiBSupport.Scheme));
    }
}

internal sealed class ApiBLogCapture : ILoggerProvider
{
    public List<string> Lines { get; } = [];
    public ILogger CreateLogger(string categoryName) => new Capture(this);
    public void Dispose() { }

    private sealed class Capture(ApiBLogCapture owner) : ILogger
    {
        public IDisposable? BeginScope<TState>(TState state) where TState : notnull => null;
        public bool IsEnabled(LogLevel logLevel) => logLevel >= LogLevel.Error;
        public void Log<TState>(LogLevel logLevel, EventId eventId, TState state, Exception? exception, Func<TState, Exception?, string> formatter)
        {
            if (exception is null) return;
            lock (owner.Lines) owner.Lines.Add(formatter(state, exception) + " " + exception);
        }
    }
}
