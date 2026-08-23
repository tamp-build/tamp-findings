using Tamp.Findings.Application.Ingest;
using Tamp.Findings.Application;
using Tamp.Findings.Web.Components;
using System.Text.Json.Serialization;
using Microsoft.AspNetCore.HttpOverrides;
using Microsoft.EntityFrameworkCore;
using Tamp.Findings.Api.Authentication;
using Tamp.Findings.Api.Endpoints;
using Tamp.Findings.Api.Services;
using Tamp.Findings.Application.Risk;
using Tamp.Findings.Data;
using Microsoft.AspNetCore.Authentication.OAuth;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Options;
using Tamp.Findings.Workflows;

var builder = WebApplication.CreateBuilder(args);

// Raise both the request-body limit (Kestrel) and the form value count limit
// so coverage ingest, which bundles every source file in the scan scope, can
// post a few MB of payload without the framework refusing it. 100 MB ceiling
// is generous for a single-repo scan; cap stays well below shenanigan territory.
builder.WebHost.ConfigureKestrel(k => k.Limits.MaxRequestBodySize = 100L * 1024 * 1024);

// Behind the Cloudflare tunnel in prod: the tunnel terminates TLS at
// the edge and forwards plain HTTP to the in-cluster Service. Without
// this, ASP.NET Core builds OAuth redirect URIs from the Host it
// actually sees (an internal pod IP, scheme http://) — which GitHub
// rejects with "redirect_uri is not associated with this application".
//
// Trust X-Forwarded-Proto + X-Forwarded-Host (Cloudflare adds both)
// so HttpContext.Request reflects the public-origin URL.
//
// Empty KnownNetworks/KnownProxies + ForwardLimit=null = trust the
// tunnel regardless of source IP. Safe because the cluster Service is
// only reachable via the tunnel; no direct LAN ingress to the pod.
builder.Services.Configure<ForwardedHeadersOptions>(o =>
{
    o.ForwardedHeaders = ForwardedHeaders.XForwardedFor
                       | ForwardedHeaders.XForwardedProto
                       | ForwardedHeaders.XForwardedHost;
    o.KnownIPNetworks.Clear();
    o.KnownProxies.Clear();
});

builder.Services.AddOpenApi();

// Spec promises every error response is JSON. Without ProblemDetails,
// minimal API deserialization failures return 400 with empty body —
// adopters of /ingest/* (Tamp.Ingest.V1, etc.) can't debug a malformed
// payload because the wire response says nothing. AddProblemDetails +
// UseStatusCodePages downstream gives every 4xx/5xx a Problem Details
// JSON body (RFC 9457: { type, title, status, detail, instance }).
builder.Services.AddProblemDetails();

// Enums on the wire are strings, not ints — friendlier for hand-written
// payloads from scanners and for the agent surface in F11.
builder.Services.ConfigureHttpJsonOptions(o =>
    o.SerializerOptions.Converters.Add(new JsonStringEnumConverter()));

// Postgres connection comes from configuration. In dev the bundled
// docker-compose Postgres exposes this on localhost:5432; in prod, set
// TAMP_FINDINGS_DB or ConnectionStrings:Findings to point at a real Postgres.
var connectionString =
    builder.Configuration["ConnectionStrings:Findings"]
    ?? Environment.GetEnvironmentVariable("TAMP_FINDINGS_DB")
    ?? "Host=localhost;Port=5544;Database=tamp_findings;Username=tamp;Password=tamp";

builder.Services.AddFindingsDb(connectionString);

// TFND-115: the workflow engine, off by default.
//
// Off because nothing in the product REQUIRES it. Approvals are rows enforced
// by ApprovalService, and they have to keep working with the engine stopped —
// a pending decision that vanishes when a worker is down is worse than having
// no workflow at all. What Elsa adds is the time-driven half: expiring an
// unanswered request, and the daily due-date sweep.
//
// It also owns its own tables in its own DbContext, so enabling it is a schema
// change to a schema this repo does not author. Making that opt-in keeps a
// deployment that does not want it free of it entirely.
if (builder.Configuration.GetValue("Workflows:Enabled", false))
{
    builder.Services.AddTampWorkflows(connectionString);
}

// IHttpClientFactory powers the SBOM registry enrichment service. A
// single named client is registered so the factory can pool sockets
// across enrichment calls.
builder.Services.AddHttpClient("registries");
builder.Services.AddScoped<SbomEnrichmentService>();
// Builds RiskInputs for an explicit CV-id set — drives the per-build
// evaluator. /aggregates still computes its own inline against the
// latest-canonical set; a future refactor can consolidate.
// TFND-25: project-scoped VEX statements suppress matching vulns from
// CVE counts + KEV count.

// TFND-26: CISA Known Exploited Vulnerabilities catalog. Service does
// the actual upsert; the hosted worker schedules it (startup + daily).
// TFND-23: check runs are published OUT OF BAND of the ingest that triggers
// them. The findings are stored by the time this is queued; a notification that
// holds a CI step open is worse than a late one.
builder.Services.AddSingleton<Tamp.Findings.Api.Services.CheckPublishQueue>();
builder.Services.AddHostedService<Tamp.Findings.Api.Services.CheckPublishWorker>();
builder.Services.TryAddSingleton(TimeProvider.System);

// TFND-11 (F10.5): a suppression's expiry date is the date it stops working,
// not the date of the next build that happens to touch the finding.
builder.Services.AddHostedService<Tamp.Findings.Api.Services.SuppressionExpiryWorker>();

builder.Services.AddScoped<Tamp.Findings.Api.Services.KevFeedSyncService>();
builder.Services.AddHostedService<Tamp.Findings.Api.Services.KevFeedSyncWorker>();

builder.Services.AddCors(options =>
{
    // POC dev posture: any origin allowed. The SPA uses Vite's /api proxy
    // so same-origin via the dev server is the normal path — this opens
    // direct API access for ad-hoc curl from other machines, the MCP
    // server, and any future tools. Tighten to an allow-list before any
    // non-local deployment.
    options.AddDefaultPolicy(p =>
        p.AllowAnyOrigin()
         .AllowAnyHeader()
         .AllowAnyMethod());
});

// TFND-4 OIDC sign-in. Cookie session + GitHub OAuth challenge.
builder.Services.AddTampFindingsAuth(builder.Configuration);

// TFND-111: identity providers configured in the DATABASE, registered at
// runtime rather than at startup. This is what makes adding or disabling one
// take effect without a redeploy — the rows are the source of truth and the
// running schemes are derived from them.
//
// The HOST's data protection is deliberately left alone. Provider secrets get
// their own database-backed key ring (ProviderSecretProtector) because they must
// survive a restart; putting the host's on the database too would make Blazor's
// render-mode payload and the auth cookie depend on it, and a database outage
// would become a 500 on every URL instead of a screen that says "Unavailable".
builder.Services.AddSingleton<DynamicProviderStore>();
builder.Services.AddSingleton<DynamicSchemeRegistry>();
builder.Services.AddSingleton<IConfigureOptions<OAuthOptions>, DynamicOAuthOptions>();
builder.Services.AddSingleton<IConfigureOptions<OpenIdConnectOptions>, DynamicOidcOptions>();
builder.Services.AddHostedService<IdentityProviderStartup>();

// Lets /_framework through the authorization gate so an anonymous visitor can
// boot the circuit that renders the sign-in page. See the type for the two
// approaches that do NOT work (TFND-126).
builder.Services.AddSingleton<
    Microsoft.AspNetCore.Authorization.IAuthorizationMiddlewareResultHandler,
    Tamp.Findings.Api.Authentication.FrameworkAssetAuthorizationHandler>();

// TFND-40 / ADR 0002. The Blazor UI lives in Tamp.Findings.Web (a Razor Class
// Library) and is hosted here — one process, one port, one cookie, so the
// single-image deployment (TFND-4) holds. Interactivity is declared per
// component rather than globally: the dense screens want InteractiveServer,
// while the attestation (a print target feeding the PDF generator) and sign-in
// stay static SSR.
builder.Services.AddRazorComponents()
    .AddInteractiveServerComponents();

// Flows the signed-in user into components so [Authorize] and
// AuthorizeRouteView can see them.
builder.Services.AddCascadingAuthenticationState();

// Current client / project / component / build / spine / selection, read from
// the route. Scoped, so one instance per circuit — the sidebar scope card, the
// header URL chip and every screen body all read the same answer rather than
// each parsing the URL for themselves (TFND-63).
builder.Services.AddScoped<Tamp.Findings.Web.Routing.RouteScope>();

// Row density and the per-build delta toggle. Persona-dependent rather than
// screen-dependent — the four personas want very different densities of the
// same data, which the brief called the central design problem (TFND-66).
builder.Services.AddScoped<Tamp.Findings.Web.Routing.ViewPreferences>();

// The signed-in user resolved to a Principal at a scope. Every gated screen
// needs it, because the design disables an action and says why rather than
// hiding it (TFND-80).
builder.Services.AddScoped<Tamp.Findings.Web.Security.CurrentUser>();

// Localization (TFND-67). Strings live in resources, never in markup.
//
// The pseudo-locale decorator sits ON TOP of the real localizer, so a string
// only gets accented if it went through the catalogue — anything still plain
// ASCII under ?culture=qps-ploc is a hardcoded literal. That is the test, and
// it only works at this seam.
builder.Services.AddLocalization(o => o.ResourcesPath = "Resources");
builder.Services.AddScoped(typeof(Microsoft.Extensions.Localization.IStringLocalizer<>),
    typeof(Tamp.Findings.Web.Localization.PseudoStringLocalizer<>));

// Authorization, query/command services and the audit write path all live
// behind this one call, shared by the API endpoints, the Blazor components and
// (in process) the MCP tools. Empty until TFND-68.
builder.Services.AddFindingsApplication();

// Bearer-token auth for /ingest/*. Each request brings a cli_/prj_
// token; the filter validates + stashes the row, the endpoints
// scope-check resolved Client/Project against it.
builder.Services.AddScoped<Tamp.Findings.Api.Authentication.IngestAuthFilter>();

// TFND-12 (F11): the MCP server, hosted IN THIS PROCESS.
//
// In-process rather than a sidecar so the tools call the Application layer
// directly (ADR 0002) — an agent's read goes through the same
// CapabilityEvaluator a human's does. A separate host would need its own copy
// of that decision, and two copies drift.
//
// Registering it is not the same as serving it: the endpoint is gated on the
// McpEnabled instance setting, which is off until an operator turns it on.
builder.Services.AddMcpServer(options =>
    {
        options.ServerInfo = new ModelContextProtocol.Protocol.Implementation
        {
            Name = "tamp.findings",
            Version = typeof(Program).Assembly.GetName().Version?.ToString() ?? "0.0.0",
        };
    })
    // Stateless, and that is load-bearing rather than incidental: the agent's
    // identity lives on a SCOPED AgentContext that the auth middleware fills in
    // per request, so a tool and the middleware that authorised it have to share
    // one DI scope. A long-lived session would put them in different scopes and
    // AgentContext.Require() would throw — loudly, which is the right failure,
    // but do not turn sessions on without moving the identity with them.
    .WithHttpTransport(options => options.Stateless = true)
    .WithTools<Tamp.Findings.Mcp.FindingsTools>();

var app = builder.Build();

// Run pending migrations on startup so adopters don't need to remember
// `dotnet ef`. Test hosts opt out via the TAMP_FINDINGS_SKIP_MIGRATE env var.
if (Environment.GetEnvironmentVariable("TAMP_FINDINGS_SKIP_MIGRATE") != "true")
{
    using var scope = app.Services.CreateScope();
    var db = scope.ServiceProvider.GetRequiredService<FindingsDbContext>();
    db.Database.Migrate();

    // TFND-8 (F7.2): keep the built-in paid-component registry current.
    //
    // Idempotent, and it never writes the cost, currency, support date or
    // enabled flag — those belong to the operator. An upgrade can add a vendor
    // without overwriting what somebody recorded about their own contract.
    await Tamp.Findings.Application.SystemAdmin.PaidComponentRegistry.SeedAsync(db);

    // Arm the administrator claim token if nobody has signed in yet
    // (TFND-126). Printed to the container log because whoever can read the
    // log is the operator — that possession is what the token proves.
    //
    // Disarmed the moment any user exists, so restarting an in-use instance
    // never prints a live claim token.
    var setup = scope.ServiceProvider.GetRequiredService<Tamp.Findings.Application.Setup.SetupToken>();
    setup.Arm(await db.Users.CountAsync());
    if (setup.ValueForStartupLog is { } claimToken)
    {
        var banner = new string('=', 68);
        Console.WriteLine();
        Console.WriteLine(banner);
        Console.WriteLine("  tamp.findings is UNCLAIMED — no administrator exists yet.");
        Console.WriteLine();
        Console.WriteLine("  Sign in and enter this setup token to claim the admin seat:");
        Console.WriteLine();
        Console.WriteLine($"      {claimToken}");
        Console.WriteLine();
        Console.WriteLine("  It is shown only while the instance is unclaimed, and it is not");
        Console.WriteLine("  stored anywhere. A wrong token creates no account.");
        Console.WriteLine(banner);
        Console.WriteLine();
    }
    // Ensure exactly one system-default RiskPolicy exists. Seeded from
    // RiskPolicyDefaults so the v1 weights stay in one place; admins can
    // edit the seed row in place after first run.
    if (!await db.RiskPolicies.AnyAsync(p => p.IsDefault))
    {
        db.RiskPolicies.Add(new Tamp.Findings.Domain.Entities.RiskPolicy
        {
            Name = Tamp.Findings.Domain.Risk.RiskPolicyDefaults.TampStandardV1Name,
            Description = "System-seeded default. Editable — admins can tune the weights or clone to start a new policy.",
            IsDefault = true,
            IsSeeded = true,
            Config = Tamp.Findings.Domain.Risk.RiskPolicyDefaults.BuildTampStandardV1(),
        });
        await db.SaveChangesAsync();
    }

    // Seed the federal policy alongside the default, for contract work
    // that specifies dynamic analysis (SSDF PW.8.1 / 800-53 SA-11(8)).
    // Deliberately NOT IsDefault: adopting it is a per-project decision
    // via Project.RiskPolicyId, so its arrival never rescores anyone.
    // Idempotent on name — an admin who renames or deletes it won't have
    // it silently reappear under the old name on the next boot.
    var federalName = Tamp.Findings.Domain.Risk.RiskPolicyDefaults.TampFederalV1Name;
    if (!await db.RiskPolicies.AnyAsync(p => p.Name == federalName))
    {
        db.RiskPolicies.Add(new Tamp.Findings.Domain.Entities.RiskPolicy
        {
            Name = federalName,
            Description = "Adds DAST scoring (dastSevere / dastLow) and expects all six scanner classes. "
                        + "Schema 2 — weights are relative and normalise to 100. Assign per project; not the system default.",
            IsDefault = false,
            IsSeeded = true,
            Config = Tamp.Findings.Domain.Risk.RiskPolicyDefaults.BuildTampFederalV1(),
        });
        await db.SaveChangesAsync();
    }
}

// ForwardedHeaders MUST run before anything that reads Request.Scheme
// / Request.Host (auth, redirect builders, OAuth challenge URL
// generation). Goes first in the pipeline.
app.UseForwardedHeaders();

// Backstop for any 4xx/5xx that reaches the client with an empty
// body — pairs with AddProblemDetails() to ensure every error
// response carries a parseable JSON payload. Specifically catches
// the minimal-API deserialization 400 (record-binding failure) that
// otherwise returns Content-Length: 0.
app.UseStatusCodePages();

app.UseCors();

// Static assets: stylesheets, fonts and the Blazor framework script.
//
// TFND-128 retired the React SPA, so UseDefaultFiles is gone with it — there is
// no index.html to rewrite `/` to, and Blazor's Portfolio page owns the root.
app.UseStaticFiles();
// NOTE: deliberately UseStaticFiles rather than MapStaticAssets.
//
// UseStaticFiles is middleware — it runs before routing and authorization, so
// stylesheets, fonts and the Blazor framework script are served without an
// authorization check. That is what we want: they are not secrets, and the
// sign-in page (TFND-126) has to load its own CSS and boot a circuit BEFORE
// the visitor is authenticated.
//
// MapStaticAssets was tried first and is the modern default, but it registers
// ENDPOINTS, which inherit the host's RequireAuthenticatedUser fallback policy
// — and marking them AllowAnonymous produced 200s with empty bodies for every
// asset, including the fingerprinted URLs its own Assets[] helper emits. The
// middleware path has no such interaction. Revisit only with a test that
// actually fetches an asset and asserts its length; a status code alone does
// not catch this.
//
// UseStaticFiles above already serves the RCL's wwwroot through the static
// web assets file provider, so _content/Tamp.Findings.Web/ resolves here.

// Culture negotiation. Accept-Language by default; ?culture=qps-ploc switches
// the running app into the pseudo-locale, which is how the ~40% expansion is
// verified per screen without a translator (TFND-67).
var supportedCultures = new[] { "en", Tamp.Findings.Web.Localization.PseudoLocale.CultureName };
app.UseRequestLocalization(new Microsoft.AspNetCore.Builder.RequestLocalizationOptions()
    .SetDefaultCulture("en")
    .AddSupportedCultures(supportedCultures)
    .AddSupportedUICultures(supportedCultures));

app.UseAuthentication();
app.UseAuthorization();

// TFND-12: bearer-token auth for the agent surface, attached to the PATH
// BRANCH rather than to each mapped route.
//
// MapMcp registers more than one route — the stream, and the POST that rides it
// — so a per-route filter would be one SDK upgrade away from leaving one
// uncovered. A branch covers whatever the SDK maps, today and after.
//
// It runs BEFORE the transport, so a bad token never reaches a tool and never
// opens a stream.
app.UseWhen(
    ctx => ctx.Request.Path.StartsWithSegments("/mcp"),
    branch => branch.UseMiddleware<Tamp.Findings.Api.Authentication.McpAuthMiddleware>());

app.UseAntiforgery();
app.MapOpenApi().AllowAnonymous();

app.MapGet("/health", () => Results.Ok(new { status = "ok", service = "tamp.findings.api" }))
   .WithName("Health")
   .WithSummary("Liveness probe")
   .AllowAnonymous();

app.MapGet("/version", () => Results.Ok(new
{
    service = "tamp.findings.api",
    version = typeof(Program).Assembly.GetName().Version?.ToString() ?? "0.0.0",
}))
   .WithName("Version")
   .WithSummary("Build version")
   .AllowAnonymous();

// Auth surface — challenge, callback (registered by the OAuth handler at
// /auth/github/callback), /auth/me, /auth/logout, /auth/denied.
app.MapAuth();

// Ingest-token CRUD — SPA-facing, behind the cookie-auth fallback.
app.MapIngestTokens();

// TFND-12: the agent surface.
//
// AllowAnonymous at the ENDPOINT because this path carries its own bearer-token
// auth (see McpAuthMiddleware, branched onto /mcp above). Without it the host's
// cookie fallback policy would answer an agent with a sign-in redirect it
// cannot follow, and the failure would look like a broken server rather than a
// bad token.
app.MapMcp("/mcp").AllowAnonymous();

// Ingest endpoints — anonymous. Build script + future CI runners post to
// these from outside a browser; bearer-token auth for them is TFND-4
// follow-up work. Each endpoint flags itself .AllowAnonymous() to opt out
// of the FallbackPolicy.
app.MapIngest();
app.MapSbomIngest();
app.MapCoverageIngest();
app.MapScanRunIngest();
app.MapSbomEnrich();
app.MapSbomVulnerabilities();

// SPA-facing query endpoints — protected by the fallback policy
// (RequireAuthenticatedUser; see AuthExtensions).
app.MapCoverageDetail();
app.MapTestResults();
app.MapFindingsQuery();
app.MapFindingsList();
app.MapFindingsTree();
app.MapDast();
app.MapSbomComponents();
app.MapSuppressions();
app.MapRoleAssignments();
app.MapAggregates();
app.MapRiskPolicies();
app.MapProjectScanReceipts();
app.MapBuildEvaluation();
app.MapVexStatements();
app.MapPoamItems();
app.MapSsdfAttestation();
app.MapOscal();
app.MapProjectVdp();
app.MapSbomProvenance();
app.MapHierarchyCreate();

// SPA fallback — any URL the API doesn't match (i.e. client-side
// routes like /projects/<id>/attestation) serves index.html so the
// React Router can pick it up on hydration. MUST come after all
// API routes; otherwise it would shadow them. AllowAnonymous so a
// signed-out visitor sees the SignInView rather than a 401.
// Blazor UI (TFND-40). Registered BEFORE the SPA fallback: an explicit route
// always beats a fallback, so the two frontends coexist on one origin with no
// path prefix and nothing to unwind at cutover (TFND-128). Blazor claims only
// the routes its components declare — today just /ui.
//
// Consequence while both are live: no Blazor page may claim "/" until the SPA
// is retired, or it shadows index.html.
// Serves the Blazor framework script. It ships in the
// microsoft.aspnetcore.app.internal.assets package as a static web asset and
// is reachable ONLY through this — UseStaticFiles cannot find it, which is why
// /_framework/blazor.web.js 404'd without it and no circuit ever booted.
//
// It registers ENDPOINTS, so these paths inherit the host's fallback policy —
// that is what FrameworkAssetAuthorizationHandler exists for. Do NOT add
// .AllowAnonymous() here: that produced 200 responses with EMPTY BODIES for
// every asset, which looks exactly like a working app with no styling.
app.MapStaticAssets();

app.MapRazorComponents<App>()
    .AddInteractiveServerRenderMode()
    // AllowAnonymous at the ENDPOINT, [Authorize] at the COMPONENT. The host's
    // FallbackPolicy would otherwise gate _framework/blazor.web.js itself, so
    // an anonymous visitor could not boot the circuit that renders the sign-in
    // page — and would get a JSON 401 rather than a challenge. Per-page
    // authorization is handled by AuthorizeRouteView in Routes.razor, and the
    // real gate is the Application layer (ADR 0002), not this endpoint.
    .AllowAnonymous();

// TFND-128: no SPA fallback. Every route Blazor does not recognise now reaches
// Blazor's own NotFound, which renders inside the shell with the reader's
// navigation intact — rather than silently serving index.html for a URL nothing
// answers, which is how a typo used to look like a working page that failed to
// load.

app.Run();

// Surfaced for WebApplicationFactory<Program> in tests.
public partial class Program;
