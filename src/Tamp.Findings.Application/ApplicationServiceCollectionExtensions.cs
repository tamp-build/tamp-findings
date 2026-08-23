using Microsoft.Extensions.DependencyInjection;

namespace Tamp.Findings.Application;

// Composition root for the application layer (ADR 0002).
//
// Every consumer — Tamp.Findings.Api, Tamp.Findings.Web and
// Tamp.Findings.Mcp — registers the same services through this one call, so
// none of them can end up with a different set of rules than the others.
//
// Fills up as work lands:
//   TFND-68  the capability model and authorization evaluator  [done]
//   TFND-73  the audit write path
//   later    query/command services, migrated out of Tamp.Findings.Api.Services
//
// The migration out of Api.Services is incremental by design — a big-bang move
// would destabilise ingest, which is not part of the TFND-40 redesign. It must
// still be finished: TFND-129 verifies Api.Services carries no business logic
// before the track closes.
public static class ApplicationServiceCollectionExtensions
{
    public static IServiceCollection AddFindingsApplication(this IServiceCollection services)
    {
        // Stateless and cheap. Registering it here rather than in each host is
        // the point of ADR 0002: Api, Web and Mcp cannot end up with different
        // authorization rules because there is only one registration.
        services.AddSingleton<Authorization.CapabilityEvaluator>();

        // Singleton and in-memory: the setup token is armed once at startup
        // and must not survive into the database, where it would become a
        // standing credential rather than a one-time claim.
        services.AddSingleton<Setup.SetupToken>();
        services.AddSingleton<Authorization.ScopeResolver>();

        // Scoped: it reads the DbContext, and the admin flag is read from the
        // DATABASE rather than from a claim, so a stale cookie cannot carry an
        // admin flag that has since been revoked.
        services.AddScoped<Authorization.PrincipalResolver>();

        // Scoped, and deliberately NOT saving on its own: an audit entry joins
        // the same transaction as the change it describes, so it can never
        // survive a rolled-back action and an action can never commit without
        // its entry.
        services.AddScoped<Auditing.AuditLog>();

        // Moved here from Tamp.Findings.Api.Services (ADR 0002): the Blazor UI
        // needs them and cannot reference the API project. The migration is
        // incremental by design — a service moves when the first non-API
        // consumer needs it, not in a big bang that would destabilise ingest.
        services.AddScoped<Risk.RiskInputsBuilder>();
        services.AddScoped<Risk.VexResolver>();
        services.AddScoped<Projects.ProjectHubQuery>();
        services.AddScoped<Projects.ComponentService>();
        services.AddScoped<Projects.PortfolioQuery>();
        services.AddScoped<Projects.HierarchyService>();
        services.AddScoped<Explorer.FindingsExplorerQuery>();
        services.AddScoped<Explorer.DastExplorerQuery>();
        services.AddScoped<Explorer.SbomExplorerQuery>();
        services.AddScoped<Explorer.CoverageAndTestsQuery>();
        services.AddScoped<Explorer.HostAliasService>();
        services.AddScoped<Explorer.RuleBreakdownQuery>();
        services.AddScoped<Explorer.CostsAndLicensesQuery>();
        services.AddScoped<SystemAdmin.PaidComponentRegistry>();
        services.AddScoped<Poam.PoamQuery>();
        services.AddScoped<Poam.PoamService>();
        services.AddScoped<Vex.VexQuery>();
        services.AddScoped<Attestation.SsdfAttestationBuilder>();
        services.AddScoped<Attestation.AttestationExporter>();
        services.AddScoped<Attestation.AttestationSnapshotService>();
        services.AddScoped<Policy.PolicyService>();
        services.AddScoped<Policy.GateService>();
        services.AddScoped<Projects.ProjectSettingsService>();
        services.AddScoped<SystemAdmin.SystemAdminService>();
        services.AddScoped<SystemAdmin.IdentityProviderService>();
        // Singleton: it owns a key ring, and building one per request would
        // re-read the key table on every provider save.
        services.AddSingleton<SystemAdmin.ProviderSecretProtector>();
        services.AddScoped<Approvals.ApprovalService>();
        services.AddScoped<Projects.ClientQuery>();
        services.AddScoped<Ingest.IngestTokenService>();
        services.AddScoped<Ingest.CveReconciler>();

        // TFND-23: the GitHub App client. A NAMED client with the API base
        // address pinned here, so no call site can accidentally point the
        // App's credentials at a different host.
        services.AddHttpClient<GitHub.GitHubCheckPublisher>(http =>
        {
            http.BaseAddress = new Uri("https://api.github.com/");
            // GitHub is a dependency, not a partner: a slow response must not
            // hold an ingest open.
            http.Timeout = TimeSpan.FromSeconds(20);
        });
        services.AddScoped<Projects.ProjectKeyService>();

        // TFND-12: the agent surface.
        //
        // AgentContext is SCOPED and holds the resolved token for the request
        // being served. Registering it here rather than in the API host is what
        // stops a second host from inventing its own way to decide who an agent
        // is — the tools can only read it from this one place.
        services.AddScoped<Mcp.McpTokenService>();
        services.AddScoped<Mcp.AgentReadService>();
        services.AddScoped<Mcp.AgentContext>();

        return services;
    }
}
