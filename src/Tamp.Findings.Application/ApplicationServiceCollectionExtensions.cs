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

        return services;
    }
}
