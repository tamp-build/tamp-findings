using Microsoft.Extensions.DependencyInjection;

namespace Tamp.Findings.Application;

// Composition root for the application layer (ADR 0002).
//
// Every consumer — Tamp.Findings.Api, Tamp.Findings.Web and
// Tamp.Findings.Mcp — registers the same services through this one call, so
// none of them can end up with a different set of rules than the others.
//
// This is deliberately empty at the scaffold stage. It fills up as work lands:
//   TFND-68  the capability model and authorization evaluator
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
        return services;
    }
}
