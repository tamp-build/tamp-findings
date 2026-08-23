using Elsa.Extensions;
using Elsa.Scheduling.Features;
using Elsa.Persistence.EFCore.Extensions;
using Elsa.Persistence.EFCore.Modules.Management;
using Elsa.Persistence.EFCore.Modules.Runtime;
using Microsoft.Extensions.DependencyInjection;
using Tamp.Findings.Workflows.Definitions;

namespace Tamp.Findings.Workflows;

/// <summary>
/// Bringing Elsa into the host (TFND-115).
///
/// Two execution paths, deliberately kept distinguishable:
///
///   IWorkflowRunner     in-process, synchronous, no persistence. The RULES
///                       path. ADR 0001's constraint lives here: a rule
///                       workflow evaluates a finding SET, not a finding. Ten
///                       rules over 5,000 findings is ten invocations (~8 ms);
///                       per-finding would be 50,000 (~40 s) and is not viable.
///
///   IWorkflowDispatcher background queue, persisted. The APPROVALS path,
///                       where a workflow waits days for a person.
///
/// Elsa owns its own tables in its own DbContext. It is not folded into
/// FindingsDbContext's migration history: the engine's schema is the engine's
/// business, and an Elsa upgrade should not need a migration authored here.
/// </summary>
public static class WorkflowServiceCollectionExtensions
{
    public static IServiceCollection AddTampWorkflows(
        this IServiceCollection services, string connectionString)
    {
        services.AddElsa(elsa =>
        {
            elsa.UseWorkflowManagement(management =>
                management.UseEntityFrameworkCore(ef => ef.UsePostgreSql(connectionString)));

            elsa.UseWorkflowRuntime(runtime =>
                runtime.UseEntityFrameworkCore(ef => ef.UsePostgreSql(connectionString)));

            // Timers and delays. The scheduled workflows are the only ones
            // that genuinely need the engine, which is what earns this feature
            // its place — the approvals are state in the database, not
            // orchestration.
            elsa.UseScheduling();

            // Definitions ship as CODE, per the spike: "workflow definitions
            // ship as definitions; no authoring UI is required to run them".
            // Elsa Studio (TFND-125) is a way to LOOK at them later, never a
            // prerequisite for running them.
            elsa.AddWorkflowsFrom<PoamRiskAcceptanceWorkflow>();
        });

        // The bridge from an Elsa activity back into the application layer.
        // Activities resolve this rather than reaching for a DbContext, so
        // every workflow-driven change goes through the same capability checks
        // and the same audit path as a human-driven one (ADR 0002).
        services.AddScoped<WorkflowBridge>();

        return services;
    }
}
