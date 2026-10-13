using System.Security.Claims;
using Microsoft.AspNetCore.Http.HttpResults;
using Microsoft.EntityFrameworkCore;
using Tamp.Findings.Api.Authentication;
using Tamp.Findings.Application.Attestation;
using Tamp.Findings.Application.Authorization;
using Tamp.Findings.Data;

namespace Tamp.Findings.Api.Endpoints;

/// <summary>
/// OSCAL export as its own surface (TFND-39).
///
/// The ticket asks for this explicitly: "the redesign should not assume the
/// attestation view is the only consumer of this data — an OSCAL export path
/// may want its own surface."
///
/// It wants one because the consumers are different. The attestation screen is
/// read by a person who signs; this is read by a pipeline that submits a FedRAMP
/// package, and a pipeline should not have to drive a browser, click Export and
/// scrape a download to get a document the system can generate directly.
/// </summary>
public static class OscalEndpoints
{
    public static IEndpointRouteBuilder MapOscal(this IEndpointRouteBuilder app)
    {
        app.MapGet("/projects/{projectId:guid}/oscal", ExportAsync)
           .WithName("OscalExport")
           .WithTags("Attestation")
           .WithSummary(
               "OSCAL 1.1.2 for a build — assessment-results, plan-of-action-and-milestones, "
               + "component-definition, or a bundle of all three with shared UUIDs. FedRAMP "
               + "RFC-0024 requires machine-readable packages from 30 Sep 2026.");

        // Catalog IMPORT, the other direction (TFND-180, v3 §6).
        //
        // Multipart rather than a JSON body, and an endpoint rather than only a Blazor
        // handler, for one reason: the catalog is ~10 MB of OSCAL. The house pattern for
        // importing reference content is a textarea paste (see /system/policy-pack),
        // which is fine for a policy pack and hopeless for this.
        //
        // An HTTP route also serves the case the spec actually names — an air-gapped
        // instance, where somebody carries the file in and curls it, with no browser
        // and no egress to usnistgov.
        app.MapPost("/system/control-catalog", ImportCatalogAsync)
           .WithName("ImportControlCatalog")
           .WithTags("Compliance")
           .WithSummary(
               "Import an OSCAL control catalog as the new current one, with optional "
               + "baseline profiles (form fields: catalog, baseline-low, baseline-moderate, "
               + "baseline-high). Needs EditPolicyWeights. Idempotent by content hash; prior "
               + "catalogs are retained because attestations cite the version they signed against.")
           .DisableAntiforgery();

        return app;
    }

    private static async Task<IResult> ImportCatalogAsync(
        HttpContext ctx,
        FindingsDbContext db,
        PrincipalResolver principals,
        Application.Compliance.Oscal.ControlCatalogImportService import,
        CancellationToken ct)
    {
        if (!ctx.Request.HasFormContentType)
            return Results.BadRequest("Send multipart/form-data with a 'catalog' file.");

        var (actor, _, deny) = await EndpointActor.ForScopeAsync(
            ctx, db, principals, clientId: null, projectId: null, ct);
        if (deny is not null) return deny;

        // A malformed or empty multipart body throws rather than returning an empty form,
        // and that is a bad request, not a server fault.
        IFormCollection form;
        try
        {
            form = await ctx.Request.ReadFormAsync(ct);
        }
        catch (Exception ex) when (ex is InvalidDataException or IOException)
        {
            return Results.BadRequest($"That upload could not be read: {ex.Message}");
        }

        var catalog = form.Files["catalog"] ?? form.Files.FirstOrDefault();
        if (catalog is null) return Results.BadRequest("No 'catalog' file in the request.");

        // Profiles are OPTIONAL, and leaving them out is a real choice rather than an
        // incomplete request: a catalog on its own still carries every control and its
        // parameters. What it cannot carry is baseline membership, which lives in the
        // profiles — so without them every control imports as belonging to no baseline.
        var profiles = new Dictionary<Domain.Compliance.BaselineLevel, Stream>();
        var opened = new List<Stream>();
        try
        {
            void Add(Domain.Compliance.BaselineLevel level, string field)
            {
                if (form.Files[field] is not { Length: > 0 } file) return;
                var s = file.OpenReadStream();
                opened.Add(s);
                profiles[level] = s;
            }
            Add(Domain.Compliance.BaselineLevel.Low, "baseline-low");
            Add(Domain.Compliance.BaselineLevel.Moderate, "baseline-moderate");
            Add(Domain.Compliance.BaselineLevel.High, "baseline-high");

            await using var catalogStream = catalog.OpenReadStream();

            var source = form["source"].ToString() is { Length: > 0 } s2
                ? s2
                : $"Uploaded · {catalog.FileName}";

            var result = await import.ImportAsync(actor!, catalogStream, profiles, source, ct);

            if (result.WasDenied) return Results.Forbid();
            if (!result.Success) return Results.BadRequest(result.Error);
            return Results.Ok(result.Value);
        }
        finally
        {
            foreach (var s in opened) await s.DisposeAsync();
        }
    }

    private static async Task<Results<ContentHttpResult, NotFound<string>, BadRequest<string>, ForbidHttpResult>>
        ExportAsync(
            Guid projectId,
            string? commitSha,
            string? model,
            HttpContext http,
            FindingsDbContext db,
            SsdfAttestationBuilder builder,
            AttestationExporter exporter,
            CapabilityEvaluator capabilities,
            PrincipalResolver principals,
            ILoggerFactory logs,
            CancellationToken ct)
    {
        if (!Enum.TryParse<OscalModel>(model ?? nameof(OscalModel.Bundle), ignoreCase: true, out var wanted))
        {
            return TypedResults.BadRequest(
                $"model must be one of: {string.Join(", ", Enum.GetNames<OscalModel>())}");
        }

        var project = await db.Projects.AsNoTracking()
            .Where(p => p.Id == projectId)
            .Select(p => new { p.Id, p.ClientId })
            .SingleOrDefaultAsync(ct);
        if (project is null) return TypedResults.NotFound("project not found");

        // Who is acting comes from the authenticated cookie, never a header —
        // and the capability is evaluated at the PROJECT, because export rights
        // are scoped like every other right in this product.
        if (!Guid.TryParse(http.User.FindFirstValue(AuthExtensions.TampUserIdClaim), out var userId))
            return TypedResults.Forbid();

        var scope = ScopeTarget.Project(project.ClientId, project.Id);
        var actor = await principals.ResolveAsync(userId, scope, ct);
        if (actor is null) return TypedResults.Forbid();

        var decision = capabilities.Evaluate(actor, Capability.ExportAttestation);
        if (!decision.Allowed)
        {
            // ForbidHttpResult carries no body, so the reason goes to the log
            // rather than being lost — a 403 nobody can explain is a support
            // ticket.
            logs.CreateLogger("Tamp.Findings.Oscal")
                .LogWarning("OSCAL export denied for {Login} on {ProjectId}: {Reason}",
                    actor.Login, projectId, decision.Reason);
            return TypedResults.Forbid();
        }

        var doc = await builder.BuildAsync(projectId, commitSha, ct);
        if (doc is null) return TypedResults.NotFound("project not found, or no default risk policy seeded");

        // A document with no build has nothing to attest. Emitting a package
        // that looks official and says nothing is worse than refusing — it
        // would enter a submission queue and be rejected there, days later, by
        // somebody with no idea why it was empty.
        if (doc.Build is null)
            return TypedResults.BadRequest("no canonical build to attest — ingest one first");

        var payload = await exporter.ExportAsync(actor, scope, doc, AttestationFormat.Oscal, wanted, ct);
        if (!payload.Success) return TypedResults.BadRequest(payload.Error!);

        // Content rather than a file download: the caller is a pipeline, and
        // Content-Disposition would make it save a file it wants to pipe. The
        // filename the UI would have used is on a header for anyone who does
        // want to write it out.
        http.Response.Headers["X-Tamp-Filename"] = payload.Value!.FileName;

        return TypedResults.Content(
            System.Text.Encoding.UTF8.GetString(payload.Value.Content),
            "application/json");
    }
}
