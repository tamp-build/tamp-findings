using Microsoft.EntityFrameworkCore;
using Tamp.Findings.Api.Authentication;
using Tamp.Findings.Api.Contracts;
using Tamp.Findings.Data;
using Tamp.Findings.Domain.Entities;

namespace Tamp.Findings.Api.Endpoints;

/// <summary>
/// Recording the image a build produced, and the base image behind it
/// (TFND-134).
///
/// A base image is usually the single largest source of inherited CVEs in a
/// deployed artefact, and unlike a package it is one line in a Dockerfile — the
/// highest leverage per fix available. Until this existed the product could see
/// every CVE the base image dragged in and could not say where they came from
/// or how old the foundation was.
/// </summary>
public static class ContainerImageIngestEndpoints
{
    public static IEndpointRouteBuilder MapContainerImageIngest(this IEndpointRouteBuilder app)
    {
        app.MapPost("/ingest/container-image", IngestAsync)
           .WithName("IngestContainerImage")
           .WithTags("Ingest")
           .WithSummary(
               "Record the image a build produced and, when identifiable, the base image behind it. "
               + "Produced by Tamp.Trivy InspectImage (TAM-282). Requires Authorization: Bearer cli_… or prj_…")
           .AllowAnonymous()
           .AddEndpointFilter<IngestAuthFilter>();

        return app;
    }

    private static async Task<IResult> IngestAsync(
        ContainerImageIngestRequest req, HttpContext ctx, FindingsDbContext db, CancellationToken ct)
    {
        if (string.IsNullOrWhiteSpace(req.Client)) return Results.BadRequest("client required");
        if (string.IsNullOrWhiteSpace(req.Project)) return Results.BadRequest("project required");
        if (string.IsNullOrWhiteSpace(req.Component)) return Results.BadRequest("component required");
        if (string.IsNullOrWhiteSpace(req.Version)) return Results.BadRequest("version required");
        if (string.IsNullOrWhiteSpace(req.Reference)) return Results.BadRequest("reference required");

        // A base timestamp with no base reference is a report about an image
        // nobody named. Refused rather than stored, because the dashboard would
        // then show an age against a blank — and somebody would act on it.
        if (req.BaseImageCreatedAt is not null && string.IsNullOrWhiteSpace(req.BaseImageReference))
            return Results.BadRequest("baseImageCreatedAt requires baseImageReference");

        var token = IngestAuthFilter.CurrentToken(ctx);

        var (version, scopeErr) = await ResolveVersionAsync(db, token, req, ct);
        if (scopeErr is not null) return scopeErr;

        // One row per build, updated in place. Two rows would leave two answers
        // to "how old is the base image" and the score would depend on which
        // one a query happened to pick.
        var image = await db.ContainerImages
            .FirstOrDefaultAsync(i => i.ComponentVersionId == version!.Id, ct);

        if (image is null)
        {
            image = new ContainerImage
            {
                ComponentVersionId = version!.Id,
                Reference = req.Reference,
            };
            db.ContainerImages.Add(image);
        }

        image.Reference = req.Reference;
        image.Digest = Blank(req.Digest);
        image.CreatedAt = req.CreatedAt;
        image.OsFamily = Blank(req.OsFamily);
        image.OsVersion = Blank(req.OsVersion);
        image.SizeBytes = req.SizeBytes;
        image.BaseImageReference = Blank(req.BaseImageReference);
        image.BaseImageDigest = Blank(req.BaseImageDigest);
        image.BaseImageCreatedAt = req.BaseImageCreatedAt;
        image.InspectedAt = DateTimeOffset.UtcNow;

        await db.SaveChangesAsync(ct);

        // The response SAYS what is missing rather than returning a bare 200.
        // A pipeline author who thinks they wired up base-image age and
        // actually did not should find that out from the call that was supposed
        // to do it, not from a gate reading Unknown three weeks later.
        var note = image.BaseImageReference is null
            ? "No base image supplied, so base-image age cannot be evaluated. The OCI annotation "
              + "that names a base image is usually absent — pass baseImageReference explicitly "
              + "from your build, and inspect that reference too for its publish date."
            : image.BaseImageCreatedAt is null
                ? "Base image named but no publish date supplied, so its age cannot be evaluated. "
                  + "Inspect the base reference itself to get one."
                : null;

        return Results.Ok(new ContainerImageIngestResponse(
            version!.Id, image.Id, image.BaseImageAgeInDays, note));
    }

    private static async Task<(ComponentVersion? version, IResult? error)> ResolveVersionAsync(
        FindingsDbContext db, Domain.Entities.IngestToken? token,
        ContainerImageIngestRequest req, CancellationToken ct)
    {
        var (_, project, scopeErr) =
            await IngestScopeGuard.ResolveAndGuardAsync(db, token, req.Client, req.Project, ct);
        if (scopeErr is not null) return (null, scopeErr);

        var componentLower = req.Component.ToLower();
        var component =
            await db.Components.FirstOrDefaultAsync(
                c => c.ProjectId == project!.Id && c.Name.ToLower() == componentLower, ct)
            ?? db.Components.Add(new Component
            {
                ProjectId = project!.Id, Name = req.Component, Kind = req.ComponentKind,
            }).Entity;

        ComponentFlavor? flavor = null;
        if (!string.IsNullOrWhiteSpace(req.Flavor))
        {
            var flavorLower = req.Flavor.ToLower();
            flavor = await db.ComponentFlavors.FirstOrDefaultAsync(
                         f => f.ComponentId == component.Id && f.Name.ToLower() == flavorLower, ct)
                     ?? db.ComponentFlavors.Add(new ComponentFlavor
                     {
                         ComponentId = component.Id, Name = req.Flavor,
                     }).Entity;
        }

        var version = await db.ComponentVersions.FirstOrDefaultAsync(v =>
            v.ComponentId == component.Id
            && v.FlavorId == (flavor != null ? flavor.Id : (Guid?)null)
            && v.VersionString == req.Version, ct);

        if (version is null)
        {
            version = db.ComponentVersions.Add(new ComponentVersion
            {
                ComponentId = component.Id,
                FlavorId = flavor?.Id,
                VersionString = req.Version,
                CommitSha = req.CommitSha,
                BranchName = req.Branch,
                BuildId = req.BuildId,
                PullRequestRef = req.PullRequestRef,
            }).Entity;
        }

        await db.SaveChangesAsync(ct);
        return (version, null);
    }

    private static string? Blank(string? value) =>
        string.IsNullOrWhiteSpace(value) ? null : value.Trim();
}
