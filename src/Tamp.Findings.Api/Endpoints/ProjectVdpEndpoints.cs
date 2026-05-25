using System.Security.Claims;
using Microsoft.EntityFrameworkCore;
using Tamp.Findings.Api.Authentication;
using Tamp.Findings.Data;
using Tamp.Findings.Domain.Entities;

namespace Tamp.Findings.Api.Endpoints;

// TFND-32: per-project Vulnerability Disclosure Policy metadata.
// Federal procurement (CISA BOD 20-01 / SSDF RV.3.1) expects every
// project to publish a way for outside researchers to report
// vulnerabilities. Storing the three fields on Project flips the
// attestation's RV.3.1 line from Manual → Yes/Partial.
public sealed record ProjectVdpDto(
    Guid ProjectId,
    string? VdpPolicyUrl,
    string? VdpContactEmail,
    string? VdpReportingFormUrl);

public sealed record UpdateProjectVdpRequest(
    string? VdpPolicyUrl,
    string? VdpContactEmail,
    string? VdpReportingFormUrl);

public static class ProjectVdpEndpoints
{
    public static IEndpointRouteBuilder MapProjectVdp(this IEndpointRouteBuilder app)
    {
        var g = app.MapGroup("").WithTags("VDP");

        g.MapGet("/projects/{projectId:guid}/vdp", GetAsync)
         .WithSummary("Get this project's Vulnerability Disclosure Policy metadata. Drives SSDF RV.3.1 evidence in the attestation doc.");
        g.MapPut("/projects/{projectId:guid}/vdp", UpdateAsync)
         .WithSummary("Replace the project's VDP metadata. Admin only. Pass nulls to clear individual fields.");
        return app;
    }

    private static async Task<IResult> GetAsync(Guid projectId, FindingsDbContext db, CancellationToken ct)
    {
        var row = await db.Projects.AsNoTracking()
            .Where(p => p.Id == projectId)
            .Select(p => new { p.Id, p.VdpPolicyUrl, p.VdpContactEmail, p.VdpReportingFormUrl })
            .FirstOrDefaultAsync(ct);
        if (row is null) return Results.NotFound();
        return Results.Ok(new ProjectVdpDto(row.Id, row.VdpPolicyUrl, row.VdpContactEmail, row.VdpReportingFormUrl));
    }

    private static async Task<IResult> UpdateAsync(
        Guid projectId, UpdateProjectVdpRequest req, HttpContext ctx, FindingsDbContext db, CancellationToken ct)
    {
        var (_, deny) = await RequireAdminAsync(ctx, db, ct);
        if (deny is not null) return deny;
        var p = await db.Projects.FirstOrDefaultAsync(x => x.Id == projectId, ct);
        if (p is null) return Results.NotFound();
        p.VdpPolicyUrl = NullIfBlank(req.VdpPolicyUrl);
        p.VdpContactEmail = NullIfBlank(req.VdpContactEmail);
        p.VdpReportingFormUrl = NullIfBlank(req.VdpReportingFormUrl);
        await db.SaveChangesAsync(ct);
        return Results.Ok(new ProjectVdpDto(p.Id, p.VdpPolicyUrl, p.VdpContactEmail, p.VdpReportingFormUrl));
    }

    private static string? NullIfBlank(string? s) =>
        string.IsNullOrWhiteSpace(s) ? null : s.Trim();

    private static async Task<(User? user, IResult? deny)> RequireAdminAsync(HttpContext ctx, FindingsDbContext db, CancellationToken ct)
    {
        if (!Guid.TryParse(ctx.User.FindFirstValue(AuthExtensions.TampUserIdClaim), out var uid))
            return (null, Results.Unauthorized());
        var user = await db.Users.FirstOrDefaultAsync(u => u.Id == uid, ct);
        if (user is null || !user.IsApproved) return (null, Results.Unauthorized());
        if (!user.IsAdmin) return (user, Results.Forbid());
        return (user, null);
    }
}
