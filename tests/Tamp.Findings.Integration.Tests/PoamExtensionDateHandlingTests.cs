using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Tamp.Findings.Application.Approvals;
using Tamp.Findings.Application.Authorization;
using Tamp.Findings.Domain.Entities;
using Tamp.Findings.Domain.Values;

namespace Tamp.Findings.Integration.Tests;

// TFND-233: a POA&M date reaches Postgres as timestamptz, which npgsql only accepts with a zero offset. The
// approved-extension effect parses the date the requester sent; whatever offset that string carries (or does
// not) it must land as a UTC instant and save, never throw or shift to the host's local zone.
[Collection(DatabaseCollection.Name)]
public class PoamExtensionDateHandlingTests
{
    private readonly DatabaseFixture _fx;
    public PoamExtensionDateHandlingTests(DatabaseFixture fx) => _fx = fx;

    private async Task<(Guid ItemId, PendingApproval Approval, Principal Decider)> ArrangeAsync(string payload, DateTimeOffset? closedAt = null)
    {
        using var scope = _fx.Scope();
        var db = _fx.Db(scope);
        var actors = await AppCovSeed.UsersAsync(db);
        var (client, project) = await AppCovSeed.ClientProjectAsync(db, "poamext");
        var item = new PoamItem
        {
            ProjectId = project.Id, Title = "ext-item", WeaknessDescription = "w",
            ScheduledCompletionDate = new DateTimeOffset(2026, 6, 1, 0, 0, 0, TimeSpan.Zero),
            ClosedAt = closedAt,
        };
        db.PoamItems.Add(item);
        await db.SaveChangesAsync();
        var approval = new PendingApproval
        {
            Kind = ApprovalKind.PoamExtension, SubjectKind = nameof(PoamItem), SubjectId = item.Id,
            ClientId = client.Id, ProjectId = project.Id, RequestedByUserId = actors.Lead.UserId,
            RequestedByLogin = "requester", Payload = payload,
        };
        return (item.Id, approval, actors.Admin);
    }

    private async Task<PoamItem> ApplyAsync(string payload, DateTimeOffset? closedAt = null)
    {
        var (itemId, approval, decider) = await ArrangeAsync(payload, closedAt);
        using (var scope = _fx.Scope())
        {
            var effect = scope.ServiceProvider.GetServices<IApprovalEffect>().Single(e => e.Kind == ApprovalKind.PoamExtension);
            await effect.ApplyAsync(approval, decider, default);
            // The effect only mutates the tracked entity; ApprovalService.DecideAsync saves it in the same
            // transaction as the decision. Save through the same scope's context, as that flow does.
            await scope.ServiceProvider.GetRequiredService<Tamp.Findings.Data.FindingsDbContext>().SaveChangesAsync();
        }
        using var scope2 = _fx.Scope();
        return await _fx.Db(scope2).PoamItems.AsNoTracking().SingleAsync(p => p.Id == itemId);
    }

    [SkippableTheory]
    [InlineData("2026-12-31T00:00:00.0000000+00:00", "2026-12-31T00:00:00Z")]   // what the page sends (round-trip "O", UTC)
    [InlineData("2026-12-31T00:00:00-05:00", "2026-12-31T05:00:00Z")]           // a non-UTC offset is converted, not stored as-is
    [InlineData("2026-12-31T00:00:00+09:30", "2026-12-30T14:30:00Z")]           // ...in either direction
    [InlineData("2026-12-31", "2026-12-31T00:00:00Z")]                          // no zone at all: assumed UTC, never the host's local zone
    public async Task The_new_date_is_stored_as_a_utc_instant_whatever_offset_the_payload_carries(string payload, string expectedUtc)
    {
        Skip.IfNot(_fx.Available);

        var item = await ApplyAsync(payload);

        Assert.Equal(DateTimeOffset.Parse(expectedUtc, System.Globalization.CultureInfo.InvariantCulture), item.ScheduledCompletionDate);
        Assert.Equal(TimeSpan.Zero, item.ScheduledCompletionDate!.Value.Offset);
    }

    [SkippableTheory]
    [InlineData("")]
    [InlineData("not a date")]
    [InlineData("31/31/2026")]
    public async Task A_missing_or_malformed_date_moves_nothing(string payload)
    {
        Skip.IfNot(_fx.Available);

        var item = await ApplyAsync(payload);

        Assert.Equal(new DateTimeOffset(2026, 6, 1, 0, 0, 0, TimeSpan.Zero), item.ScheduledCompletionDate);
    }

    [SkippableFact]
    public async Task A_closed_item_is_not_reopened_by_an_extension()
    {
        Skip.IfNot(_fx.Available);

        var item = await ApplyAsync("2026-12-31T00:00:00+00:00", closedAt: DateTimeOffset.UtcNow.AddDays(-1));

        Assert.Equal(new DateTimeOffset(2026, 6, 1, 0, 0, 0, TimeSpan.Zero), item.ScheduledCompletionDate);
    }
}
