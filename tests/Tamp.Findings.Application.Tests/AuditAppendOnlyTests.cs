using Microsoft.EntityFrameworkCore;
using Tamp.Findings.Data;
using Tamp.Findings.Domain.Entities;
using Tamp.Findings.Domain.Values;

namespace Tamp.Findings.Application.Tests;

// The audit trail is append-only, and that is enforced by the DbContext rather
// than by convention (TFND-73).
//
// "Everyone remembers not to modify audit rows" is exactly the kind of rule
// that holds until the one time it doesn't, and this is the evidence an
// assessor reads first.
//
// No database is needed: the guard runs BEFORE base.SaveChanges, so it throws
// without a connection ever being opened. That is itself worth knowing — the
// refusal is not a database constraint that could be bypassed by a different
// code path into the same tables.
public class AuditAppendOnlyTests
{
    private static FindingsDbContext Context() =>
        new(new DbContextOptionsBuilder<FindingsDbContext>()
            .UseNpgsql("Host=unused;Database=unused;Username=unused;Password=unused")
            .Options);

    private static AuditEntry Existing() => new()
    {
        Id = Guid.NewGuid(),
        ActorLogin = "scott",
        Action = "poam.risk_accepted",
        Class = AuditClass.Risk,
    };

    [Fact]
    public void Modifying_an_audit_entry_is_refused()
    {
        using var db = Context();
        var entry = Existing();
        db.Attach(entry);

        entry.Detail = "actually it was fine";

        var ex = Assert.Throws<InvalidOperationException>(() => db.SaveChanges());
        Assert.Contains("append-only", ex.Message, StringComparison.OrdinalIgnoreCase);
        Assert.Contains(entry.Action, ex.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void Deleting_an_audit_entry_is_refused()
    {
        using var db = Context();
        var entry = Existing();
        db.Attach(entry);

        db.Remove(entry);

        var ex = Assert.Throws<InvalidOperationException>(() => db.SaveChanges());
        Assert.Contains("append-only", ex.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task The_async_save_path_is_guarded_too()
    {
        // Two SaveChanges overloads means two places to forget. The async one
        // is what the endpoints actually call.
        using var db = Context();
        var entry = Existing();
        db.Attach(entry);
        entry.Detail = "changed";

        await Assert.ThrowsAsync<InvalidOperationException>(() => db.SaveChangesAsync());
    }

    [Fact]
    public void Rewriting_history_by_changing_the_actor_is_refused()
    {
        // The attack the rule exists for: not deleting a row, but quietly
        // reattributing one. An assessor comparing two exports would never see
        // it, so the write path has to make it impossible.
        using var db = Context();
        var entry = Existing();
        db.Attach(entry);

        entry.ActorLogin = "someone-else";

        Assert.Throws<InvalidOperationException>(() => db.SaveChanges());
    }
}
