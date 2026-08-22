using Tamp.Findings.Domain.Entities;
using Tamp.Findings.Domain.Values;

namespace Tamp.Findings.Domain.Tests;

// The audit trail is compliance evidence, not a debug log (TFND-73).
public class AuditEntryTests
{
    [Fact]
    public void Audit_classes_have_stable_persisted_values()
    {
        // Stored as an int. Renumbering would silently reclassify history —
        // a risk-acceptance would become an access event, or worse, Other.
        Assert.Equal(0, (int)AuditClass.Other);
        Assert.Equal(1, (int)AuditClass.Risk);
        Assert.Equal(2, (int)AuditClass.Access);
    }

    [Fact]
    public void An_entry_records_the_actor_login_rather_than_only_a_foreign_key()
    {
        // The record has to still read correctly after a user is renamed or
        // removed. An assessor reading a five-year-old trail cannot be handed
        // a dangling join.
        var entry = new AuditEntry
        {
            ActorLogin = "scott",
            Action = "poam.risk_accepted",
            Class = AuditClass.Risk,
        };

        Assert.Equal("scott", entry.ActorLogin);
        Assert.Null(entry.UserId);
    }

    [Fact]
    public void An_entry_defaults_to_now_and_to_the_other_class()
    {
        var before = DateTimeOffset.UtcNow.AddSeconds(-1);

        var entry = new AuditEntry { ActorLogin = "x", Action = "y" };

        Assert.True(entry.At >= before);
        // Defaulting to Risk or Access would inflate what an assessor reads
        // first; Other is the honest default for an unclassified action.
        Assert.Equal(AuditClass.Other, entry.Class);
    }

    [Fact]
    public void The_admin_flag_is_recorded_separately_from_the_project_role()
    {
        // Admin is not a ProjectRole, and "an admin did this" is a materially
        // different fact from "an architect did this". Collapsing them would
        // lose the distinction an assessor cares about most.
        var entry = new AuditEntry
        {
            ActorLogin = "root",
            Action = "role.granted",
            Class = AuditClass.Access,
            ActorWasAdmin = true,
            ActorRole = null,
        };

        Assert.True(entry.ActorWasAdmin);
        Assert.Null(entry.ActorRole);
    }
}
