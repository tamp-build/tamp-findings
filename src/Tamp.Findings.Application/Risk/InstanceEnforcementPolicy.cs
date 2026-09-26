using Tamp.Findings.Domain.Values;

namespace Tamp.Findings.Application.Risk;

// The deployment's enforcement lock, sourced from CONFIGURATION (env vars /
// appsettings), not the database (ADR 0004 §3.3).
//
// The locked floor is a platform-team lever, and the platform team controls the
// deployment config — not necessarily the in-app admin. So when enforcement is
// locked HERE, it overrides the stored InstanceSettings and the admin UI cannot
// change it: a compromised or well-meaning instance admin must not be able to
// downgrade the enforcement the platform mandated. Advisory/unlocked when
// unset, so a fresh install and the OSS default are unaffected.
public sealed class InstanceEnforcementPolicy
{
    public bool ConfigLocked { get; }

    // The mode the config lock pins the instance to. Meaningful only when
    // ConfigLocked; locking without naming a mode means "enforce".
    public EnforcementMode ConfigMode { get; }

    public InstanceEnforcementPolicy(bool configLocked, EnforcementMode configMode)
    {
        ConfigLocked = configLocked;
        ConfigMode = configMode;
    }

    /// <summary>
    /// The effective instance-level (mode, locked), given the stored settings.
    /// Config wins when locked; otherwise the database values stand.
    /// </summary>
    public (EnforcementMode Mode, bool Locked) Effective(EnforcementMode dbMode, bool dbLocked)
        => ConfigLocked ? (ConfigMode, true) : (dbMode, dbLocked);

    // For tests and hosts with no enforcement config.
    public static InstanceEnforcementPolicy Unlocked { get; } = new(false, EnforcementMode.Advisory);
}
