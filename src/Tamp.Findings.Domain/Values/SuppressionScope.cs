namespace Tamp.Findings.Domain.Values;

public enum SuppressionScope
{
    SingleFinding = 1,
    RuleOnFile = 2,
    // 3 (RuleOnComponent) retired with the Component tier (component-collapse).
    RuleEverywhere = 4,
}
