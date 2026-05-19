namespace Tamp.Findings.Domain.Values;

public enum SuppressionScope
{
    SingleFinding = 1,
    RuleOnFile = 2,
    RuleOnComponent = 3,
    RuleEverywhere = 4,
}
