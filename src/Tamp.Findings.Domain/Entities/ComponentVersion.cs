namespace Tamp.Findings.Domain.Entities;

public sealed class ComponentVersion
{
    public Guid Id { get; set; } = Guid.NewGuid();
    public Guid ComponentId { get; set; }
    public Guid? FlavorId { get; set; }

    public required string VersionString { get; set; }
    public string? CommitSha { get; set; }
    public string? BranchName { get; set; }
    public string? BuildId { get; set; }
    public string? PullRequestRef { get; set; }

    public DateTimeOffset CreatedAt { get; set; } = DateTimeOffset.UtcNow;

    public Component? Component { get; set; }
    public ComponentFlavor? Flavor { get; set; }
    public ICollection<Finding> Findings { get; set; } = [];
}
