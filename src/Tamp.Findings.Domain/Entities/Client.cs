namespace Tamp.Findings.Domain.Entities;

public sealed class Client
{
    public Guid Id { get; set; } = Guid.NewGuid();
    public required string Name { get; set; }
    public string? Description { get; set; }
    public DateTimeOffset CreatedAt { get; set; } = DateTimeOffset.UtcNow;

    public ICollection<Project> Projects { get; set; } = [];
}
