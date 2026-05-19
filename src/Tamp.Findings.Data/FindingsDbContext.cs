using Microsoft.EntityFrameworkCore;
using Tamp.Findings.Domain.Entities;

namespace Tamp.Findings.Data;

public sealed class FindingsDbContext(DbContextOptions<FindingsDbContext> options) : DbContext(options)
{
    public DbSet<Client> Clients => Set<Client>();
    public DbSet<Project> Projects => Set<Project>();
    public DbSet<Component> Components => Set<Component>();
    public DbSet<ComponentFlavor> ComponentFlavors => Set<ComponentFlavor>();
    public DbSet<ComponentVersion> ComponentVersions => Set<ComponentVersion>();
    public DbSet<Finding> Findings => Set<Finding>();
    public DbSet<Suppression> Suppressions => Set<Suppression>();
    public DbSet<User> Users => Set<User>();
    public DbSet<ProjectRoleAssignment> ProjectRoleAssignments => Set<ProjectRoleAssignment>();

    protected override void OnModelCreating(ModelBuilder b)
    {
        base.OnModelCreating(b);

        b.Entity<Client>(e =>
        {
            e.HasKey(x => x.Id);
            e.Property(x => x.Name).HasMaxLength(256).IsRequired();
            e.HasIndex(x => x.Name).IsUnique();
        });

        b.Entity<Project>(e =>
        {
            e.HasKey(x => x.Id);
            e.Property(x => x.Name).HasMaxLength(256).IsRequired();
            e.HasOne(x => x.Client).WithMany(c => c.Projects).HasForeignKey(x => x.ClientId).OnDelete(DeleteBehavior.Cascade);
            e.HasIndex(x => new { x.ClientId, x.Name }).IsUnique();
        });

        b.Entity<Component>(e =>
        {
            e.HasKey(x => x.Id);
            e.Property(x => x.Name).HasMaxLength(256).IsRequired();
            e.Property(x => x.Kind).HasMaxLength(64);
            e.HasOne(x => x.Project).WithMany(p => p.Components).HasForeignKey(x => x.ProjectId).OnDelete(DeleteBehavior.Cascade);
            e.HasIndex(x => new { x.ProjectId, x.Name }).IsUnique();
        });

        b.Entity<ComponentFlavor>(e =>
        {
            e.HasKey(x => x.Id);
            e.Property(x => x.Name).HasMaxLength(64).IsRequired();
            e.HasOne(x => x.Component).WithMany(c => c.Flavors).HasForeignKey(x => x.ComponentId).OnDelete(DeleteBehavior.Cascade);
            e.HasIndex(x => new { x.ComponentId, x.Name }).IsUnique();
        });

        b.Entity<ComponentVersion>(e =>
        {
            e.HasKey(x => x.Id);
            e.Property(x => x.VersionString).HasMaxLength(128).IsRequired();
            e.Property(x => x.CommitSha).HasMaxLength(64);
            e.Property(x => x.BranchName).HasMaxLength(256);
            e.Property(x => x.BuildId).HasMaxLength(128);
            e.Property(x => x.PullRequestRef).HasMaxLength(128);
            e.HasOne(x => x.Component).WithMany(c => c.Versions).HasForeignKey(x => x.ComponentId).OnDelete(DeleteBehavior.Cascade);
            e.HasOne(x => x.Flavor).WithMany().HasForeignKey(x => x.FlavorId).OnDelete(DeleteBehavior.SetNull);
            e.HasIndex(x => new { x.ComponentId, x.FlavorId, x.VersionString }).IsUnique();
            e.HasIndex(x => x.CommitSha);
        });

        b.Entity<Finding>(e =>
        {
            e.HasKey(x => x.Id);
            e.Property(x => x.Hash).HasMaxLength(128).IsRequired();
            e.Property(x => x.RuleId).HasMaxLength(256).IsRequired();
            e.Property(x => x.Title).HasMaxLength(512).IsRequired();
            e.Property(x => x.FilePath).HasMaxLength(1024);
            e.Property(x => x.Snippet).HasColumnType("text");
            e.Property(x => x.Description).HasColumnType("text");
            e.HasOne(x => x.ComponentVersion).WithMany(v => v.Findings).HasForeignKey(x => x.ComponentVersionId).OnDelete(DeleteBehavior.Cascade);
            // Dedup invariant: a finding is unique per (component version + hash).
            e.HasIndex(x => new { x.ComponentVersionId, x.Hash }).IsUnique();
            e.HasIndex(x => x.Status);
            e.HasIndex(x => x.Severity);
            e.HasIndex(x => x.Scanner);
        });

        b.Entity<Suppression>(e =>
        {
            e.HasKey(x => x.Id);
            e.Property(x => x.Reason).HasMaxLength(2048).IsRequired();
            e.Property(x => x.RuleId).HasMaxLength(256);
            e.Property(x => x.FilePath).HasMaxLength(1024);
            e.HasIndex(x => x.FindingId);
            e.HasIndex(x => x.RuleId);
            e.HasIndex(x => x.ComponentId);
            e.HasIndex(x => x.ExpiresAt);
        });

        b.Entity<User>(e =>
        {
            e.HasKey(x => x.Id);
            e.Property(x => x.Login).HasMaxLength(256).IsRequired();
            e.Property(x => x.DisplayName).HasMaxLength(256).IsRequired();
            e.HasIndex(x => x.Login).IsUnique();
        });

        b.Entity<ProjectRoleAssignment>(e =>
        {
            e.HasKey(x => x.Id);
            e.HasIndex(x => new { x.UserId, x.Role, x.ClientId, x.ProjectId, x.ComponentId }).IsUnique();
        });
    }
}
