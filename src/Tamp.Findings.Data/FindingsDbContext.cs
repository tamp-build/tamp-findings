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
    public DbSet<SbomSnapshot> SbomSnapshots => Set<SbomSnapshot>();
    public DbSet<SbomComponent> SbomComponents => Set<SbomComponent>();
    public DbSet<SbomDependency> SbomDependencies => Set<SbomDependency>();
    public DbSet<Vulnerability> Vulnerabilities => Set<Vulnerability>();

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

        b.Entity<SbomSnapshot>(e =>
        {
            e.HasKey(x => x.Id);
            e.Property(x => x.SerialNumber).HasMaxLength(256);
            e.Property(x => x.SpecVersion).HasMaxLength(32);
            e.Property(x => x.ToolName).HasMaxLength(128);
            e.Property(x => x.ToolVersion).HasMaxLength(64);
            e.HasOne(x => x.ComponentVersion).WithMany().HasForeignKey(x => x.ComponentVersionId).OnDelete(DeleteBehavior.Cascade);
            // Most-recent-wins: one snapshot per component version. Re-ingest
            // replaces, so a unique index here matches the service contract.
            e.HasIndex(x => x.ComponentVersionId).IsUnique();
        });

        b.Entity<SbomComponent>(e =>
        {
            e.HasKey(x => x.Id);
            e.Property(x => x.Purl).HasMaxLength(1024).IsRequired();
            e.Property(x => x.Name).HasMaxLength(512).IsRequired();
            e.Property(x => x.Version).HasMaxLength(128).IsRequired();
            e.Property(x => x.Kind).HasMaxLength(32);
            e.Property(x => x.License).HasMaxLength(256);
            e.Property(x => x.LatestVersion).HasMaxLength(128);
            e.HasOne(x => x.SbomSnapshot).WithMany(s => s.Components).HasForeignKey(x => x.SbomSnapshotId).OnDelete(DeleteBehavior.Cascade);
            e.HasIndex(x => new { x.SbomSnapshotId, x.Purl }).IsUnique();
        });

        b.Entity<SbomDependency>(e =>
        {
            e.HasKey(x => x.Id);
            e.HasOne<SbomSnapshot>().WithMany(s => s.Dependencies).HasForeignKey(x => x.SbomSnapshotId).OnDelete(DeleteBehavior.Cascade);
            e.HasOne<SbomComponent>().WithMany().HasForeignKey(x => x.ParentComponentId).OnDelete(DeleteBehavior.NoAction);
            e.HasOne<SbomComponent>().WithMany().HasForeignKey(x => x.ChildComponentId).OnDelete(DeleteBehavior.NoAction);
            e.HasIndex(x => new { x.SbomSnapshotId, x.ParentComponentId, x.ChildComponentId }).IsUnique();
        });

        b.Entity<Vulnerability>(e =>
        {
            e.HasKey(x => x.Id);
            e.Property(x => x.AdvisoryId).HasMaxLength(64).IsRequired();
            e.Property(x => x.Title).HasMaxLength(512);
            e.Property(x => x.Description).HasColumnType("text");
            e.Property(x => x.FixedInVersion).HasMaxLength(128);
            e.Property(x => x.ReferenceUrl).HasMaxLength(1024);
            e.HasOne(x => x.SbomComponent).WithMany(c => c.Vulnerabilities).HasForeignKey(x => x.SbomComponentId).OnDelete(DeleteBehavior.Cascade);
            e.HasIndex(x => new { x.SbomComponentId, x.AdvisoryId }).IsUnique();
            e.HasIndex(x => x.Severity);
        });
    }
}
