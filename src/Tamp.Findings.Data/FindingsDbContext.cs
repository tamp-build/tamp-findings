using Microsoft.EntityFrameworkCore;
using Microsoft.AspNetCore.DataProtection.EntityFrameworkCore;
using Tamp.Findings.Domain.Entities;

namespace Tamp.Findings.Data;

public sealed class FindingsDbContext(DbContextOptions<FindingsDbContext> options)
    : DbContext(options), IDataProtectionKeyContext
{
    public DbSet<Client> Clients => Set<Client>();
    public DbSet<Project> Projects => Set<Project>();
    public DbSet<ComponentVersion> ComponentVersions => Set<ComponentVersion>();
    public DbSet<Finding> Findings => Set<Finding>();
    public DbSet<PaidComponent> PaidComponents => Set<PaidComponent>();
    public DbSet<ContainerImage> ContainerImages => Set<ContainerImage>();
    public DbSet<Suppression> Suppressions => Set<Suppression>();
    public DbSet<User> Users => Set<User>();
    public DbSet<ProjectRoleAssignment> ProjectRoleAssignments => Set<ProjectRoleAssignment>();

    // Append-only. Nothing in the app may update or delete these — see
    // SaveChanges below, which refuses at the context level rather than
    // trusting every call site to behave.
    public DbSet<AuditEntry> AuditEntries => Set<AuditEntry>();

    public DbSet<InstanceSettings> InstanceSettings => Set<InstanceSettings>();

    public DbSet<HostAlias> HostAliases => Set<HostAlias>();
    public DbSet<SbomSnapshot> SbomSnapshots => Set<SbomSnapshot>();
    public DbSet<SbomComponent> SbomComponents => Set<SbomComponent>();
    public DbSet<SbomDependency> SbomDependencies => Set<SbomDependency>();
    public DbSet<Vulnerability> Vulnerabilities => Set<Vulnerability>();
    public DbSet<CoverageReport> CoverageReports => Set<CoverageReport>();
    public DbSet<CoverageModule> CoverageModules => Set<CoverageModule>();
    public DbSet<CoverageSourceFile> CoverageSourceFiles => Set<CoverageSourceFile>();
    public DbSet<CoverageClass> CoverageClasses => Set<CoverageClass>();
    public DbSet<ScanRunReceipt> ScanRunReceipts => Set<ScanRunReceipt>();
    public DbSet<TestRunReport> TestRunReports => Set<TestRunReport>();
    public DbSet<TestSuiteResult> TestSuiteResults => Set<TestSuiteResult>();
    public DbSet<TestCaseResult> TestCaseResults => Set<TestCaseResult>();
    public DbSet<RawReportArtifact> RawReportArtifacts => Set<RawReportArtifact>();
    public DbSet<ModelPrice> ModelPrices => Set<ModelPrice>();
    public DbSet<LicenseResolution> LicenseResolutions => Set<LicenseResolution>();
    public DbSet<ScanUsageObservation> ScanUsageObservations => Set<ScanUsageObservation>();
    public DbSet<IngestToken> IngestTokens => Set<IngestToken>();
    public DbSet<RiskPolicy> RiskPolicies => Set<RiskPolicy>();
    public DbSet<PolicyTemplate> PolicyTemplates => Set<PolicyTemplate>();
    public DbSet<ControlCatalog> ControlCatalogs => Set<ControlCatalog>();
    public DbSet<Framework> Frameworks => Set<Framework>();
    public DbSet<ConformanceFinding> ConformanceFindings => Set<ConformanceFinding>();
    public DbSet<DecisionDiagnostic> DecisionDiagnostics => Set<DecisionDiagnostic>();
    public DbSet<ScoreSnapshot> ScoreSnapshots => Set<ScoreSnapshot>();
    public DbSet<KevAdvisory> KevAdvisories => Set<KevAdvisory>();
    public DbSet<VexStatement> VexStatements => Set<VexStatement>();
    public DbSet<PoamItem> PoamItems => Set<PoamItem>();
    public DbSet<AttestationSnapshot> AttestationSnapshots => Set<AttestationSnapshot>();
    public DbSet<PendingApproval> PendingApprovals => Set<PendingApproval>();
    public DbSet<IdentityProvider> IdentityProviders => Set<IdentityProvider>();
    public DbSet<McpToken> McpTokens => Set<McpToken>();

    // tamp-EOProvenance (ADR 0011): the EO/memo mandate registry. DirectiveStatusChange
    // is append-only (enforced in GuardAuditTrail) — it is the point-in-time evidence.
    public DbSet<Instrument> Instruments => Set<Instrument>();
    public DbSet<InstrumentRelation> InstrumentRelations => Set<InstrumentRelation>();
    public DbSet<Directive> Directives => Set<Directive>();
    public DbSet<DirectiveStatusChange> DirectiveStatusChanges => Set<DirectiveStatusChange>();
    public DbSet<DirectiveCrosswalk> DirectiveCrosswalks => Set<DirectiveCrosswalk>();

    // tamp-ztt (TFND-188 / ADR 0010): the ZT maturity + operational-mandate model.
    public DbSet<MaturityModelCatalog> MaturityModelCatalogs => Set<MaturityModelCatalog>();
    public DbSet<ZtSystem> ZtSystems => Set<ZtSystem>();
    public DbSet<EnterpriseOffering> EnterpriseOfferings => Set<EnterpriseOffering>();
    public DbSet<ZtInheritanceEdge> ZtInheritanceEdges => Set<ZtInheritanceEdge>();
    public DbSet<ZtSystemPick> ZtSystemPicks => Set<ZtSystemPick>();
    public DbSet<MandatePack> MandatePacks => Set<MandatePack>();

    // Authoritative conformance-rules store (TFND-190 / ADR 0012).
    public DbSet<ConformanceRule> ConformanceRules => Set<ConformanceRule>();

    /// <summary>
    /// ASP.NET Data Protection key ring (TFND-111).
    ///
    /// In the database rather than on disk because the default store is the
    /// filesystem or the registry — and in a container that means a restart
    /// orphans every encrypted identity-provider secret on the instance. The
    /// operator would only discover it at the moment sign-in stopped working.
    /// </summary>
    public DbSet<DataProtectionKey> DataProtectionKeys => Set<DataProtectionKey>();

    protected override void OnModelCreating(ModelBuilder b)
    {
        base.OnModelCreating(b);

        b.Entity<Client>(e =>
        {
            e.HasKey(x => x.Id);
            e.Property(x => x.Name).HasMaxLength(256).IsRequired();
            e.HasIndex(x => x.Name).IsUnique();
            // SetNull on the FK so deleting a RiskPolicy doesn't cascade
            // delete clients — they just fall back to the system default.
            e.HasOne<RiskPolicy>().WithMany().HasForeignKey(x => x.RiskPolicyId).OnDelete(DeleteBehavior.SetNull);
            // Three-layer policy (ADR 0007): the inherited template + this
            // client's own hardening overlay (jsonb). SetNull so deleting a
            // template drops the link rather than the client.
            e.HasOne<PolicyTemplate>().WithMany().HasForeignKey(x => x.PolicyTemplateId).OnDelete(DeleteBehavior.SetNull);
            e.Property(x => x.PolicyLayer).HasColumnType("jsonb");
            // TFND-177: the compliance framework this client's projects follow.
            e.HasOne<Framework>().WithMany().HasForeignKey(x => x.FrameworkId).OnDelete(DeleteBehavior.SetNull);
        });

        b.Entity<Project>(e =>
        {
            e.HasKey(x => x.Id);
            e.Property(x => x.Name).HasMaxLength(256).IsRequired();
            e.Property(x => x.GitHubRepository).HasMaxLength(256);
            e.HasOne(x => x.Client).WithMany(c => c.Projects).HasForeignKey(x => x.ClientId).OnDelete(DeleteBehavior.Cascade);
            e.HasIndex(x => new { x.ClientId, x.Name }).IsUnique();
            e.Property(x => x.BadgeKey).HasMaxLength(64);
            e.HasIndex(x => x.BadgeKey).IsUnique();
            e.HasOne<RiskPolicy>().WithMany().HasForeignKey(x => x.RiskPolicyId).OnDelete(DeleteBehavior.SetNull);
            // Project acceptance gates — jsonb. Null = no gates wired
            // (every build passes). Distinct from RiskPolicy which is
            // also jsonb but lives in its own table.
            e.Property(x => x.GatesConfig).HasColumnType("jsonb");
            // Three-layer policy (ADR 0007): this project's hardening overlay.
            e.Property(x => x.PolicyLayer).HasColumnType("jsonb");
            // TFND-32: VDP metadata.
            e.Property(x => x.VdpPolicyUrl).HasMaxLength(1024);
            e.Property(x => x.VdpContactEmail).HasMaxLength(320);
            e.Property(x => x.VdpReportingFormUrl).HasMaxLength(1024);
        });

        b.Entity<ComponentVersion>(e =>
        {
            e.HasKey(x => x.Id);
            e.Property(x => x.VersionString).HasMaxLength(128).IsRequired();
            e.Property(x => x.Flavor).HasMaxLength(64);
            e.Property(x => x.CommitSha).HasMaxLength(64);
            e.Property(x => x.BranchName).HasMaxLength(256);
            e.Property(x => x.BuildId).HasMaxLength(128);
            e.Property(x => x.PullRequestRef).HasMaxLength(128);
            // The build anchors to its Project (component-collapse); (project, flavor, version)
            // is the unique build key now that the Component tier is gone.
            e.HasOne(x => x.Project).WithMany(p => p.Versions).HasForeignKey(x => x.ProjectId).OnDelete(DeleteBehavior.Cascade);
            e.HasIndex(x => new { x.ProjectId, x.Flavor, x.VersionString }).IsUnique();
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
            // TFND-17: short tag (secret / misconfiguration / vulnerability).
            e.Property(x => x.SubCategory).HasMaxLength(64);
            e.Property(x => x.Purl).HasMaxLength(512);
            e.HasOne(x => x.ComponentVersion).WithMany(v => v.Findings).HasForeignKey(x => x.ComponentVersionId).OnDelete(DeleteBehavior.Cascade);
            // Dedup invariant: a finding is unique per (component version + hash).
            e.HasIndex(x => new { x.ComponentVersionId, x.Hash }).IsUnique();
            e.HasIndex(x => x.Status);
            e.HasIndex(x => x.Severity);
            e.HasIndex(x => x.Scanner);
        });

        // TFND-134: the image a build produced, and the base image behind it.
        b.Entity<ContainerImage>(e =>
        {
            e.HasKey(x => x.Id);
            e.Property(x => x.Reference).HasMaxLength(512).IsRequired();
            e.Property(x => x.Digest).HasMaxLength(256);
            e.Property(x => x.OsFamily).HasMaxLength(64);
            e.Property(x => x.OsVersion).HasMaxLength(64);
            e.Property(x => x.BaseImageReference).HasMaxLength(512);
            e.Property(x => x.BaseImageDigest).HasMaxLength(256);
            e.Ignore(x => x.BaseImageAgeInDays);

            // One image per build. Re-inspecting the same build updates rather
            // than accumulating — otherwise a rebuild would leave two answers
            // to "how old is the base image" and the score would depend on
            // which one a query happened to pick.
            e.HasIndex(x => x.ComponentVersionId).IsUnique();

            e.HasOne(x => x.ComponentVersion)
             .WithMany()
             .HasForeignKey(x => x.ComponentVersionId)
             .OnDelete(DeleteBehavior.Cascade);
        });

        // TFND-8 (F7.2): the paid-component registry. Instance-scoped — "Telerik
        // is a paid product" is a fact about the world, not about a tenant.
        b.Entity<PaidComponent>(e =>
        {
            e.HasKey(x => x.Id);
            e.Property(x => x.Vendor).HasMaxLength(200).IsRequired();
            e.Property(x => x.Product).HasMaxLength(200).IsRequired();
            e.Property(x => x.PackagePrefix).HasMaxLength(200).IsRequired();
            e.Property(x => x.Ecosystem).HasMaxLength(64);
            e.Property(x => x.Currency).HasMaxLength(8).IsRequired();
            e.Property(x => x.LicenseModel).HasMaxLength(200);
            e.Property(x => x.PricingUrl).HasMaxLength(1024);
            e.Property(x => x.Notes).HasMaxLength(2048);
            // Two rows matching the same packages would double-count a vendor
            // on the costs screen, which is the one number people act on.
            e.HasIndex(x => new { x.Ecosystem, x.PackagePrefix }).IsUnique();
        });

        b.Entity<Suppression>(e =>
        {
            e.HasKey(x => x.Id);
            e.Property(x => x.Reason).HasMaxLength(2048).IsRequired();
            e.Property(x => x.RuleId).HasMaxLength(256);
            e.Property(x => x.FilePath).HasMaxLength(1024);
            e.HasIndex(x => x.FindingId);
            e.HasIndex(x => x.RuleId);
            e.HasIndex(x => x.ExpiresAt);
            // TFND-132: the matcher filters on tenant before anything else, so
            // this is the index the hot path actually uses.
            e.HasIndex(x => new { x.ClientId, x.ProjectId });
        });

        b.Entity<User>(e =>
        {
            e.HasKey(x => x.Id);
            e.Property(x => x.Login).HasMaxLength(256).IsRequired();
            e.Property(x => x.DisplayName).HasMaxLength(256).IsRequired();
            e.Property(x => x.Email).HasMaxLength(320);
            e.Property(x => x.AvatarUrl).HasMaxLength(1024);
            e.HasIndex(x => x.Login).IsUnique();
            // GitHub's numeric id is the durable identity (login can be
            // renamed); sparse-unique so pre-OIDC rows with NULL don't collide.
            e.HasIndex(x => x.GitHubUserId).IsUnique().HasFilter("\"GitHubUserId\" IS NOT NULL");

            // TFND-111: identity from a registry-configured provider. The PAIR
            // is unique, not the subject alone — a subject is only unique
            // within an issuer, and two OIDC providers can both hand out "1"
            // and mean different people. Sparse, so GitHub rows with NULLs do
            // not all collide with each other.
            e.Property(x => x.ExternalScheme).HasMaxLength(64);
            e.Property(x => x.ExternalSubject).HasMaxLength(256);
            e.HasIndex(x => new { x.ExternalScheme, x.ExternalSubject })
                .IsUnique()
                .HasFilter("\"ExternalSubject\" IS NOT NULL");
        });

        b.Entity<HostAlias>(e =>
        {
            e.Property(x => x.Alias).HasMaxLength(320).IsRequired();
            e.Property(x => x.CanonicalHost).HasMaxLength(320).IsRequired();
            // One alias can only point one way, or a lookup becomes
            // ambiguous and the tree would group non-deterministically.
            e.HasIndex(x => new { x.ProjectId, x.Alias }).IsUnique();
        });

        b.Entity<InstanceSettings>(e =>
        {
            e.HasKey(x => x.Id);
            e.Property(x => x.InstanceUrl).HasMaxLength(512);
            e.Property(x => x.SmtpHost).HasMaxLength(256);
            e.Property(x => x.SmtpFrom).HasMaxLength(256);
            e.Property(x => x.GitHubAppId).HasMaxLength(32);
            e.Property(x => x.GitHubAppPrivateKeyProtected).HasColumnType("text");
            e.Property(x => x.GitHubCheckName).HasMaxLength(128);
            // Native text[]: the list is short, read whole, and never queried
            // by element, so a join table would be three tables of ceremony
            // for no gain.
            e.Property(x => x.ExpectedScanners).HasColumnType("text[]");
            e.Property(x => x.AllowedEmailDomains).HasColumnType("text[]");
            e.Property(x => x.MfaRequiredRoles).HasColumnType("text[]");
        });

        b.Entity<AuditEntry>(e =>
        {
            e.Property(x => x.ActorLogin).HasMaxLength(200).IsRequired();
            e.Property(x => x.Action).HasMaxLength(120).IsRequired();
            e.Property(x => x.SubjectKind).HasMaxLength(60);

            // The three reads an assessor actually performs: recent activity,
            // everything in one scope, and everything of one class.
            e.HasIndex(x => x.At);
            e.HasIndex(x => new { x.ClientId, x.ProjectId, x.At });
            e.HasIndex(x => new { x.Class, x.At });
        });

        b.Entity<ProjectRoleAssignment>(e =>
        {
            e.HasKey(x => x.Id);
            e.HasIndex(x => new { x.UserId, x.Role, x.ClientId, x.ProjectId }).IsUnique();
        });

        b.Entity<SbomSnapshot>(e =>
        {
            e.HasKey(x => x.Id);
            e.Property(x => x.SerialNumber).HasMaxLength(256);
            e.Property(x => x.SpecVersion).HasMaxLength(32);
            e.Property(x => x.ToolName).HasMaxLength(128);
            e.Property(x => x.ToolVersion).HasMaxLength(64);
            // TFND-21: jsonb so we can keep the full metadata.tools record
            // (multiple tools, both 1.4 array shape and 1.5 nested shape).
            e.Property(x => x.MetadataTools).HasColumnType("jsonb");
            // TFND-29: SLSA / in-toto provenance attestation.
            e.Property(x => x.ProvenanceJson).HasColumnType("jsonb");
            e.Property(x => x.ProvenanceType).HasMaxLength(256);
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
            // TFND-21: hashes stored as algorithm→value map (jsonb).
            e.Property(x => x.Hashes).HasColumnType("jsonb");
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
            e.Property(x => x.CvssVector).HasMaxLength(256);
            e.HasOne(x => x.SbomComponent).WithMany(c => c.Vulnerabilities).HasForeignKey(x => x.SbomComponentId).OnDelete(DeleteBehavior.Cascade);
            e.HasIndex(x => new { x.SbomComponentId, x.AdvisoryId }).IsUnique();
            e.HasIndex(x => x.Severity);
        });

        b.Entity<McpToken>(e =>
        {
            e.HasKey(x => x.Id);
            e.Property(x => x.Name).HasMaxLength(200).IsRequired();
            e.Property(x => x.TokenHash).HasMaxLength(64).IsRequired();
            // The hash IS the lookup key on every agent request, so it is
            // unique and indexed rather than scanned.
            e.HasIndex(x => x.TokenHash).IsUnique();
            e.HasIndex(x => new { x.ClientId, x.ProjectId });
        });

        b.Entity<IdentityProvider>(e =>
        {
            e.HasKey(x => x.Id);
            e.Property(x => x.Scheme).HasMaxLength(64).IsRequired();
            e.Property(x => x.DisplayName).HasMaxLength(128).IsRequired();
            e.Property(x => x.ClientId).HasMaxLength(512).IsRequired();
            e.Property(x => x.ProtectedClientSecret).HasColumnType("text");
            e.Property(x => x.Authority).HasMaxLength(512);
            e.Property(x => x.Scopes).HasMaxLength(512);
            // The scheme IS the identity. Two providers sharing one would make
            // /auth/login/{scheme} ambiguous and the second registration would
            // silently win.
            e.HasIndex(x => x.Scheme).IsUnique();
        });

        b.Entity<PendingApproval>(e =>
        {
            e.HasKey(x => x.Id);
            e.Property(x => x.SubjectKind).HasMaxLength(60).IsRequired();
            e.Property(x => x.RequestedByLogin).HasMaxLength(200).IsRequired();
            e.Property(x => x.DecidedByLogin).HasMaxLength(200);
            // The two reads the screens perform: "is this thing pending?" and
            // "what is waiting on me?".
            e.HasIndex(x => new { x.SubjectKind, x.SubjectId, x.State });
            e.HasIndex(x => new { x.State, x.AssignedToUserId });
        });

        b.Entity<AttestationSnapshot>(e =>
        {
            e.HasKey(x => x.Id);
            e.Property(x => x.CommitSha).HasMaxLength(64).IsRequired();
            e.Property(x => x.DocumentJson).HasColumnType("jsonb").IsRequired();
            e.Property(x => x.RiskPolicyName).HasMaxLength(128).IsRequired();
            e.Property(x => x.Band).HasMaxLength(32).IsRequired();
            e.Property(x => x.SignedBy).HasMaxLength(256);
            // Newest first per project is the only access pattern: the screen
            // asks "is there a snapshot for this build", and the list asks
            // "what has been generated here".
            e.HasIndex(x => new { x.ProjectId, x.CommitSha, x.GeneratedAt });
        });

        b.Entity<CoverageReport>(e =>
        {
            e.HasKey(x => x.Id);
            e.Property(x => x.ToolName).HasMaxLength(128).IsRequired();
            e.Property(x => x.ToolVersion).HasMaxLength(64);
            e.HasOne(x => x.ComponentVersion).WithMany().HasForeignKey(x => x.ComponentVersionId).OnDelete(DeleteBehavior.Cascade);
            // Replace-on-ingest: one report per CV.
            e.HasIndex(x => x.ComponentVersionId).IsUnique();
        });

        b.Entity<CoverageModule>(e =>
        {
            e.HasKey(x => x.Id);
            e.Property(x => x.Name).HasMaxLength(512).IsRequired();
            e.HasOne(x => x.Report).WithMany(r => r.Modules).HasForeignKey(x => x.CoverageReportId).OnDelete(DeleteBehavior.Cascade);
            e.HasIndex(x => new { x.CoverageReportId, x.Name }).IsUnique();
        });

        b.Entity<CoverageSourceFile>(e =>
        {
            e.HasKey(x => x.Id);
            e.Property(x => x.RelativePath).HasMaxLength(1024).IsRequired();
            e.Property(x => x.AbsolutePath).HasMaxLength(1024);
            // text column for source — these are typically a few KB but
            // occasionally hit 100k+ on long file types like generated code.
            e.Property(x => x.SourceText).HasColumnType("text").IsRequired();
            e.HasOne(x => x.Report).WithMany(r => r.SourceFiles).HasForeignKey(x => x.CoverageReportId).OnDelete(DeleteBehavior.Cascade);
            e.HasIndex(x => new { x.CoverageReportId, x.RelativePath }).IsUnique();
        });

        b.Entity<TestRunReport>(e =>
        {
            e.HasKey(x => x.Id);
            e.Property(x => x.ToolName).HasMaxLength(128).IsRequired();
            e.Property(x => x.ToolVersion).HasMaxLength(64);
            e.HasOne(x => x.ComponentVersion).WithMany().HasForeignKey(x => x.ComponentVersionId).OnDelete(DeleteBehavior.Cascade);
            // Replace-on-ingest: one report per CV.
            e.HasIndex(x => x.ComponentVersionId).IsUnique();
        });

        b.Entity<TestSuiteResult>(e =>
        {
            e.HasKey(x => x.Id);
            e.Property(x => x.AssemblyName).HasMaxLength(512).IsRequired();
            e.Property(x => x.ClassName).HasMaxLength(1024).IsRequired();
            e.HasOne(x => x.Report).WithMany(r => r.Suites).HasForeignKey(x => x.TestRunReportId).OnDelete(DeleteBehavior.Cascade);
            // A suite's identity is (assembly, class) — the same class name legitimately exists in
            // two assemblies. The old (report, class) key 500'd on that; ingest also merges dupes.
            e.HasIndex(x => new { x.TestRunReportId, x.AssemblyName, x.ClassName }).IsUnique();
        });

        b.Entity<TestCaseResult>(e =>
        {
            e.HasKey(x => x.Id);
            e.Property(x => x.Name).HasMaxLength(1024).IsRequired();
            e.Property(x => x.ErrorMessage).HasColumnType("text");
            e.Property(x => x.ErrorStackTrace).HasColumnType("text");
            e.HasOne(x => x.Suite).WithMany(s => s.Cases).HasForeignKey(x => x.TestSuiteResultId).OnDelete(DeleteBehavior.Cascade);
            e.HasIndex(x => new { x.TestSuiteResultId, x.Name });
        });

        b.Entity<ModelPrice>(e =>
        {
            e.HasKey(x => x.Id);
            e.Property(x => x.ModelId).HasMaxLength(128).IsRequired();
            e.Property(x => x.Provider).HasMaxLength(64);
            e.Property(x => x.Currency).HasMaxLength(8).IsRequired();
            e.Property(x => x.InputPerMillion).HasColumnType("numeric(12,4)");
            e.Property(x => x.OutputPerMillion).HasColumnType("numeric(12,4)");
            // One price per (model, effective date) — a dated table, newest-effective-wins at read time.
            e.HasIndex(x => new { x.ModelId, x.EffectiveFrom }).IsUnique();
        });

        b.Entity<LicenseResolution>(e =>
        {
            e.HasKey(x => x.Id);
            e.Property(x => x.Purl).HasMaxLength(1024).IsRequired();
            e.Property(x => x.Spdx).HasMaxLength(256).IsRequired();
            e.Property(x => x.Note).HasMaxLength(2048);
            e.Property(x => x.ResolvedBy).HasMaxLength(256);
            // Global fact keyed by purl: one resolution per package version, upserted.
            e.HasIndex(x => x.Purl).IsUnique();
        });

        b.Entity<ScanUsageObservation>(e =>
        {
            e.HasKey(x => x.Id);
            e.Property(x => x.Adapter).HasMaxLength(64).IsRequired();
            e.Property(x => x.Capability).HasMaxLength(128);
            e.Property(x => x.ModelId).HasMaxLength(128).IsRequired();
            e.Property(x => x.Provider).HasMaxLength(64);
            e.HasOne(x => x.ComponentVersion).WithMany().HasForeignKey(x => x.ComponentVersionId).OnDelete(DeleteBehavior.Cascade);
            e.HasIndex(x => new { x.ComponentVersionId, x.ObservedAt });
        });

        b.Entity<RawReportArtifact>(e =>
        {
            e.HasKey(x => x.Id);
            e.Property(x => x.Format).HasMaxLength(32).IsRequired();
            e.Property(x => x.FileName).HasMaxLength(512);
            e.Property(x => x.SlotKey).HasMaxLength(512).IsRequired();
            e.Property(x => x.Sha256).HasMaxLength(64).IsRequired();
            e.Property(x => x.ToolName).HasMaxLength(128);
            e.Property(x => x.CompressedBytes).HasColumnType("bytea").IsRequired();
            e.HasOne(x => x.ComponentVersion).WithMany().HasForeignKey(x => x.ComponentVersionId).OnDelete(DeleteBehavior.Cascade);
            // Replace-by-file with dedup: one row per (build, kind, slot); re-posting the same slot
            // supersedes it, different files coexist. SlotKey is the filename, or "sha256:<hash>".
            e.HasIndex(x => new { x.ComponentVersionId, x.Kind, x.SlotKey }).IsUnique();
        });

        b.Entity<ScanRunReceipt>(e =>
        {
            e.HasKey(x => x.Id);
            e.Property(x => x.ToolName).HasMaxLength(128);
            e.Property(x => x.ToolVersion).HasMaxLength(64);
            e.Property(x => x.Notes).HasMaxLength(2048);
            e.HasOne(x => x.ComponentVersion).WithMany().HasForeignKey(x => x.ComponentVersionId).OnDelete(DeleteBehavior.Cascade);
            // Replace-on-ingest: one receipt per (CV, Scanner).
            e.HasIndex(x => new { x.ComponentVersionId, x.Scanner }).IsUnique();
        });

        b.Entity<IngestToken>(e =>
        {
            e.HasKey(x => x.Id);
            e.Property(x => x.TokenHash).HasMaxLength(128).IsRequired();
            e.Property(x => x.Name).HasMaxLength(256).IsRequired();
            // Hash is the lookup key on every ingest hit — unique index
            // keeps the validate path to a single-row hit.
            e.HasIndex(x => x.TokenHash).IsUnique();
            e.HasIndex(x => x.ClientId);
            e.HasIndex(x => x.ProjectId);
        });

        b.Entity<VexStatement>(e =>
        {
            e.HasKey(x => x.Id);
            e.Property(x => x.Purl).HasMaxLength(1024).IsRequired();
            e.Property(x => x.ComponentVersion).HasMaxLength(128);
            e.Property(x => x.AdvisoryId).HasMaxLength(64).IsRequired();
            e.Property(x => x.ImpactStatement).HasColumnType("text");
            e.Property(x => x.ResponseReferenceUrl).HasMaxLength(1024);
            // Lookup at score time: project + advisory + purl. Index
            // matches that query shape.
            e.HasIndex(x => new { x.ProjectId, x.AdvisoryId, x.Purl });
            e.HasIndex(x => x.RetiredAt);
            e.HasOne<Project>().WithMany().HasForeignKey(x => x.ProjectId).OnDelete(DeleteBehavior.Cascade);
        });

        b.Entity<PoamItem>(e =>
        {
            e.HasKey(x => x.Id);
            e.Property(x => x.Title).HasMaxLength(512).IsRequired();
            e.Property(x => x.WeaknessDescription).HasColumnType("text").IsRequired();
            e.Property(x => x.MitigationPlan).HasColumnType("text");
            e.Property(x => x.ResourcesRequired).HasMaxLength(2048);
            e.Property(x => x.ReferenceUrl).HasMaxLength(1024);
            // Source discriminator (TFND-188 / ADR 0010 §9).
            e.Property(x => x.SourceRef).HasMaxLength(256);
            e.Property(x => x.MandatePackVersion).HasMaxLength(64);
            e.HasIndex(x => new { x.SourceKind, x.SourceRef });
            // Linked Finding/Vulnerability Guids as jsonb. EnableDynamicJson
            // (see ServiceCollectionExtensions) lets Npgsql round-trip the
            // List<Guid> without a converter.
            e.Property(x => x.LinkedFindingIds).HasColumnType("jsonb");
            // Past-due gate scans by (ProjectId, ClosedAt IS NULL, ScheduledCompletionDate)
            // — index matches that shape.
            e.HasIndex(x => new { x.ProjectId, x.Status, x.ScheduledCompletionDate });
            e.HasIndex(x => x.ClosedAt);
            e.HasOne<Project>().WithMany().HasForeignKey(x => x.ProjectId).OnDelete(DeleteBehavior.Cascade);
        });

        b.Entity<KevAdvisory>(e =>
        {
            // CveId is the natural primary key: the CISA catalog
            // publishes exactly one row per CVE. Postgres can't index
            // varchar(64) any cheaper than as the PK itself, so use it
            // directly instead of carrying a synthetic GUID.
            e.HasKey(x => x.CveId);
            e.Property(x => x.CveId).HasMaxLength(64);
            e.Property(x => x.VendorProject).HasMaxLength(256);
            e.Property(x => x.Product).HasMaxLength(256);
            e.Property(x => x.VulnerabilityName).HasMaxLength(512);
            e.Property(x => x.ShortDescription).HasColumnType("text");
            e.Property(x => x.RequiredAction).HasColumnType("text");
            e.Property(x => x.Notes).HasColumnType("text");
            e.HasIndex(x => x.DueDate);
            e.HasIndex(x => x.KnownRansomwareCampaignUse);
        });

        b.Entity<RiskPolicy>(e =>
        {
            e.HasKey(x => x.Id);
            e.Property(x => x.Name).HasMaxLength(256).IsRequired();
            e.Property(x => x.Description).HasMaxLength(2048);
            // Typed POCO → jsonb. EnableDynamicJson is on (see
            // ServiceCollectionExtensions), so Npgsql will materialize
            // Dictionary<string, RiskCategoryConfig> round-trip without
            // a converter.
            e.Property(x => x.Config).HasColumnType("jsonb").IsRequired();
            e.HasIndex(x => x.Name).IsUnique();
            // Sparse-unique on IsDefault=true guarantees one (and only one)
            // system default at the DB level. Postgres partial-unique
            // index expresses this cleanly.
            e.HasIndex(x => x.IsDefault).IsUnique().HasFilter("\"IsDefault\" = true");
        });

        b.Entity<PolicyTemplate>(e =>
        {
            e.HasKey(x => x.Id);
            e.Property(x => x.Name).HasMaxLength(256).IsRequired();
            e.Ignore(x => x.Label); // computed
            // The hardenable overlay, jsonb like RiskPolicy.Config.
            e.Property(x => x.Layer).HasColumnType("jsonb").IsRequired();
            e.Property(x => x.CreatedByLogin).HasMaxLength(256);
            // A template's identity is (name, version) — a new version is a new
            // row, so the pair is unique, not the name alone.
            e.HasIndex(x => new { x.Name, x.Version }).IsUnique();
            // Link the scoring policy; SetNull so deleting it drops the link.
            e.HasOne<RiskPolicy>().WithMany().HasForeignKey(x => x.RiskPolicyId).OnDelete(DeleteBehavior.SetNull);
        });

        b.Entity<ControlCatalog>(e =>
        {
            e.HasKey(x => x.Id);
            e.Property(x => x.Name).HasMaxLength(256).IsRequired();
            e.Property(x => x.Source).HasMaxLength(512).IsRequired();
            e.Property(x => x.Version).HasMaxLength(64).IsRequired();
            // The controls travel inline as jsonb — a catalog is read whole.
            e.Property(x => x.Controls).HasColumnType("jsonb").IsRequired();
            // At most one current catalog, like the default RiskPolicy.
            e.HasIndex(x => x.IsCurrent).IsUnique().HasFilter("\"IsCurrent\" = true");
        });

        b.Entity<Framework>(e =>
        {
            e.HasKey(x => x.Id);
            e.Property(x => x.Slug).HasMaxLength(64).IsRequired();
            e.Property(x => x.Name).HasMaxLength(256).IsRequired();
            e.Property(x => x.Source).HasMaxLength(512).IsRequired();
            e.Property(x => x.Version).HasMaxLength(64).IsRequired();
            e.HasIndex(x => x.Slug).IsUnique();
        });

        b.Entity<ConformanceFinding>(e =>
        {
            e.HasKey(x => x.Id);
            e.Property(x => x.AdrRef).HasMaxLength(64).IsRequired();
            e.Property(x => x.RuleId).HasMaxLength(128).IsRequired();
            e.Property(x => x.AdrQuote).HasColumnType("text");
            e.Property(x => x.CodeEvidence).HasColumnType("text");
            e.Property(x => x.DispositionJustification).HasColumnType("text");
            // Control refs travel as jsonb, like other string lists here.
            e.Property(x => x.ControlRefs).HasColumnType("jsonb");
            // ZT maturity / mandate signal (TFND-188).
            e.Property(x => x.ZtPillar).HasMaxLength(128);
            e.Property(x => x.ZtFunction).HasMaxLength(128);
            e.Property(x => x.MandateId).HasMaxLength(128);
            e.HasIndex(x => x.ComponentVersionId);
            e.HasIndex(x => x.MandateId);
        });

        // Undocumented-decision advisories (reverse-examination, ADR 0013). Advisory-only
        // governance evidence — never gates. Upsert key is (build, ruleId, location) so a
        // re-run refreshes rather than duplicates.
        b.Entity<DecisionDiagnostic>(e =>
        {
            e.HasKey(x => x.Id);
            e.Property(x => x.RuleId).HasMaxLength(128).IsRequired();
            e.Property(x => x.Kind).HasMaxLength(64).IsRequired();
            e.Property(x => x.Summary).HasColumnType("text").IsRequired();
            e.Property(x => x.Location).HasMaxLength(1024);
            e.Property(x => x.CommitSha).HasMaxLength(128);
            e.Property(x => x.ControlRefs).HasColumnType("jsonb");
            e.HasIndex(x => x.ComponentVersionId);
            e.HasIndex(x => new { x.ComponentVersionId, x.RuleId, x.Location });
        });

        // Per-build score snapshot (TFND-176). One row per (project, commit), upserted at ingest.
        b.Entity<ScoreSnapshot>(e =>
        {
            e.HasKey(x => x.Id);
            e.Property(x => x.CommitSha).HasMaxLength(128).IsRequired();
            e.Property(x => x.Band).HasMaxLength(32);
            e.Property(x => x.PolicyName).HasMaxLength(256);
            e.Property(x => x.Breakdown).HasColumnType("jsonb");
            e.HasIndex(x => new { x.ProjectId, x.CommitSha }).IsUnique();
            e.HasIndex(x => new { x.ProjectId, x.BuiltAt });
        });

        // ── tamp-EOProvenance (ADR 0011) ──
        b.Entity<Instrument>(e =>
        {
            e.HasKey(x => x.Id);
            e.Property(x => x.Identifier).HasMaxLength(64).IsRequired();
            e.Property(x => x.Title).HasMaxLength(1024).IsRequired();
            e.Property(x => x.IssuingAuthority).HasMaxLength(256);
            e.Property(x => x.PublicationCite).HasMaxLength(512);
            e.Property(x => x.SourceHash).HasMaxLength(128);
            e.Property(x => x.ExtractionModelId).HasMaxLength(128);
            e.HasIndex(x => x.Identifier).IsUnique();
        });

        b.Entity<InstrumentRelation>(e =>
        {
            e.HasKey(x => x.Id);
            e.Property(x => x.FromSection).HasMaxLength(128);
            e.Property(x => x.ToSection).HasMaxLength(128);
            // Walkable in either direction (ADR 0011 §2).
            e.HasIndex(x => x.FromInstrumentId);
            e.HasIndex(x => x.ToInstrumentId);
        });

        b.Entity<Directive>(e =>
        {
            e.HasKey(x => x.Id);
            e.Property(x => x.Ref).HasMaxLength(128).IsRequired();
            e.Property(x => x.Section).HasMaxLength(128);
            e.Property(x => x.Who).HasMaxLength(512).IsRequired();
            e.Property(x => x.MustDo).HasColumnType("text").IsRequired();
            e.Property(x => x.SourceHash).HasMaxLength(128);
            e.Property(x => x.ExtractionModelId).HasMaxLength(128);
            e.HasIndex(x => x.Ref).IsUnique();
            e.HasIndex(x => x.InstrumentId);
        });

        b.Entity<DirectiveStatusChange>(e =>
        {
            e.HasKey(x => x.Id);
            // Point-in-time lookup: latest change ≤ asOf, per directive.
            e.HasIndex(x => new { x.DirectiveId, x.EffectiveDate });
        });

        b.Entity<DirectiveCrosswalk>(e =>
        {
            e.HasKey(x => x.Id);
            e.Property(x => x.TargetRef).HasMaxLength(256).IsRequired();
            e.HasIndex(x => x.DirectiveId);
            // No mandate double-scored: one directive per (Target, TargetRef).
            e.HasIndex(x => new { x.Target, x.TargetRef }).IsUnique();
        });

        // ── tamp-ztt (TFND-188 / ADR 0010) ──
        b.Entity<MaturityModelCatalog>(e =>
        {
            e.HasKey(x => x.Id);
            e.Property(x => x.Name).HasMaxLength(256).IsRequired();
            e.Property(x => x.Version).HasMaxLength(64).IsRequired();
            e.Property(x => x.Source).HasMaxLength(512).IsRequired();
            e.Property(x => x.Pillars).HasColumnType("jsonb").IsRequired();
            e.HasIndex(x => x.IsCurrent).IsUnique().HasFilter("\"IsCurrent\" = true");
        });

        b.Entity<ZtSystem>(e =>
        {
            e.HasKey(x => x.Id);
            e.Property(x => x.Name).HasMaxLength(256).IsRequired();
            e.Property(x => x.CsamId).HasMaxLength(128);
            e.Property(x => x.SystemKind).HasMaxLength(64);
            e.HasIndex(x => new { x.ClientId, x.Name }).IsUnique();
            e.HasIndex(x => x.ProjectId);
            e.HasOne<Client>().WithMany().HasForeignKey(x => x.ClientId).OnDelete(DeleteBehavior.Cascade);
            e.HasOne<Project>().WithMany().HasForeignKey(x => x.ProjectId).OnDelete(DeleteBehavior.SetNull);
        });

        b.Entity<EnterpriseOffering>(e =>
        {
            e.HasKey(x => x.Id);
            e.Property(x => x.ServiceLevelId).HasMaxLength(128).IsRequired();
            e.Property(x => x.Name).HasMaxLength(256).IsRequired();
            e.Property(x => x.Description).HasColumnType("text");
            e.Property(x => x.FunctionScores).HasColumnType("jsonb").IsRequired();
            e.HasIndex(x => new { x.ClientId, x.ServiceLevelId }).IsUnique();
            e.HasOne<Client>().WithMany().HasForeignKey(x => x.ClientId).OnDelete(DeleteBehavior.Cascade);
        });

        b.Entity<ZtInheritanceEdge>(e =>
        {
            e.HasKey(x => x.Id);
            e.Property(x => x.Pillar).HasMaxLength(128).IsRequired();
            e.Property(x => x.Function).HasMaxLength(128).IsRequired();
            e.Property(x => x.AttesterName).HasMaxLength(256);
            e.Property(x => x.AttesterLogin).HasMaxLength(256);
            e.Property(x => x.Statement).HasColumnType("text");
            e.Property(x => x.EvidenceRef).HasMaxLength(1024);
            // One inheritance source per function per system.
            e.HasIndex(x => new { x.SystemId, x.Pillar, x.Function }).IsUnique();
            e.HasOne<ZtSystem>().WithMany().HasForeignKey(x => x.SystemId).OnDelete(DeleteBehavior.Cascade);
            e.HasOne<EnterpriseOffering>().WithMany().HasForeignKey(x => x.OfferingId).OnDelete(DeleteBehavior.Cascade);
        });

        b.Entity<ZtSystemPick>(e =>
        {
            e.HasKey(x => x.Id);
            e.Property(x => x.Pillar).HasMaxLength(128).IsRequired();
            e.Property(x => x.Function).HasMaxLength(128).IsRequired();
            e.Property(x => x.Justification).HasColumnType("text");
            e.HasIndex(x => new { x.SystemId, x.Pillar, x.Function }).IsUnique();
            e.HasOne<ZtSystem>().WithMany().HasForeignKey(x => x.SystemId).OnDelete(DeleteBehavior.Cascade);
        });

        b.Entity<MandatePack>(e =>
        {
            e.HasKey(x => x.Id);
            e.Property(x => x.Version).HasMaxLength(64).IsRequired();
            e.Property(x => x.Mandates).HasColumnType("jsonb").IsRequired();
            e.HasIndex(x => x.IsCurrent).IsUnique().HasFilter("\"IsCurrent\" = true");
        });

        b.Entity<ConformanceRule>(e =>
        {
            e.HasKey(x => x.Id);
            e.Property(x => x.AdrRef).HasMaxLength(64).IsRequired();
            e.Property(x => x.RuleId).HasMaxLength(128).IsRequired();
            e.Property(x => x.Intent).HasColumnType("text");
            e.Property(x => x.CheckSpec).HasColumnType("text");
            e.Property(x => x.ControlRefs).HasColumnType("jsonb");
            e.Property(x => x.ZtPillar).HasMaxLength(128);
            e.Property(x => x.ZtFunction).HasMaxLength(128);
            e.Property(x => x.MandateId).HasMaxLength(128);
            e.Property(x => x.RulesSha).HasMaxLength(128);
            e.Property(x => x.ExtractionModelId).HasMaxLength(128);
            // Upsert key: one row per rule per project (retire toggles RetiredAt on it).
            e.HasIndex(x => new { x.ProjectId, x.AdrRef, x.RuleId }).IsUnique();
            // The active-set fetch scans by project + not-retired.
            e.HasIndex(x => new { x.ProjectId, x.RetiredAt });
            e.HasOne<Project>().WithMany().HasForeignKey(x => x.ProjectId).OnDelete(DeleteBehavior.Cascade);
        });

        b.Entity<CoverageClass>(e =>
        {
            e.HasKey(x => x.Id);
            e.Property(x => x.FullName).HasMaxLength(1024).IsRequired();
            // Native Postgres integer[] — Npgsql maps int[] without a converter.
            e.Property(x => x.VisitedLines).HasColumnType("integer[]").IsRequired();
            e.Property(x => x.UnvisitedLines).HasColumnType("integer[]").IsRequired();
            e.HasOne(x => x.Module).WithMany(m => m.Classes).HasForeignKey(x => x.CoverageModuleId).OnDelete(DeleteBehavior.Cascade);
            e.HasOne(x => x.SourceFile).WithMany(f => f.Classes).HasForeignKey(x => x.CoverageSourceFileId).OnDelete(DeleteBehavior.Cascade);
            e.HasIndex(x => new { x.CoverageModuleId, x.FullName, x.CoverageSourceFileId }).IsUnique();
        });
    }

    // Append-only enforcement for the audit trail.
    //
    // Enforced HERE rather than by convention, because "everyone remembers not
    // to modify audit rows" is exactly the kind of rule that holds until the
    // one time it doesn't. An audit trail with an eraser is not an audit
    // trail, and this is the evidence an assessor reads first.
    //
    // Note this does not stop someone with database access editing rows
    // directly. It stops the APPLICATION from having a code path that does.
    public override int SaveChanges(bool acceptAllChangesOnSuccess)
    {
        GuardAuditTrail();
        return base.SaveChanges(acceptAllChangesOnSuccess);
    }

    public override Task<int> SaveChangesAsync(
        bool acceptAllChangesOnSuccess, CancellationToken cancellationToken = default)
    {
        GuardAuditTrail();
        return base.SaveChangesAsync(acceptAllChangesOnSuccess, cancellationToken);
    }

    private void GuardAuditTrail()
    {
        foreach (var entry in ChangeTracker.Entries<AuditEntry>())
        {
            if (entry.State is EntityState.Modified or EntityState.Deleted)
            {
                throw new InvalidOperationException(
                    $"AuditEntry is append-only; attempted to {entry.State.ToString().ToLowerInvariant()} "
                    + $"entry {entry.Entity.Id} ({entry.Entity.Action}). Write a new entry instead.");
            }
        }

        // Directive status changes are the point-in-time evidence (ADR 0011 §4):
        // never delete, always date. A status history with an eraser cannot prove
        // what was in force on a past date. Append a new change to correct one.
        foreach (var entry in ChangeTracker.Entries<DirectiveStatusChange>())
        {
            if (entry.State is EntityState.Modified or EntityState.Deleted)
            {
                throw new InvalidOperationException(
                    $"DirectiveStatusChange is append-only; attempted to {entry.State.ToString().ToLowerInvariant()} "
                    + $"change {entry.Entity.Id} on directive {entry.Entity.DirectiveId}. Append a new dated change instead.");
            }
        }

        // Attestation snapshots are evidence (TFND-103, ADR 0001). An
        // attestation signed in March must be reproducible in September, and a
        // snapshot that can be edited is not evidence — so the document itself
        // is frozen and only the signature fields may ever be filled in.
        foreach (var entry in ChangeTracker.Entries<AttestationSnapshot>())
        {
            if (entry.State == EntityState.Deleted)
            {
                throw new InvalidOperationException(
                    $"AttestationSnapshot {entry.Entity.Id} is immutable; it cannot be deleted. "
                    + "It is the evidence that a signature was sound.");
            }

            if (entry.State != EntityState.Modified) continue;

            var mutated = entry.Properties
                .Where(p => p.IsModified)
                .Select(p => p.Metadata.Name)
                // The sign-off fields are the only ones that may change, and
                // only once (SignAsync refuses a second signature). TFND-160
                // adds the key-backed signature written at the same moment.
                .Where(name => name is not (
                    nameof(AttestationSnapshot.SignedAt) or nameof(AttestationSnapshot.SignedBy)
                    or nameof(AttestationSnapshot.Signature) or nameof(AttestationSnapshot.SignatureAlgorithm)
                    or nameof(AttestationSnapshot.SigningKeyId)))
                .ToArray();

            if (mutated.Length > 0)
            {
                throw new InvalidOperationException(
                    $"AttestationSnapshot {entry.Entity.Id} is immutable; attempted to change "
                    + $"{string.Join(", ", mutated)}. Generate a new snapshot instead.");
            }
        }
    }
}
