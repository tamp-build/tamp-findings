using System;
using System.Collections.Generic;
using Microsoft.EntityFrameworkCore.Migrations;
using Tamp.Findings.Domain.Compliance;
using Tamp.Findings.Domain.Entities;

#nullable disable

namespace Tamp.Findings.Data.Migrations
{
    /// <inheritdoc />
    public partial class AddZtMaturityModel : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AddColumn<string>(
                name: "MandatePackVersion",
                table: "PoamItems",
                type: "character varying(64)",
                maxLength: 64,
                nullable: true);

            migrationBuilder.AddColumn<int>(
                name: "SourceKind",
                table: "PoamItems",
                type: "integer",
                nullable: false,
                defaultValue: 0);

            migrationBuilder.AddColumn<string>(
                name: "SourceRef",
                table: "PoamItems",
                type: "character varying(256)",
                maxLength: 256,
                nullable: true);

            migrationBuilder.AddColumn<string>(
                name: "MandateId",
                table: "ConformanceFindings",
                type: "character varying(128)",
                maxLength: 128,
                nullable: true);

            migrationBuilder.AddColumn<string>(
                name: "ZtFunction",
                table: "ConformanceFindings",
                type: "character varying(128)",
                maxLength: 128,
                nullable: true);

            migrationBuilder.AddColumn<string>(
                name: "ZtPillar",
                table: "ConformanceFindings",
                type: "character varying(128)",
                maxLength: 128,
                nullable: true);

            migrationBuilder.AddColumn<int>(
                name: "ZtStage",
                table: "ConformanceFindings",
                type: "integer",
                nullable: true);

            migrationBuilder.AddColumn<Guid>(
                name: "MaturityModelId",
                table: "Clients",
                type: "uuid",
                nullable: true);

            migrationBuilder.AddColumn<int>(
                name: "ZtAttestationExpiryDays",
                table: "Clients",
                type: "integer",
                nullable: true);

            migrationBuilder.AddColumn<string>(
                name: "ZtAttestationRequirement",
                table: "Clients",
                type: "text",
                nullable: true);

            migrationBuilder.CreateTable(
                name: "EnterpriseOfferings",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "uuid", nullable: false),
                    ClientId = table.Column<Guid>(type: "uuid", nullable: false),
                    ServiceLevelId = table.Column<string>(type: "character varying(128)", maxLength: 128, nullable: false),
                    Name = table.Column<string>(type: "character varying(256)", maxLength: 256, nullable: false),
                    Description = table.Column<string>(type: "text", nullable: true),
                    CreatedAt = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false),
                    FunctionScores = table.Column<List<OfferingFunctionScore>>(type: "jsonb", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_EnterpriseOfferings", x => x.Id);
                    table.ForeignKey(
                        name: "FK_EnterpriseOfferings_Clients_ClientId",
                        column: x => x.ClientId,
                        principalTable: "Clients",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateTable(
                name: "MandatePacks",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "uuid", nullable: false),
                    Version = table.Column<string>(type: "character varying(64)", maxLength: 64, nullable: false),
                    IsCurrent = table.Column<bool>(type: "boolean", nullable: false),
                    IsSeeded = table.Column<bool>(type: "boolean", nullable: false),
                    CreatedAt = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false),
                    Mandates = table.Column<List<MandateDefinition>>(type: "jsonb", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_MandatePacks", x => x.Id);
                });

            migrationBuilder.CreateTable(
                name: "MaturityModelCatalogs",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "uuid", nullable: false),
                    Name = table.Column<string>(type: "character varying(256)", maxLength: 256, nullable: false),
                    Version = table.Column<string>(type: "character varying(64)", maxLength: 64, nullable: false),
                    Source = table.Column<string>(type: "character varying(512)", maxLength: 512, nullable: false),
                    ImportedSha = table.Column<string>(type: "text", nullable: true),
                    IsSeeded = table.Column<bool>(type: "boolean", nullable: false),
                    IsCurrent = table.Column<bool>(type: "boolean", nullable: false),
                    ImportedAt = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false),
                    Pillars = table.Column<List<ZtPillar>>(type: "jsonb", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_MaturityModelCatalogs", x => x.Id);
                });

            migrationBuilder.CreateTable(
                name: "ZtSystems",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "uuid", nullable: false),
                    ClientId = table.Column<Guid>(type: "uuid", nullable: false),
                    ProjectId = table.Column<Guid>(type: "uuid", nullable: true),
                    Name = table.Column<string>(type: "character varying(256)", maxLength: 256, nullable: false),
                    CsamId = table.Column<string>(type: "character varying(128)", maxLength: 128, nullable: true),
                    SystemKind = table.Column<string>(type: "character varying(64)", maxLength: 64, nullable: true),
                    CreatedAt = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_ZtSystems", x => x.Id);
                    table.ForeignKey(
                        name: "FK_ZtSystems_Clients_ClientId",
                        column: x => x.ClientId,
                        principalTable: "Clients",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Cascade);
                    table.ForeignKey(
                        name: "FK_ZtSystems_Projects_ProjectId",
                        column: x => x.ProjectId,
                        principalTable: "Projects",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.SetNull);
                });

            migrationBuilder.CreateTable(
                name: "ZtInheritanceEdges",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "uuid", nullable: false),
                    SystemId = table.Column<Guid>(type: "uuid", nullable: false),
                    OfferingId = table.Column<Guid>(type: "uuid", nullable: false),
                    Pillar = table.Column<string>(type: "character varying(128)", maxLength: 128, nullable: false),
                    Function = table.Column<string>(type: "character varying(128)", maxLength: 128, nullable: false),
                    AttesterName = table.Column<string>(type: "character varying(256)", maxLength: 256, nullable: true),
                    AttesterLogin = table.Column<string>(type: "character varying(256)", maxLength: 256, nullable: true),
                    Statement = table.Column<string>(type: "text", nullable: true),
                    EvidenceRef = table.Column<string>(type: "character varying(1024)", maxLength: 1024, nullable: true),
                    AttestedAt = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: true),
                    ExpiresAt = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: true),
                    AuthorUserId = table.Column<Guid>(type: "uuid", nullable: false),
                    CreatedAt = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_ZtInheritanceEdges", x => x.Id);
                    table.ForeignKey(
                        name: "FK_ZtInheritanceEdges_EnterpriseOfferings_OfferingId",
                        column: x => x.OfferingId,
                        principalTable: "EnterpriseOfferings",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Cascade);
                    table.ForeignKey(
                        name: "FK_ZtInheritanceEdges_ZtSystems_SystemId",
                        column: x => x.SystemId,
                        principalTable: "ZtSystems",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateTable(
                name: "ZtSystemPicks",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "uuid", nullable: false),
                    SystemId = table.Column<Guid>(type: "uuid", nullable: false),
                    Pillar = table.Column<string>(type: "character varying(128)", maxLength: 128, nullable: false),
                    Function = table.Column<string>(type: "character varying(128)", maxLength: 128, nullable: false),
                    Kind = table.Column<int>(type: "integer", nullable: false),
                    Justification = table.Column<string>(type: "text", nullable: true),
                    AuthorUserId = table.Column<Guid>(type: "uuid", nullable: false),
                    CreatedAt = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_ZtSystemPicks", x => x.Id);
                    table.ForeignKey(
                        name: "FK_ZtSystemPicks_ZtSystems_SystemId",
                        column: x => x.SystemId,
                        principalTable: "ZtSystems",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateIndex(
                name: "IX_PoamItems_SourceKind_SourceRef",
                table: "PoamItems",
                columns: new[] { "SourceKind", "SourceRef" });

            migrationBuilder.CreateIndex(
                name: "IX_ConformanceFindings_MandateId",
                table: "ConformanceFindings",
                column: "MandateId");

            migrationBuilder.CreateIndex(
                name: "IX_EnterpriseOfferings_ClientId_ServiceLevelId",
                table: "EnterpriseOfferings",
                columns: new[] { "ClientId", "ServiceLevelId" },
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_MandatePacks_IsCurrent",
                table: "MandatePacks",
                column: "IsCurrent",
                unique: true,
                filter: "\"IsCurrent\" = true");

            migrationBuilder.CreateIndex(
                name: "IX_MaturityModelCatalogs_IsCurrent",
                table: "MaturityModelCatalogs",
                column: "IsCurrent",
                unique: true,
                filter: "\"IsCurrent\" = true");

            migrationBuilder.CreateIndex(
                name: "IX_ZtInheritanceEdges_OfferingId",
                table: "ZtInheritanceEdges",
                column: "OfferingId");

            migrationBuilder.CreateIndex(
                name: "IX_ZtInheritanceEdges_SystemId_Pillar_Function",
                table: "ZtInheritanceEdges",
                columns: new[] { "SystemId", "Pillar", "Function" },
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_ZtSystemPicks_SystemId_Pillar_Function",
                table: "ZtSystemPicks",
                columns: new[] { "SystemId", "Pillar", "Function" },
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_ZtSystems_ClientId_Name",
                table: "ZtSystems",
                columns: new[] { "ClientId", "Name" },
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_ZtSystems_ProjectId",
                table: "ZtSystems",
                column: "ProjectId");
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropTable(
                name: "MandatePacks");

            migrationBuilder.DropTable(
                name: "MaturityModelCatalogs");

            migrationBuilder.DropTable(
                name: "ZtInheritanceEdges");

            migrationBuilder.DropTable(
                name: "ZtSystemPicks");

            migrationBuilder.DropTable(
                name: "EnterpriseOfferings");

            migrationBuilder.DropTable(
                name: "ZtSystems");

            migrationBuilder.DropIndex(
                name: "IX_PoamItems_SourceKind_SourceRef",
                table: "PoamItems");

            migrationBuilder.DropIndex(
                name: "IX_ConformanceFindings_MandateId",
                table: "ConformanceFindings");

            migrationBuilder.DropColumn(
                name: "MandatePackVersion",
                table: "PoamItems");

            migrationBuilder.DropColumn(
                name: "SourceKind",
                table: "PoamItems");

            migrationBuilder.DropColumn(
                name: "SourceRef",
                table: "PoamItems");

            migrationBuilder.DropColumn(
                name: "MandateId",
                table: "ConformanceFindings");

            migrationBuilder.DropColumn(
                name: "ZtFunction",
                table: "ConformanceFindings");

            migrationBuilder.DropColumn(
                name: "ZtPillar",
                table: "ConformanceFindings");

            migrationBuilder.DropColumn(
                name: "ZtStage",
                table: "ConformanceFindings");

            migrationBuilder.DropColumn(
                name: "MaturityModelId",
                table: "Clients");

            migrationBuilder.DropColumn(
                name: "ZtAttestationExpiryDays",
                table: "Clients");

            migrationBuilder.DropColumn(
                name: "ZtAttestationRequirement",
                table: "Clients");
        }
    }
}
