using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace Tamp.Findings.Data.Migrations
{
    /// <inheritdoc />
    public partial class DropComponentTier : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropForeignKey(
                name: "FK_ComponentVersions_ComponentFlavors_FlavorId",
                table: "ComponentVersions");

            migrationBuilder.DropForeignKey(
                name: "FK_ComponentVersions_Components_ComponentId",
                table: "ComponentVersions");

            migrationBuilder.DropTable(
                name: "ComponentFlavors");

            migrationBuilder.DropTable(
                name: "Components");

            migrationBuilder.DropIndex(
                name: "IX_Suppressions_ComponentId",
                table: "Suppressions");

            migrationBuilder.DropIndex(
                name: "IX_ProjectRoleAssignments_UserId_Role_ClientId_ProjectId_Compo~",
                table: "ProjectRoleAssignments");

            migrationBuilder.DropIndex(
                name: "IX_McpTokens_ClientId_ProjectId_ComponentId",
                table: "McpTokens");

            migrationBuilder.DropIndex(
                name: "IX_ComponentVersions_ComponentId_FlavorId_VersionString",
                table: "ComponentVersions");

            migrationBuilder.DropIndex(
                name: "IX_ComponentVersions_FlavorId",
                table: "ComponentVersions");

            migrationBuilder.DropIndex(
                name: "IX_ComponentVersions_ProjectId_Flavor_VersionString",
                table: "ComponentVersions");

            migrationBuilder.DropColumn(
                name: "ComponentId",
                table: "Suppressions");

            migrationBuilder.DropColumn(
                name: "ComponentId",
                table: "ProjectRoleAssignments");

            migrationBuilder.DropColumn(
                name: "ComponentId",
                table: "McpTokens");

            migrationBuilder.DropColumn(
                name: "ComponentId",
                table: "ComponentVersions");

            migrationBuilder.DropColumn(
                name: "FlavorId",
                table: "ComponentVersions");

            migrationBuilder.DropColumn(
                name: "ComponentId",
                table: "AuditEntries");

            migrationBuilder.CreateIndex(
                name: "IX_ProjectRoleAssignments_UserId_Role_ClientId_ProjectId",
                table: "ProjectRoleAssignments",
                columns: new[] { "UserId", "Role", "ClientId", "ProjectId" },
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_McpTokens_ClientId_ProjectId",
                table: "McpTokens",
                columns: new[] { "ClientId", "ProjectId" });

            migrationBuilder.CreateIndex(
                name: "IX_ComponentVersions_ProjectId_Flavor_VersionString",
                table: "ComponentVersions",
                columns: new[] { "ProjectId", "Flavor", "VersionString" },
                unique: true);
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropIndex(
                name: "IX_ProjectRoleAssignments_UserId_Role_ClientId_ProjectId",
                table: "ProjectRoleAssignments");

            migrationBuilder.DropIndex(
                name: "IX_McpTokens_ClientId_ProjectId",
                table: "McpTokens");

            migrationBuilder.DropIndex(
                name: "IX_ComponentVersions_ProjectId_Flavor_VersionString",
                table: "ComponentVersions");

            migrationBuilder.AddColumn<Guid>(
                name: "ComponentId",
                table: "Suppressions",
                type: "uuid",
                nullable: true);

            migrationBuilder.AddColumn<Guid>(
                name: "ComponentId",
                table: "ProjectRoleAssignments",
                type: "uuid",
                nullable: true);

            migrationBuilder.AddColumn<Guid>(
                name: "ComponentId",
                table: "McpTokens",
                type: "uuid",
                nullable: true);

            migrationBuilder.AddColumn<Guid>(
                name: "ComponentId",
                table: "ComponentVersions",
                type: "uuid",
                nullable: false,
                defaultValue: new Guid("00000000-0000-0000-0000-000000000000"));

            migrationBuilder.AddColumn<Guid>(
                name: "FlavorId",
                table: "ComponentVersions",
                type: "uuid",
                nullable: true);

            migrationBuilder.AddColumn<Guid>(
                name: "ComponentId",
                table: "AuditEntries",
                type: "uuid",
                nullable: true);

            migrationBuilder.CreateTable(
                name: "Components",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "uuid", nullable: false),
                    ProjectId = table.Column<Guid>(type: "uuid", nullable: false),
                    CreatedAt = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false),
                    Kind = table.Column<string>(type: "character varying(64)", maxLength: 64, nullable: true),
                    Name = table.Column<string>(type: "character varying(256)", maxLength: 256, nullable: false),
                    Profile = table.Column<int>(type: "integer", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_Components", x => x.Id);
                    table.ForeignKey(
                        name: "FK_Components_Projects_ProjectId",
                        column: x => x.ProjectId,
                        principalTable: "Projects",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateTable(
                name: "ComponentFlavors",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "uuid", nullable: false),
                    ComponentId = table.Column<Guid>(type: "uuid", nullable: false),
                    Name = table.Column<string>(type: "character varying(64)", maxLength: 64, nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_ComponentFlavors", x => x.Id);
                    table.ForeignKey(
                        name: "FK_ComponentFlavors_Components_ComponentId",
                        column: x => x.ComponentId,
                        principalTable: "Components",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateIndex(
                name: "IX_Suppressions_ComponentId",
                table: "Suppressions",
                column: "ComponentId");

            migrationBuilder.CreateIndex(
                name: "IX_ProjectRoleAssignments_UserId_Role_ClientId_ProjectId_Compo~",
                table: "ProjectRoleAssignments",
                columns: new[] { "UserId", "Role", "ClientId", "ProjectId", "ComponentId" },
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_McpTokens_ClientId_ProjectId_ComponentId",
                table: "McpTokens",
                columns: new[] { "ClientId", "ProjectId", "ComponentId" });

            migrationBuilder.CreateIndex(
                name: "IX_ComponentVersions_ComponentId_FlavorId_VersionString",
                table: "ComponentVersions",
                columns: new[] { "ComponentId", "FlavorId", "VersionString" },
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_ComponentVersions_FlavorId",
                table: "ComponentVersions",
                column: "FlavorId");

            migrationBuilder.CreateIndex(
                name: "IX_ComponentVersions_ProjectId_Flavor_VersionString",
                table: "ComponentVersions",
                columns: new[] { "ProjectId", "Flavor", "VersionString" });

            migrationBuilder.CreateIndex(
                name: "IX_ComponentFlavors_ComponentId_Name",
                table: "ComponentFlavors",
                columns: new[] { "ComponentId", "Name" },
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_Components_ProjectId_Name",
                table: "Components",
                columns: new[] { "ProjectId", "Name" },
                unique: true);

            migrationBuilder.AddForeignKey(
                name: "FK_ComponentVersions_ComponentFlavors_FlavorId",
                table: "ComponentVersions",
                column: "FlavorId",
                principalTable: "ComponentFlavors",
                principalColumn: "Id",
                onDelete: ReferentialAction.SetNull);

            migrationBuilder.AddForeignKey(
                name: "FK_ComponentVersions_Components_ComponentId",
                table: "ComponentVersions",
                column: "ComponentId",
                principalTable: "Components",
                principalColumn: "Id",
                onDelete: ReferentialAction.Cascade);
        }
    }
}
