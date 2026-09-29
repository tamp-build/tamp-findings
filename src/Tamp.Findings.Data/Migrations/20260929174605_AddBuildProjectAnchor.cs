using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace Tamp.Findings.Data.Migrations
{
    /// <inheritdoc />
    public partial class AddBuildProjectAnchor : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            // Component-collapse PR1: anchor each build (ComponentVersion) directly to its Project,
            // and carry the flavor as a plain string tag. Add nullable, backfill from the existing
            // Component/ComponentFlavor rows, THEN enforce NOT NULL + FK — so the 177 existing rows
            // are anchored correctly rather than defaulted to an empty guid that fails the FK.
            migrationBuilder.AddColumn<string>(
                name: "Flavor",
                table: "ComponentVersions",
                type: "character varying(64)",
                maxLength: 64,
                nullable: true);

            migrationBuilder.AddColumn<Guid>(
                name: "ProjectId",
                table: "ComponentVersions",
                type: "uuid",
                nullable: true);

            // Backfill from the tier being collapsed.
            migrationBuilder.Sql(
                "UPDATE \"ComponentVersions\" cv SET \"ProjectId\" = c.\"ProjectId\" " +
                "FROM \"Components\" c WHERE cv.\"ComponentId\" = c.\"Id\";");
            migrationBuilder.Sql(
                "UPDATE \"ComponentVersions\" cv SET \"Flavor\" = f.\"Name\" " +
                "FROM \"ComponentFlavors\" f WHERE cv.\"FlavorId\" = f.\"Id\";");

            // Every build now has a project; enforce it.
            migrationBuilder.AlterColumn<Guid>(
                name: "ProjectId",
                table: "ComponentVersions",
                type: "uuid",
                nullable: false,
                oldClrType: typeof(Guid),
                oldType: "uuid",
                oldNullable: true);

            migrationBuilder.CreateIndex(
                name: "IX_ComponentVersions_ProjectId_Flavor_VersionString",
                table: "ComponentVersions",
                columns: new[] { "ProjectId", "Flavor", "VersionString" });

            migrationBuilder.AddForeignKey(
                name: "FK_ComponentVersions_Projects_ProjectId",
                table: "ComponentVersions",
                column: "ProjectId",
                principalTable: "Projects",
                principalColumn: "Id",
                onDelete: ReferentialAction.Cascade);
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropForeignKey(
                name: "FK_ComponentVersions_Projects_ProjectId",
                table: "ComponentVersions");

            migrationBuilder.DropIndex(
                name: "IX_ComponentVersions_ProjectId_Flavor_VersionString",
                table: "ComponentVersions");

            migrationBuilder.DropColumn(
                name: "Flavor",
                table: "ComponentVersions");

            migrationBuilder.DropColumn(
                name: "ProjectId",
                table: "ComponentVersions");
        }
    }
}
