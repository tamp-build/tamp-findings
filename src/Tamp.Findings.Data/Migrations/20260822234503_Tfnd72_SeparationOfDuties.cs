using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace Tamp.Findings.Data.Migrations
{
    /// <inheritdoc />
    public partial class Tfnd72_SeparationOfDuties : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AddColumn<Guid>(
                name: "GrantedByUserId",
                table: "ProjectRoleAssignments",
                type: "uuid",
                nullable: true);

            migrationBuilder.AddColumn<string>(
                name: "SodConflict",
                table: "ProjectRoleAssignments",
                type: "text",
                nullable: true);

            migrationBuilder.CreateTable(
                name: "InstanceSettings",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "uuid", nullable: false),
                    EnforceSeparationOfDuties = table.Column<bool>(type: "boolean", nullable: false),
                    UpdatedAt = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_InstanceSettings", x => x.Id);
                });
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropTable(
                name: "InstanceSettings");

            migrationBuilder.DropColumn(
                name: "GrantedByUserId",
                table: "ProjectRoleAssignments");

            migrationBuilder.DropColumn(
                name: "SodConflict",
                table: "ProjectRoleAssignments");
        }
    }
}
