using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace Tamp.Findings.Data.Migrations
{
    /// <inheritdoc />
    public partial class Tfnd147_EnforcementMode : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AddColumn<bool>(
                name: "EnforcementLocked",
                table: "InstanceSettings",
                type: "boolean",
                nullable: false,
                defaultValue: false);

            migrationBuilder.AddColumn<int>(
                name: "EnforcementMode",
                table: "InstanceSettings",
                type: "integer",
                nullable: false,
                defaultValue: 0);

            migrationBuilder.AddColumn<int>(
                name: "EnforcementMode",
                table: "Clients",
                type: "integer",
                nullable: true);
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropColumn(
                name: "EnforcementLocked",
                table: "InstanceSettings");

            migrationBuilder.DropColumn(
                name: "EnforcementMode",
                table: "InstanceSettings");

            migrationBuilder.DropColumn(
                name: "EnforcementMode",
                table: "Clients");
        }
    }
}
