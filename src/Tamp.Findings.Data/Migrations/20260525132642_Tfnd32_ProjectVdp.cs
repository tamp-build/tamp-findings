using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace Tamp.Findings.Data.Migrations
{
    /// <inheritdoc />
    public partial class Tfnd32_ProjectVdp : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AddColumn<string>(
                name: "VdpContactEmail",
                table: "Projects",
                type: "character varying(320)",
                maxLength: 320,
                nullable: true);

            migrationBuilder.AddColumn<string>(
                name: "VdpPolicyUrl",
                table: "Projects",
                type: "character varying(1024)",
                maxLength: 1024,
                nullable: true);

            migrationBuilder.AddColumn<string>(
                name: "VdpReportingFormUrl",
                table: "Projects",
                type: "character varying(1024)",
                maxLength: 1024,
                nullable: true);
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropColumn(
                name: "VdpContactEmail",
                table: "Projects");

            migrationBuilder.DropColumn(
                name: "VdpPolicyUrl",
                table: "Projects");

            migrationBuilder.DropColumn(
                name: "VdpReportingFormUrl",
                table: "Projects");
        }
    }
}
