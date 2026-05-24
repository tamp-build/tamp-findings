using Microsoft.EntityFrameworkCore.Migrations;
using Tamp.Findings.Domain.Risk;

#nullable disable

namespace Tamp.Findings.Data.Migrations
{
    /// <inheritdoc />
    public partial class Tfnd_ProjectGates : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AddColumn<ProjectGatesConfig>(
                name: "GatesConfig",
                table: "Projects",
                type: "jsonb",
                nullable: true);
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropColumn(
                name: "GatesConfig",
                table: "Projects");
        }
    }
}
