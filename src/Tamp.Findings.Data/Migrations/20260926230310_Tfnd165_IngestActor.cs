using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace Tamp.Findings.Data.Migrations
{
    /// <inheritdoc />
    public partial class Tfnd165_IngestActor : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AddColumn<string>(
                name: "ActorId",
                table: "ComponentVersions",
                type: "text",
                nullable: true);

            migrationBuilder.AddColumn<int>(
                name: "ActorKind",
                table: "ComponentVersions",
                type: "integer",
                nullable: true);
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropColumn(
                name: "ActorId",
                table: "ComponentVersions");

            migrationBuilder.DropColumn(
                name: "ActorKind",
                table: "ComponentVersions");
        }
    }
}
