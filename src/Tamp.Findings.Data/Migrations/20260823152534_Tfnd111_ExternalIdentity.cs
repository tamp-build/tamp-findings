using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace Tamp.Findings.Data.Migrations
{
    /// <inheritdoc />
    public partial class Tfnd111_ExternalIdentity : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AddColumn<string>(
                name: "ExternalScheme",
                table: "Users",
                type: "character varying(64)",
                maxLength: 64,
                nullable: true);

            migrationBuilder.AddColumn<string>(
                name: "ExternalSubject",
                table: "Users",
                type: "character varying(256)",
                maxLength: 256,
                nullable: true);

            migrationBuilder.CreateIndex(
                name: "IX_Users_ExternalScheme_ExternalSubject",
                table: "Users",
                columns: new[] { "ExternalScheme", "ExternalSubject" },
                unique: true,
                filter: "\"ExternalSubject\" IS NOT NULL");
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropIndex(
                name: "IX_Users_ExternalScheme_ExternalSubject",
                table: "Users");

            migrationBuilder.DropColumn(
                name: "ExternalScheme",
                table: "Users");

            migrationBuilder.DropColumn(
                name: "ExternalSubject",
                table: "Users");
        }
    }
}
