using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace Tamp.Findings.Data.Migrations
{
    /// <inheritdoc />
    public partial class Tfnd23_GitHubApp : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AddColumn<string>(
                name: "GitHubRepository",
                table: "Projects",
                type: "character varying(256)",
                maxLength: 256,
                nullable: true);

            migrationBuilder.AddColumn<string>(
                name: "GitHubAppId",
                table: "InstanceSettings",
                type: "character varying(32)",
                maxLength: 32,
                nullable: true);

            migrationBuilder.AddColumn<string>(
                name: "GitHubAppPrivateKeyProtected",
                table: "InstanceSettings",
                type: "text",
                nullable: true);

            migrationBuilder.AddColumn<string>(
                name: "GitHubCheckName",
                table: "InstanceSettings",
                type: "character varying(128)",
                maxLength: 128,
                nullable: false,
                defaultValue: "");

            migrationBuilder.AddColumn<bool>(
                name: "GitHubChecksEnabled",
                table: "InstanceSettings",
                type: "boolean",
                nullable: false,
                defaultValue: false);
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropColumn(
                name: "GitHubRepository",
                table: "Projects");

            migrationBuilder.DropColumn(
                name: "GitHubAppId",
                table: "InstanceSettings");

            migrationBuilder.DropColumn(
                name: "GitHubAppPrivateKeyProtected",
                table: "InstanceSettings");

            migrationBuilder.DropColumn(
                name: "GitHubCheckName",
                table: "InstanceSettings");

            migrationBuilder.DropColumn(
                name: "GitHubChecksEnabled",
                table: "InstanceSettings");
        }
    }
}
