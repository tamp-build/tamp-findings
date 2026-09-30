using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace Tamp.Findings.Data.Migrations
{
    /// <inheritdoc />
    public partial class AddProjectBadgeKey : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AddColumn<string>(
                name: "BadgeKey",
                table: "Projects",
                type: "character varying(64)",
                maxLength: 64,
                nullable: true);

            // Backfill every existing project with an opaque key so its badge works immediately.
            // 32 hex chars (a UUID minus dashes) — matches the 128-bit key the app mints.
            migrationBuilder.Sql(
                "UPDATE \"Projects\" SET \"BadgeKey\" = replace(gen_random_uuid()::text, '-', '') WHERE \"BadgeKey\" IS NULL;");

            migrationBuilder.CreateIndex(
                name: "IX_Projects_BadgeKey",
                table: "Projects",
                column: "BadgeKey",
                unique: true);
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropIndex(
                name: "IX_Projects_BadgeKey",
                table: "Projects");

            migrationBuilder.DropColumn(
                name: "BadgeKey",
                table: "Projects");
        }
    }
}
