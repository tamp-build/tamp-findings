using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace Tamp.Findings.Data.Migrations
{
    /// <inheritdoc />
    public partial class BuildIdentityIsTheCommit : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropIndex(
                name: "IX_ComponentVersions_ProjectId_Flavor_VersionString",
                table: "ComponentVersions");

            migrationBuilder.CreateIndex(
                name: "IX_ComponentVersions_ProjectId_Flavor_VersionString_CommitSha_~",
                table: "ComponentVersions",
                columns: new[] { "ProjectId", "Flavor", "VersionString", "CommitSha", "PullRequestRef" },
                unique: true);
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropIndex(
                name: "IX_ComponentVersions_ProjectId_Flavor_VersionString_CommitSha_~",
                table: "ComponentVersions");

            migrationBuilder.CreateIndex(
                name: "IX_ComponentVersions_ProjectId_Flavor_VersionString",
                table: "ComponentVersions",
                columns: new[] { "ProjectId", "Flavor", "VersionString" },
                unique: true);
        }
    }
}
