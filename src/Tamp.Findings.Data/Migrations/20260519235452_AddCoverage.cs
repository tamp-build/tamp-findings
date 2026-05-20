using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace Tamp.Findings.Data.Migrations
{
    /// <inheritdoc />
    public partial class AddCoverage : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.CreateTable(
                name: "CoverageReports",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "uuid", nullable: false),
                    ComponentVersionId = table.Column<Guid>(type: "uuid", nullable: false),
                    ToolName = table.Column<string>(type: "character varying(128)", maxLength: 128, nullable: false),
                    ToolVersion = table.Column<string>(type: "character varying(64)", maxLength: 64, nullable: true),
                    SequenceCoverage = table.Column<double>(type: "double precision", nullable: false),
                    BranchCoverage = table.Column<double>(type: "double precision", nullable: false),
                    CoveredSequences = table.Column<int>(type: "integer", nullable: false),
                    TotalSequences = table.Column<int>(type: "integer", nullable: false),
                    CoveredBranches = table.Column<int>(type: "integer", nullable: false),
                    TotalBranches = table.Column<int>(type: "integer", nullable: false),
                    IngestedAt = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_CoverageReports", x => x.Id);
                    table.ForeignKey(
                        name: "FK_CoverageReports_ComponentVersions_ComponentVersionId",
                        column: x => x.ComponentVersionId,
                        principalTable: "ComponentVersions",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateTable(
                name: "CoverageModules",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "uuid", nullable: false),
                    CoverageReportId = table.Column<Guid>(type: "uuid", nullable: false),
                    Name = table.Column<string>(type: "character varying(512)", maxLength: 512, nullable: false),
                    SequenceCoverage = table.Column<double>(type: "double precision", nullable: false),
                    BranchCoverage = table.Column<double>(type: "double precision", nullable: false),
                    CoveredSequences = table.Column<int>(type: "integer", nullable: false),
                    TotalSequences = table.Column<int>(type: "integer", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_CoverageModules", x => x.Id);
                    table.ForeignKey(
                        name: "FK_CoverageModules_CoverageReports_CoverageReportId",
                        column: x => x.CoverageReportId,
                        principalTable: "CoverageReports",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateIndex(
                name: "IX_CoverageModules_CoverageReportId_Name",
                table: "CoverageModules",
                columns: new[] { "CoverageReportId", "Name" },
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_CoverageReports_ComponentVersionId",
                table: "CoverageReports",
                column: "ComponentVersionId",
                unique: true);
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropTable(
                name: "CoverageModules");

            migrationBuilder.DropTable(
                name: "CoverageReports");
        }
    }
}
