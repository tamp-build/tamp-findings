using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace Tamp.Findings.Data.Migrations
{
    /// <inheritdoc />
    public partial class AddQualityIntake : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AddColumn<string>(
                name: "GateDetails",
                table: "ScanRunReceipts",
                type: "character varying(4096)",
                maxLength: 4096,
                nullable: true);

            migrationBuilder.AddColumn<string>(
                name: "GateStatus",
                table: "ScanRunReceipts",
                type: "character varying(16)",
                maxLength: 16,
                nullable: true);

            migrationBuilder.CreateTable(
                name: "AnalysisCoverageReports",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "uuid", nullable: false),
                    ComponentVersionId = table.Column<Guid>(type: "uuid", nullable: false),
                    ObservedAt = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false),
                    IngestedAt = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_AnalysisCoverageReports", x => x.Id);
                    table.ForeignKey(
                        name: "FK_AnalysisCoverageReports_ComponentVersions_ComponentVersionId",
                        column: x => x.ComponentVersionId,
                        principalTable: "ComponentVersions",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateTable(
                name: "AnalysisCoverageLanguages",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "uuid", nullable: false),
                    AnalysisCoverageReportId = table.Column<Guid>(type: "uuid", nullable: false),
                    Language = table.Column<string>(type: "character varying(64)", maxLength: 64, nullable: false),
                    FilesTotal = table.Column<int>(type: "integer", nullable: false),
                    FilesAnalyzed = table.Column<int>(type: "integer", nullable: false),
                    LinesTotal = table.Column<long>(type: "bigint", nullable: false),
                    LinesAnalyzed = table.Column<long>(type: "bigint", nullable: false),
                    AnalyzedBy = table.Column<string>(type: "character varying(256)", maxLength: 256, nullable: true),
                    PercentAnalyzed = table.Column<double>(type: "double precision", nullable: false),
                    UnanalyzedSample = table.Column<string>(type: "character varying(4096)", maxLength: 4096, nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_AnalysisCoverageLanguages", x => x.Id);
                    table.ForeignKey(
                        name: "FK_AnalysisCoverageLanguages_AnalysisCoverageReports_AnalysisC~",
                        column: x => x.AnalysisCoverageReportId,
                        principalTable: "AnalysisCoverageReports",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateIndex(
                name: "IX_AnalysisCoverageLanguages_AnalysisCoverageReportId_Language",
                table: "AnalysisCoverageLanguages",
                columns: new[] { "AnalysisCoverageReportId", "Language" });

            migrationBuilder.CreateIndex(
                name: "IX_AnalysisCoverageReports_ComponentVersionId",
                table: "AnalysisCoverageReports",
                column: "ComponentVersionId",
                unique: true);
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropTable(
                name: "AnalysisCoverageLanguages");

            migrationBuilder.DropTable(
                name: "AnalysisCoverageReports");

            migrationBuilder.DropColumn(
                name: "GateDetails",
                table: "ScanRunReceipts");

            migrationBuilder.DropColumn(
                name: "GateStatus",
                table: "ScanRunReceipts");
        }
    }
}
