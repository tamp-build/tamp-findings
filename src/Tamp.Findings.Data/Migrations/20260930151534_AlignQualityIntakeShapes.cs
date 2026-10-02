using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace Tamp.Findings.Data.Migrations
{
    /// <inheritdoc />
    public partial class AlignQualityIntakeShapes : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AddColumn<string>(
                name: "Source",
                table: "Findings",
                type: "text",
                nullable: true);

            migrationBuilder.AddColumn<string>(
                name: "Excludes",
                table: "AnalysisCoverageReports",
                type: "character varying(4096)",
                maxLength: 4096,
                nullable: true);

            migrationBuilder.AddColumn<string>(
                name: "GapLanguages",
                table: "AnalysisCoverageReports",
                type: "character varying(1024)",
                maxLength: 1024,
                nullable: true);

            migrationBuilder.CreateTable(
                name: "QualityGateResults",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "uuid", nullable: false),
                    ComponentVersionId = table.Column<Guid>(type: "uuid", nullable: false),
                    Status = table.Column<string>(type: "character varying(16)", maxLength: 16, nullable: false),
                    ConditionsJson = table.Column<string>(type: "text", nullable: true),
                    MeasuresJson = table.Column<string>(type: "text", nullable: true),
                    AnalysisId = table.Column<string>(type: "character varying(128)", maxLength: 128, nullable: true),
                    Source = table.Column<string>(type: "character varying(256)", maxLength: 256, nullable: true),
                    ObservedAt = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false),
                    IngestedAt = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_QualityGateResults", x => x.Id);
                    table.ForeignKey(
                        name: "FK_QualityGateResults_ComponentVersions_ComponentVersionId",
                        column: x => x.ComponentVersionId,
                        principalTable: "ComponentVersions",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateIndex(
                name: "IX_QualityGateResults_ComponentVersionId",
                table: "QualityGateResults",
                column: "ComponentVersionId",
                unique: true);
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropTable(
                name: "QualityGateResults");

            migrationBuilder.DropColumn(
                name: "Source",
                table: "Findings");

            migrationBuilder.DropColumn(
                name: "Excludes",
                table: "AnalysisCoverageReports");

            migrationBuilder.DropColumn(
                name: "GapLanguages",
                table: "AnalysisCoverageReports");
        }
    }
}
