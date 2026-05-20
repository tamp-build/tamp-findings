using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace Tamp.Findings.Data.Migrations
{
    /// <inheritdoc />
    public partial class AddCoverageClassesAndSources : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.CreateTable(
                name: "CoverageSourceFiles",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "uuid", nullable: false),
                    CoverageReportId = table.Column<Guid>(type: "uuid", nullable: false),
                    RelativePath = table.Column<string>(type: "character varying(1024)", maxLength: 1024, nullable: false),
                    AbsolutePath = table.Column<string>(type: "character varying(1024)", maxLength: 1024, nullable: true),
                    SourceText = table.Column<string>(type: "text", nullable: false),
                    LineCount = table.Column<int>(type: "integer", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_CoverageSourceFiles", x => x.Id);
                    table.ForeignKey(
                        name: "FK_CoverageSourceFiles_CoverageReports_CoverageReportId",
                        column: x => x.CoverageReportId,
                        principalTable: "CoverageReports",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateTable(
                name: "CoverageClasses",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "uuid", nullable: false),
                    CoverageModuleId = table.Column<Guid>(type: "uuid", nullable: false),
                    CoverageSourceFileId = table.Column<Guid>(type: "uuid", nullable: false),
                    FullName = table.Column<string>(type: "character varying(1024)", maxLength: 1024, nullable: false),
                    SequenceCoverage = table.Column<double>(type: "double precision", nullable: false),
                    BranchCoverage = table.Column<double>(type: "double precision", nullable: false),
                    CoveredSequences = table.Column<int>(type: "integer", nullable: false),
                    TotalSequences = table.Column<int>(type: "integer", nullable: false),
                    CoveredBranches = table.Column<int>(type: "integer", nullable: false),
                    TotalBranches = table.Column<int>(type: "integer", nullable: false),
                    VisitedLines = table.Column<int[]>(type: "integer[]", nullable: false),
                    UnvisitedLines = table.Column<int[]>(type: "integer[]", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_CoverageClasses", x => x.Id);
                    table.ForeignKey(
                        name: "FK_CoverageClasses_CoverageModules_CoverageModuleId",
                        column: x => x.CoverageModuleId,
                        principalTable: "CoverageModules",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Cascade);
                    table.ForeignKey(
                        name: "FK_CoverageClasses_CoverageSourceFiles_CoverageSourceFileId",
                        column: x => x.CoverageSourceFileId,
                        principalTable: "CoverageSourceFiles",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateIndex(
                name: "IX_CoverageClasses_CoverageModuleId_FullName_CoverageSourceFil~",
                table: "CoverageClasses",
                columns: new[] { "CoverageModuleId", "FullName", "CoverageSourceFileId" },
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_CoverageClasses_CoverageSourceFileId",
                table: "CoverageClasses",
                column: "CoverageSourceFileId");

            migrationBuilder.CreateIndex(
                name: "IX_CoverageSourceFiles_CoverageReportId_RelativePath",
                table: "CoverageSourceFiles",
                columns: new[] { "CoverageReportId", "RelativePath" },
                unique: true);
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropTable(
                name: "CoverageClasses");

            migrationBuilder.DropTable(
                name: "CoverageSourceFiles");
        }
    }
}
