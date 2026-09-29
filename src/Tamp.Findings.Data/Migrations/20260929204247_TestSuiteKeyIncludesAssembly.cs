using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace Tamp.Findings.Data.Migrations
{
    /// <inheritdoc />
    public partial class TestSuiteKeyIncludesAssembly : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropIndex(
                name: "IX_TestSuiteResults_TestRunReportId_ClassName",
                table: "TestSuiteResults");

            migrationBuilder.CreateIndex(
                name: "IX_TestSuiteResults_TestRunReportId_AssemblyName_ClassName",
                table: "TestSuiteResults",
                columns: new[] { "TestRunReportId", "AssemblyName", "ClassName" },
                unique: true);
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropIndex(
                name: "IX_TestSuiteResults_TestRunReportId_AssemblyName_ClassName",
                table: "TestSuiteResults");

            migrationBuilder.CreateIndex(
                name: "IX_TestSuiteResults_TestRunReportId_ClassName",
                table: "TestSuiteResults",
                columns: new[] { "TestRunReportId", "ClassName" },
                unique: true);
        }
    }
}
