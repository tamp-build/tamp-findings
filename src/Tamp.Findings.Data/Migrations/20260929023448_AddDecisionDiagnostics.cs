using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace Tamp.Findings.Data.Migrations
{
    /// <inheritdoc />
    public partial class AddDecisionDiagnostics : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.CreateTable(
                name: "DecisionDiagnostics",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "uuid", nullable: false),
                    ComponentVersionId = table.Column<Guid>(type: "uuid", nullable: false),
                    RuleId = table.Column<string>(type: "character varying(128)", maxLength: 128, nullable: false),
                    Kind = table.Column<string>(type: "character varying(64)", maxLength: 64, nullable: false),
                    Summary = table.Column<string>(type: "text", nullable: false),
                    Location = table.Column<string>(type: "character varying(1024)", maxLength: 1024, nullable: true),
                    CommitSha = table.Column<string>(type: "character varying(128)", maxLength: 128, nullable: true),
                    ControlRefs = table.Column<string>(type: "jsonb", nullable: false),
                    DetectedAt = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_DecisionDiagnostics", x => x.Id);
                });

            migrationBuilder.CreateIndex(
                name: "IX_DecisionDiagnostics_ComponentVersionId",
                table: "DecisionDiagnostics",
                column: "ComponentVersionId");

            migrationBuilder.CreateIndex(
                name: "IX_DecisionDiagnostics_ComponentVersionId_RuleId_Location",
                table: "DecisionDiagnostics",
                columns: new[] { "ComponentVersionId", "RuleId", "Location" });
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropTable(
                name: "DecisionDiagnostics");
        }
    }
}
