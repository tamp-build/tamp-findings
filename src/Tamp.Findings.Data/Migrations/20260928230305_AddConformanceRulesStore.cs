using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace Tamp.Findings.Data.Migrations
{
    /// <inheritdoc />
    public partial class AddConformanceRulesStore : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.CreateTable(
                name: "ConformanceRules",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "uuid", nullable: false),
                    ProjectId = table.Column<Guid>(type: "uuid", nullable: false),
                    AdrRef = table.Column<string>(type: "character varying(64)", maxLength: 64, nullable: false),
                    RuleId = table.Column<string>(type: "character varying(128)", maxLength: 128, nullable: false),
                    Intent = table.Column<string>(type: "text", nullable: true),
                    Method = table.Column<int>(type: "integer", nullable: false),
                    CheckSpec = table.Column<string>(type: "text", nullable: true),
                    ControlRefs = table.Column<string>(type: "jsonb", nullable: false),
                    ZtPillar = table.Column<string>(type: "character varying(128)", maxLength: 128, nullable: true),
                    ZtFunction = table.Column<string>(type: "character varying(128)", maxLength: 128, nullable: true),
                    ZtStage = table.Column<int>(type: "integer", nullable: true),
                    MandateId = table.Column<string>(type: "character varying(128)", maxLength: 128, nullable: true),
                    RulesSha = table.Column<string>(type: "character varying(128)", maxLength: 128, nullable: true),
                    ExtractionModelId = table.Column<string>(type: "character varying(128)", maxLength: 128, nullable: true),
                    ReviewStatus = table.Column<int>(type: "integer", nullable: false),
                    PushedAt = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false),
                    RetiredAt = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_ConformanceRules", x => x.Id);
                    table.ForeignKey(
                        name: "FK_ConformanceRules_Projects_ProjectId",
                        column: x => x.ProjectId,
                        principalTable: "Projects",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateIndex(
                name: "IX_ConformanceRules_ProjectId_AdrRef_RuleId",
                table: "ConformanceRules",
                columns: new[] { "ProjectId", "AdrRef", "RuleId" },
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_ConformanceRules_ProjectId_RetiredAt",
                table: "ConformanceRules",
                columns: new[] { "ProjectId", "RetiredAt" });
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropTable(
                name: "ConformanceRules");
        }
    }
}
