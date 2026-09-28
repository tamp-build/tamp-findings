using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace Tamp.Findings.Data.Migrations
{
    /// <inheritdoc />
    public partial class AddConformanceFindings : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.CreateTable(
                name: "ConformanceFindings",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "uuid", nullable: false),
                    ComponentVersionId = table.Column<Guid>(type: "uuid", nullable: false),
                    AdrRef = table.Column<string>(type: "character varying(64)", maxLength: 64, nullable: false),
                    RuleId = table.Column<string>(type: "character varying(128)", maxLength: 128, nullable: false),
                    Claim = table.Column<string>(type: "text", nullable: false),
                    Verdict = table.Column<int>(type: "integer", nullable: false),
                    Method = table.Column<int>(type: "integer", nullable: false),
                    AdrQuote = table.Column<string>(type: "text", nullable: true),
                    CodeEvidence = table.Column<string>(type: "text", nullable: true),
                    Location = table.Column<string>(type: "text", nullable: true),
                    CommitSha = table.Column<string>(type: "text", nullable: true),
                    RulesSha = table.Column<string>(type: "text", nullable: true),
                    ModelId = table.Column<string>(type: "text", nullable: true),
                    VerifyVerdict = table.Column<int>(type: "integer", nullable: false),
                    ControlRefs = table.Column<string>(type: "jsonb", nullable: false),
                    Dispositioned = table.Column<bool>(type: "boolean", nullable: false),
                    DispositionJustification = table.Column<string>(type: "text", nullable: true),
                    DispositionedByLogin = table.Column<string>(type: "text", nullable: true),
                    DispositionExpiry = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: true),
                    EvaluatedAt = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_ConformanceFindings", x => x.Id);
                });

            migrationBuilder.CreateIndex(
                name: "IX_ConformanceFindings_ComponentVersionId",
                table: "ConformanceFindings",
                column: "ComponentVersionId");
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropTable(
                name: "ConformanceFindings");
        }
    }
}
