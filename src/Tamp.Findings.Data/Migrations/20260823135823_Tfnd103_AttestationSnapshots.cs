using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace Tamp.Findings.Data.Migrations
{
    /// <inheritdoc />
    public partial class Tfnd103_AttestationSnapshots : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.CreateTable(
                name: "AttestationSnapshots",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "uuid", nullable: false),
                    ProjectId = table.Column<Guid>(type: "uuid", nullable: false),
                    CommitSha = table.Column<string>(type: "character varying(64)", maxLength: 64, nullable: false),
                    DocumentJson = table.Column<string>(type: "jsonb", nullable: false),
                    RiskPolicyId = table.Column<Guid>(type: "uuid", nullable: true),
                    RiskPolicyName = table.Column<string>(type: "character varying(128)", maxLength: 128, nullable: false),
                    Score = table.Column<double>(type: "double precision", nullable: false),
                    Band = table.Column<string>(type: "character varying(32)", maxLength: 32, nullable: false),
                    GeneratedByUserId = table.Column<Guid>(type: "uuid", nullable: false),
                    GeneratedAt = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false),
                    SignedAt = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: true),
                    SignedBy = table.Column<string>(type: "character varying(256)", maxLength: 256, nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_AttestationSnapshots", x => x.Id);
                });

            migrationBuilder.CreateIndex(
                name: "IX_AttestationSnapshots_ProjectId_CommitSha_GeneratedAt",
                table: "AttestationSnapshots",
                columns: new[] { "ProjectId", "CommitSha", "GeneratedAt" });
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropTable(
                name: "AttestationSnapshots");
        }
    }
}
