using System;
using System.Collections.Generic;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace Tamp.Findings.Data.Migrations
{
    /// <inheritdoc />
    public partial class AddScoreSnapshot : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.CreateTable(
                name: "ScoreSnapshots",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "uuid", nullable: false),
                    ProjectId = table.Column<Guid>(type: "uuid", nullable: false),
                    CommitSha = table.Column<string>(type: "character varying(128)", maxLength: 128, nullable: false),
                    Score = table.Column<double>(type: "double precision", nullable: false),
                    Band = table.Column<string>(type: "character varying(32)", maxLength: 32, nullable: true),
                    CoveragePercent = table.Column<double>(type: "double precision", nullable: true),
                    Breakdown = table.Column<Dictionary<string, double>>(type: "jsonb", nullable: false),
                    BuiltAt = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false),
                    ComputedAt = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false),
                    PolicyName = table.Column<string>(type: "character varying(256)", maxLength: 256, nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_ScoreSnapshots", x => x.Id);
                });

            migrationBuilder.CreateIndex(
                name: "IX_ScoreSnapshots_ProjectId_BuiltAt",
                table: "ScoreSnapshots",
                columns: new[] { "ProjectId", "BuiltAt" });

            migrationBuilder.CreateIndex(
                name: "IX_ScoreSnapshots_ProjectId_CommitSha",
                table: "ScoreSnapshots",
                columns: new[] { "ProjectId", "CommitSha" },
                unique: true);
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropTable(
                name: "ScoreSnapshots");
        }
    }
}
