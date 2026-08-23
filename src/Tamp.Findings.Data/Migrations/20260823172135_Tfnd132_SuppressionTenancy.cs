using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace Tamp.Findings.Data.Migrations
{
    /// <inheritdoc />
    public partial class Tfnd132_SuppressionTenancy : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AddColumn<Guid>(
                name: "ClientId",
                table: "Suppressions",
                type: "uuid",
                nullable: true);

            migrationBuilder.AddColumn<Guid>(
                name: "ProjectId",
                table: "Suppressions",
                type: "uuid",
                nullable: true);

            migrationBuilder.CreateIndex(
                name: "IX_Suppressions_ClientId_ProjectId",
                table: "Suppressions",
                columns: new[] { "ClientId", "ProjectId" });

            // Backfill the rows whose tenant is DERIVABLE, and only those.
            //
            // SingleFinding and RuleOnComponent are anchored by their subject,
            // so walking up to the project and client recovers a fact rather
            // than inventing one.
            //
            // RuleOnFile and RuleEverywhere are deliberately left null. There
            // is no record of which client asked for them — that absence IS the
            // defect — and attributing them to, say, the author's first client
            // would turn a known unknown into a wrong answer that reads as
            // authoritative. Null means "instance-wide, provenance unknown";
            // SuppressionMatcher keeps their old behaviour, so nothing anyone
            // has already signed off silently un-suppresses, and the set only
            // shrinks as they expire or are replaced.
            migrationBuilder.Sql("""
                UPDATE "Suppressions" s
                SET "ClientId" = p."ClientId", "ProjectId" = p."Id"
                FROM "Findings" f
                JOIN "ComponentVersions" cv ON cv."Id" = f."ComponentVersionId"
                JOIN "Components" c ON c."Id" = cv."ComponentId"
                JOIN "Projects" p ON p."Id" = c."ProjectId"
                WHERE s."FindingId" = f."Id" AND s."ClientId" IS NULL;
                """);

            migrationBuilder.Sql("""
                UPDATE "Suppressions" s
                SET "ClientId" = p."ClientId", "ProjectId" = p."Id"
                FROM "Components" c
                JOIN "Projects" p ON p."Id" = c."ProjectId"
                WHERE s."ComponentId" = c."Id" AND s."ClientId" IS NULL;
                """);
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropIndex(
                name: "IX_Suppressions_ClientId_ProjectId",
                table: "Suppressions");

            migrationBuilder.DropColumn(
                name: "ClientId",
                table: "Suppressions");

            migrationBuilder.DropColumn(
                name: "ProjectId",
                table: "Suppressions");
        }
    }
}
