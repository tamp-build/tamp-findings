using System.Collections.Generic;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace Tamp.Findings.Data.Migrations
{
    /// <inheritdoc />
    public partial class Tfnd113_InstanceSettings : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AddColumn<int>(
                name: "BuildRetentionDays",
                table: "InstanceSettings",
                type: "integer",
                nullable: true);

            // defaultValueSql, added retroactively: without it this migration
            // FAILS on any instance that already has an InstanceSettings row —
            // and every instance does, because TFND-72 created one for the
            // separation-of-duties switch. Postgres refuses to add a NOT NULL
            // column with no default to a populated table.
            //
            // It slipped through because the test database happened to have no
            // settings row when the migration first ran. Corrected in place
            // rather than by a follow-up migration: this one has never run
            // against a real deployment, and a second migration to fix the
            // first would leave the broken statement in the history for anyone
            // restoring from an older snapshot.
            migrationBuilder.AddColumn<List<string>>(
                name: "ExpectedScanners",
                table: "InstanceSettings",
                type: "text[]",
                nullable: false,
                defaultValueSql: "'{}'::text[]");

            migrationBuilder.AddColumn<int>(
                name: "FindingRetentionDays",
                table: "InstanceSettings",
                type: "integer",
                nullable: true);

            migrationBuilder.AddColumn<string>(
                name: "InstanceUrl",
                table: "InstanceSettings",
                type: "character varying(512)",
                maxLength: 512,
                nullable: true);

            migrationBuilder.AddColumn<int>(
                name: "SessionLifetimeHours",
                table: "InstanceSettings",
                type: "integer",
                nullable: false,
                defaultValue: 0);

            migrationBuilder.AddColumn<string>(
                name: "SmtpFrom",
                table: "InstanceSettings",
                type: "character varying(256)",
                maxLength: 256,
                nullable: true);

            migrationBuilder.AddColumn<string>(
                name: "SmtpHost",
                table: "InstanceSettings",
                type: "character varying(256)",
                maxLength: 256,
                nullable: true);

            migrationBuilder.AddColumn<int>(
                name: "SmtpPort",
                table: "InstanceSettings",
                type: "integer",
                nullable: true);
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropColumn(
                name: "BuildRetentionDays",
                table: "InstanceSettings");

            migrationBuilder.DropColumn(
                name: "ExpectedScanners",
                table: "InstanceSettings");

            migrationBuilder.DropColumn(
                name: "FindingRetentionDays",
                table: "InstanceSettings");

            migrationBuilder.DropColumn(
                name: "InstanceUrl",
                table: "InstanceSettings");

            migrationBuilder.DropColumn(
                name: "SessionLifetimeHours",
                table: "InstanceSettings");

            migrationBuilder.DropColumn(
                name: "SmtpFrom",
                table: "InstanceSettings");

            migrationBuilder.DropColumn(
                name: "SmtpHost",
                table: "InstanceSettings");

            migrationBuilder.DropColumn(
                name: "SmtpPort",
                table: "InstanceSettings");
        }
    }
}
