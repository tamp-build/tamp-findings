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

            migrationBuilder.AddColumn<List<string>>(
                name: "ExpectedScanners",
                table: "InstanceSettings",
                type: "text[]",
                nullable: false);

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
