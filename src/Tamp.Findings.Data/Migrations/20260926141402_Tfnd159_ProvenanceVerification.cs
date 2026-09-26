using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace Tamp.Findings.Data.Migrations
{
    /// <inheritdoc />
    public partial class Tfnd159_ProvenanceVerification : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AddColumn<string>(
                name: "ProvenanceVerificationMethod",
                table: "SbomSnapshots",
                type: "text",
                nullable: true);

            migrationBuilder.AddColumn<bool>(
                name: "ProvenanceVerified",
                table: "SbomSnapshots",
                type: "boolean",
                nullable: false,
                defaultValue: false);

            migrationBuilder.AddColumn<DateTimeOffset>(
                name: "ProvenanceVerifiedAt",
                table: "SbomSnapshots",
                type: "timestamp with time zone",
                nullable: true);
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropColumn(
                name: "ProvenanceVerificationMethod",
                table: "SbomSnapshots");

            migrationBuilder.DropColumn(
                name: "ProvenanceVerified",
                table: "SbomSnapshots");

            migrationBuilder.DropColumn(
                name: "ProvenanceVerifiedAt",
                table: "SbomSnapshots");
        }
    }
}
