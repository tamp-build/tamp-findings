using System;
using System.Collections.Generic;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace Tamp.Findings.Data.Migrations
{
    /// <inheritdoc />
    public partial class Tfnd29_SbomProvenance : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AddColumn<Dictionary<string, object>>(
                name: "ProvenanceJson",
                table: "SbomSnapshots",
                type: "jsonb",
                nullable: true);

            migrationBuilder.AddColumn<string>(
                name: "ProvenanceType",
                table: "SbomSnapshots",
                type: "character varying(256)",
                maxLength: 256,
                nullable: true);

            migrationBuilder.AddColumn<DateTimeOffset>(
                name: "ProvenanceUploadedAt",
                table: "SbomSnapshots",
                type: "timestamp with time zone",
                nullable: true);
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropColumn(
                name: "ProvenanceJson",
                table: "SbomSnapshots");

            migrationBuilder.DropColumn(
                name: "ProvenanceType",
                table: "SbomSnapshots");

            migrationBuilder.DropColumn(
                name: "ProvenanceUploadedAt",
                table: "SbomSnapshots");
        }
    }
}
