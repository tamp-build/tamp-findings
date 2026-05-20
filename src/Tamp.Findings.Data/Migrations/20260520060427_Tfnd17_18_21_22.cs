using System.Collections.Generic;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace Tamp.Findings.Data.Migrations
{
    /// <inheritdoc />
    public partial class Tfnd17_18_21_22 : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AddColumn<List<Dictionary<string, string>>>(
                name: "MetadataTools",
                table: "SbomSnapshots",
                type: "jsonb",
                nullable: false,
                defaultValueSql: "'[]'::jsonb");

            migrationBuilder.AddColumn<Dictionary<string, string>>(
                name: "Hashes",
                table: "SbomComponents",
                type: "jsonb",
                nullable: false,
                defaultValueSql: "'{}'::jsonb");

            migrationBuilder.AddColumn<string>(
                name: "SubCategory",
                table: "Findings",
                type: "character varying(64)",
                maxLength: 64,
                nullable: true);
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropColumn(
                name: "MetadataTools",
                table: "SbomSnapshots");

            migrationBuilder.DropColumn(
                name: "Hashes",
                table: "SbomComponents");

            migrationBuilder.DropColumn(
                name: "SubCategory",
                table: "Findings");
        }
    }
}
