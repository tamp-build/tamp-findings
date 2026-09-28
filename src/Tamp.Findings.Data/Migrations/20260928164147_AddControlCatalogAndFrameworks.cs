using System;
using System.Collections.Generic;
using Microsoft.EntityFrameworkCore.Migrations;
using Tamp.Findings.Domain.Compliance;

#nullable disable

namespace Tamp.Findings.Data.Migrations
{
    /// <inheritdoc />
    public partial class AddControlCatalogAndFrameworks : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.CreateTable(
                name: "ControlCatalogs",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "uuid", nullable: false),
                    Name = table.Column<string>(type: "character varying(256)", maxLength: 256, nullable: false),
                    Source = table.Column<string>(type: "character varying(512)", maxLength: 512, nullable: false),
                    Version = table.Column<string>(type: "character varying(64)", maxLength: 64, nullable: false),
                    OscalVersion = table.Column<string>(type: "text", nullable: true),
                    ImportedSha = table.Column<string>(type: "text", nullable: true),
                    IsSeeded = table.Column<bool>(type: "boolean", nullable: false),
                    IsCurrent = table.Column<bool>(type: "boolean", nullable: false),
                    ImportedAt = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false),
                    Controls = table.Column<List<Control>>(type: "jsonb", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_ControlCatalogs", x => x.Id);
                });

            migrationBuilder.CreateTable(
                name: "Frameworks",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "uuid", nullable: false),
                    Slug = table.Column<string>(type: "character varying(64)", maxLength: 64, nullable: false),
                    Name = table.Column<string>(type: "character varying(256)", maxLength: 256, nullable: false),
                    Kind = table.Column<int>(type: "integer", nullable: false),
                    Source = table.Column<string>(type: "character varying(512)", maxLength: 512, nullable: false),
                    Version = table.Column<string>(type: "character varying(64)", maxLength: 64, nullable: false),
                    ControlCountLabel = table.Column<string>(type: "text", nullable: true),
                    ParamsLabel = table.Column<string>(type: "text", nullable: true),
                    Status = table.Column<int>(type: "integer", nullable: false),
                    IsSeeded = table.Column<bool>(type: "boolean", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_Frameworks", x => x.Id);
                });

            migrationBuilder.CreateIndex(
                name: "IX_ControlCatalogs_IsCurrent",
                table: "ControlCatalogs",
                column: "IsCurrent",
                unique: true,
                filter: "\"IsCurrent\" = true");

            migrationBuilder.CreateIndex(
                name: "IX_Frameworks_Slug",
                table: "Frameworks",
                column: "Slug",
                unique: true);
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropTable(
                name: "ControlCatalogs");

            migrationBuilder.DropTable(
                name: "Frameworks");
        }
    }
}
