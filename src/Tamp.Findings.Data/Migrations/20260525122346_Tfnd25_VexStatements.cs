using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace Tamp.Findings.Data.Migrations
{
    /// <inheritdoc />
    public partial class Tfnd25_VexStatements : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.CreateTable(
                name: "VexStatements",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "uuid", nullable: false),
                    ProjectId = table.Column<Guid>(type: "uuid", nullable: false),
                    Purl = table.Column<string>(type: "character varying(1024)", maxLength: 1024, nullable: false),
                    ComponentVersion = table.Column<string>(type: "character varying(128)", maxLength: 128, nullable: true),
                    AdvisoryId = table.Column<string>(type: "character varying(64)", maxLength: 64, nullable: false),
                    Status = table.Column<int>(type: "integer", nullable: false),
                    Justification = table.Column<int>(type: "integer", nullable: true),
                    ImpactStatement = table.Column<string>(type: "text", nullable: true),
                    ResponseReferenceUrl = table.Column<string>(type: "character varying(1024)", maxLength: 1024, nullable: true),
                    AuthorUserId = table.Column<Guid>(type: "uuid", nullable: false),
                    CreatedAt = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false),
                    UpdatedAt = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false),
                    RetiredAt = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_VexStatements", x => x.Id);
                    table.ForeignKey(
                        name: "FK_VexStatements_Projects_ProjectId",
                        column: x => x.ProjectId,
                        principalTable: "Projects",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateIndex(
                name: "IX_VexStatements_ProjectId_AdvisoryId_Purl",
                table: "VexStatements",
                columns: new[] { "ProjectId", "AdvisoryId", "Purl" });

            migrationBuilder.CreateIndex(
                name: "IX_VexStatements_RetiredAt",
                table: "VexStatements",
                column: "RetiredAt");
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropTable(
                name: "VexStatements");
        }
    }
}
