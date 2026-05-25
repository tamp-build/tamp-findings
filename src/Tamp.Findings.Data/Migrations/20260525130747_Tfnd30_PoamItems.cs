using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace Tamp.Findings.Data.Migrations
{
    /// <inheritdoc />
    public partial class Tfnd30_PoamItems : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.CreateTable(
                name: "PoamItems",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "uuid", nullable: false),
                    ProjectId = table.Column<Guid>(type: "uuid", nullable: false),
                    Title = table.Column<string>(type: "character varying(512)", maxLength: 512, nullable: false),
                    WeaknessDescription = table.Column<string>(type: "text", nullable: false),
                    MitigationPlan = table.Column<string>(type: "text", nullable: true),
                    ResourcesRequired = table.Column<string>(type: "character varying(2048)", maxLength: 2048, nullable: true),
                    Severity = table.Column<int>(type: "integer", nullable: false),
                    Status = table.Column<int>(type: "integer", nullable: false),
                    ScheduledCompletionDate = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: true),
                    ActualCompletionDate = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: true),
                    LinkedFindingIds = table.Column<string>(type: "jsonb", nullable: false),
                    ReferenceUrl = table.Column<string>(type: "character varying(1024)", maxLength: 1024, nullable: true),
                    AuthorUserId = table.Column<Guid>(type: "uuid", nullable: false),
                    CreatedAt = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false),
                    UpdatedAt = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false),
                    ClosedAt = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_PoamItems", x => x.Id);
                    table.ForeignKey(
                        name: "FK_PoamItems_Projects_ProjectId",
                        column: x => x.ProjectId,
                        principalTable: "Projects",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateIndex(
                name: "IX_PoamItems_ClosedAt",
                table: "PoamItems",
                column: "ClosedAt");

            migrationBuilder.CreateIndex(
                name: "IX_PoamItems_ProjectId_Status_ScheduledCompletionDate",
                table: "PoamItems",
                columns: new[] { "ProjectId", "Status", "ScheduledCompletionDate" });
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropTable(
                name: "PoamItems");
        }
    }
}
