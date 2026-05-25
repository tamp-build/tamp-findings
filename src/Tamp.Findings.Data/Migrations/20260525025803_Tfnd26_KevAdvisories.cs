using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace Tamp.Findings.Data.Migrations
{
    /// <inheritdoc />
    public partial class Tfnd26_KevAdvisories : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.CreateTable(
                name: "KevAdvisories",
                columns: table => new
                {
                    CveId = table.Column<string>(type: "character varying(64)", maxLength: 64, nullable: false),
                    VendorProject = table.Column<string>(type: "character varying(256)", maxLength: 256, nullable: true),
                    Product = table.Column<string>(type: "character varying(256)", maxLength: 256, nullable: true),
                    VulnerabilityName = table.Column<string>(type: "character varying(512)", maxLength: 512, nullable: true),
                    DateAdded = table.Column<DateOnly>(type: "date", nullable: false),
                    DueDate = table.Column<DateOnly>(type: "date", nullable: false),
                    ShortDescription = table.Column<string>(type: "text", nullable: true),
                    RequiredAction = table.Column<string>(type: "text", nullable: true),
                    KnownRansomwareCampaignUse = table.Column<bool>(type: "boolean", nullable: false),
                    Notes = table.Column<string>(type: "text", nullable: true),
                    LastSyncedAt = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_KevAdvisories", x => x.CveId);
                });

            migrationBuilder.CreateIndex(
                name: "IX_KevAdvisories_DueDate",
                table: "KevAdvisories",
                column: "DueDate");

            migrationBuilder.CreateIndex(
                name: "IX_KevAdvisories_KnownRansomwareCampaignUse",
                table: "KevAdvisories",
                column: "KnownRansomwareCampaignUse");
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropTable(
                name: "KevAdvisories");
        }
    }
}
