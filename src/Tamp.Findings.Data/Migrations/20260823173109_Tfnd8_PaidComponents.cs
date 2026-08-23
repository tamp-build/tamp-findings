using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace Tamp.Findings.Data.Migrations
{
    /// <inheritdoc />
    public partial class Tfnd8_PaidComponents : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.CreateTable(
                name: "PaidComponents",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "uuid", nullable: false),
                    Vendor = table.Column<string>(type: "character varying(200)", maxLength: 200, nullable: false),
                    Product = table.Column<string>(type: "character varying(200)", maxLength: 200, nullable: false),
                    PackagePrefix = table.Column<string>(type: "character varying(200)", maxLength: 200, nullable: false),
                    Ecosystem = table.Column<string>(type: "character varying(64)", maxLength: 64, nullable: true),
                    AnnualCostPerSeat = table.Column<decimal>(type: "numeric", nullable: true),
                    Currency = table.Column<string>(type: "character varying(8)", maxLength: 8, nullable: false),
                    CostAsOf = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: true),
                    LicenseModel = table.Column<string>(type: "character varying(200)", maxLength: 200, nullable: true),
                    PricingUrl = table.Column<string>(type: "character varying(1024)", maxLength: 1024, nullable: true),
                    SupportEndsAt = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: true),
                    Notes = table.Column<string>(type: "character varying(2048)", maxLength: 2048, nullable: true),
                    IsBuiltIn = table.Column<bool>(type: "boolean", nullable: false),
                    Enabled = table.Column<bool>(type: "boolean", nullable: false),
                    UpdatedAt = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_PaidComponents", x => x.Id);
                });

            migrationBuilder.CreateIndex(
                name: "IX_PaidComponents_Ecosystem_PackagePrefix",
                table: "PaidComponents",
                columns: new[] { "Ecosystem", "PackagePrefix" },
                unique: true);
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropTable(
                name: "PaidComponents");
        }
    }
}
