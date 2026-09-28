using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace Tamp.Findings.Data.Migrations
{
    /// <inheritdoc />
    public partial class AddFrameworkAssignment : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AddColumn<int>(
                name: "Baseline",
                table: "Frameworks",
                type: "integer",
                nullable: false,
                defaultValue: 0);

            migrationBuilder.AddColumn<Guid>(
                name: "FrameworkId",
                table: "Clients",
                type: "uuid",
                nullable: true);

            migrationBuilder.CreateIndex(
                name: "IX_Clients_FrameworkId",
                table: "Clients",
                column: "FrameworkId");

            migrationBuilder.AddForeignKey(
                name: "FK_Clients_Frameworks_FrameworkId",
                table: "Clients",
                column: "FrameworkId",
                principalTable: "Frameworks",
                principalColumn: "Id",
                onDelete: ReferentialAction.SetNull);
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropForeignKey(
                name: "FK_Clients_Frameworks_FrameworkId",
                table: "Clients");

            migrationBuilder.DropIndex(
                name: "IX_Clients_FrameworkId",
                table: "Clients");

            migrationBuilder.DropColumn(
                name: "Baseline",
                table: "Frameworks");

            migrationBuilder.DropColumn(
                name: "FrameworkId",
                table: "Clients");
        }
    }
}
