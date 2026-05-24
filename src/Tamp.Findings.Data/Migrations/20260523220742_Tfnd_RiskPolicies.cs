using System;
using Microsoft.EntityFrameworkCore.Migrations;
using Tamp.Findings.Domain.Entities;

#nullable disable

namespace Tamp.Findings.Data.Migrations
{
    /// <inheritdoc />
    public partial class Tfnd_RiskPolicies : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AddColumn<Guid>(
                name: "RiskPolicyId",
                table: "Projects",
                type: "uuid",
                nullable: true);

            migrationBuilder.AddColumn<Guid>(
                name: "RiskPolicyId",
                table: "Clients",
                type: "uuid",
                nullable: true);

            migrationBuilder.CreateTable(
                name: "RiskPolicies",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "uuid", nullable: false),
                    Name = table.Column<string>(type: "character varying(256)", maxLength: 256, nullable: false),
                    Description = table.Column<string>(type: "character varying(2048)", maxLength: 2048, nullable: true),
                    IsDefault = table.Column<bool>(type: "boolean", nullable: false),
                    IsSeeded = table.Column<bool>(type: "boolean", nullable: false),
                    Config = table.Column<RiskPolicyConfig>(type: "jsonb", nullable: false),
                    CreatedByUserId = table.Column<Guid>(type: "uuid", nullable: true),
                    CreatedAt = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false),
                    UpdatedAt = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_RiskPolicies", x => x.Id);
                });

            migrationBuilder.CreateIndex(
                name: "IX_Projects_RiskPolicyId",
                table: "Projects",
                column: "RiskPolicyId");

            migrationBuilder.CreateIndex(
                name: "IX_Clients_RiskPolicyId",
                table: "Clients",
                column: "RiskPolicyId");

            migrationBuilder.CreateIndex(
                name: "IX_RiskPolicies_IsDefault",
                table: "RiskPolicies",
                column: "IsDefault",
                unique: true,
                filter: "\"IsDefault\" = true");

            migrationBuilder.CreateIndex(
                name: "IX_RiskPolicies_Name",
                table: "RiskPolicies",
                column: "Name",
                unique: true);

            migrationBuilder.AddForeignKey(
                name: "FK_Clients_RiskPolicies_RiskPolicyId",
                table: "Clients",
                column: "RiskPolicyId",
                principalTable: "RiskPolicies",
                principalColumn: "Id",
                onDelete: ReferentialAction.SetNull);

            migrationBuilder.AddForeignKey(
                name: "FK_Projects_RiskPolicies_RiskPolicyId",
                table: "Projects",
                column: "RiskPolicyId",
                principalTable: "RiskPolicies",
                principalColumn: "Id",
                onDelete: ReferentialAction.SetNull);
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropForeignKey(
                name: "FK_Clients_RiskPolicies_RiskPolicyId",
                table: "Clients");

            migrationBuilder.DropForeignKey(
                name: "FK_Projects_RiskPolicies_RiskPolicyId",
                table: "Projects");

            migrationBuilder.DropTable(
                name: "RiskPolicies");

            migrationBuilder.DropIndex(
                name: "IX_Projects_RiskPolicyId",
                table: "Projects");

            migrationBuilder.DropIndex(
                name: "IX_Clients_RiskPolicyId",
                table: "Clients");

            migrationBuilder.DropColumn(
                name: "RiskPolicyId",
                table: "Projects");

            migrationBuilder.DropColumn(
                name: "RiskPolicyId",
                table: "Clients");
        }
    }
}
