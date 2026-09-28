using System;
using Microsoft.EntityFrameworkCore.Migrations;
using Tamp.Findings.Domain.Risk;

#nullable disable

namespace Tamp.Findings.Data.Migrations
{
    /// <inheritdoc />
    public partial class AddThreeLayerPolicy : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AddColumn<PolicyLayer>(
                name: "PolicyLayer",
                table: "Projects",
                type: "jsonb",
                nullable: true);

            migrationBuilder.AddColumn<PolicyLayer>(
                name: "PolicyLayer",
                table: "Clients",
                type: "jsonb",
                nullable: true);

            migrationBuilder.AddColumn<Guid>(
                name: "PolicyTemplateId",
                table: "Clients",
                type: "uuid",
                nullable: true);

            migrationBuilder.CreateTable(
                name: "PolicyTemplates",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "uuid", nullable: false),
                    Name = table.Column<string>(type: "character varying(256)", maxLength: 256, nullable: false),
                    Version = table.Column<int>(type: "integer", nullable: false),
                    IsSeeded = table.Column<bool>(type: "boolean", nullable: false),
                    Layer = table.Column<PolicyLayer>(type: "jsonb", nullable: false),
                    RiskPolicyId = table.Column<Guid>(type: "uuid", nullable: true),
                    CreatedByLogin = table.Column<string>(type: "character varying(256)", maxLength: 256, nullable: true),
                    CreatedAt = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false),
                    UpdatedAt = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_PolicyTemplates", x => x.Id);
                    table.ForeignKey(
                        name: "FK_PolicyTemplates_RiskPolicies_RiskPolicyId",
                        column: x => x.RiskPolicyId,
                        principalTable: "RiskPolicies",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.SetNull);
                });

            migrationBuilder.CreateIndex(
                name: "IX_Clients_PolicyTemplateId",
                table: "Clients",
                column: "PolicyTemplateId");

            migrationBuilder.CreateIndex(
                name: "IX_PolicyTemplates_Name_Version",
                table: "PolicyTemplates",
                columns: new[] { "Name", "Version" },
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_PolicyTemplates_RiskPolicyId",
                table: "PolicyTemplates",
                column: "RiskPolicyId");

            migrationBuilder.AddForeignKey(
                name: "FK_Clients_PolicyTemplates_PolicyTemplateId",
                table: "Clients",
                column: "PolicyTemplateId",
                principalTable: "PolicyTemplates",
                principalColumn: "Id",
                onDelete: ReferentialAction.SetNull);
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropForeignKey(
                name: "FK_Clients_PolicyTemplates_PolicyTemplateId",
                table: "Clients");

            migrationBuilder.DropTable(
                name: "PolicyTemplates");

            migrationBuilder.DropIndex(
                name: "IX_Clients_PolicyTemplateId",
                table: "Clients");

            migrationBuilder.DropColumn(
                name: "PolicyLayer",
                table: "Projects");

            migrationBuilder.DropColumn(
                name: "PolicyLayer",
                table: "Clients");

            migrationBuilder.DropColumn(
                name: "PolicyTemplateId",
                table: "Clients");
        }
    }
}
