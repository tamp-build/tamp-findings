using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace Tamp.Findings.Data.Migrations
{
    /// <inheritdoc />
    public partial class AddEoProvenanceRegistry : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.CreateTable(
                name: "DirectiveCrosswalks",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "uuid", nullable: false),
                    DirectiveId = table.Column<Guid>(type: "uuid", nullable: false),
                    Target = table.Column<int>(type: "integer", nullable: false),
                    TargetRef = table.Column<string>(type: "character varying(256)", maxLength: 256, nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_DirectiveCrosswalks", x => x.Id);
                });

            migrationBuilder.CreateTable(
                name: "Directives",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "uuid", nullable: false),
                    InstrumentId = table.Column<Guid>(type: "uuid", nullable: false),
                    Section = table.Column<string>(type: "character varying(128)", maxLength: 128, nullable: true),
                    Ref = table.Column<string>(type: "character varying(128)", maxLength: 128, nullable: false),
                    Who = table.Column<string>(type: "character varying(512)", maxLength: 512, nullable: false),
                    MustDo = table.Column<string>(type: "text", nullable: false),
                    Type = table.Column<int>(type: "integer", nullable: false),
                    Applicability = table.Column<int>(type: "integer", nullable: false),
                    ByWhenKind = table.Column<int>(type: "integer", nullable: false),
                    AbsoluteDate = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: true),
                    RelativeOffsetDays = table.Column<int>(type: "integer", nullable: true),
                    AnchorKind = table.Column<int>(type: "integer", nullable: true),
                    AnchorInstrumentId = table.Column<Guid>(type: "uuid", nullable: true),
                    ResolvedDate = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: true),
                    SourceHash = table.Column<string>(type: "character varying(128)", maxLength: 128, nullable: true),
                    ExtractionModelId = table.Column<string>(type: "character varying(128)", maxLength: 128, nullable: true),
                    ReviewStatus = table.Column<int>(type: "integer", nullable: false),
                    CreatedAt = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_Directives", x => x.Id);
                });

            migrationBuilder.CreateTable(
                name: "DirectiveStatusChanges",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "uuid", nullable: false),
                    DirectiveId = table.Column<Guid>(type: "uuid", nullable: false),
                    Status = table.Column<int>(type: "integer", nullable: false),
                    EffectiveDate = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false),
                    CausedByInstrumentId = table.Column<Guid>(type: "uuid", nullable: true),
                    RecordedAt = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_DirectiveStatusChanges", x => x.Id);
                });

            migrationBuilder.CreateTable(
                name: "InstrumentRelations",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "uuid", nullable: false),
                    FromInstrumentId = table.Column<Guid>(type: "uuid", nullable: false),
                    ToInstrumentId = table.Column<Guid>(type: "uuid", nullable: false),
                    Type = table.Column<int>(type: "integer", nullable: false),
                    FromSection = table.Column<string>(type: "character varying(128)", maxLength: 128, nullable: true),
                    ToSection = table.Column<string>(type: "character varying(128)", maxLength: 128, nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_InstrumentRelations", x => x.Id);
                });

            migrationBuilder.CreateTable(
                name: "Instruments",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "uuid", nullable: false),
                    Identifier = table.Column<string>(type: "character varying(64)", maxLength: 64, nullable: false),
                    Title = table.Column<string>(type: "character varying(1024)", maxLength: 1024, nullable: false),
                    Type = table.Column<int>(type: "integer", nullable: false),
                    IssuingAuthority = table.Column<string>(type: "character varying(256)", maxLength: 256, nullable: true),
                    IssueDate = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false),
                    PublicationCite = table.Column<string>(type: "character varying(512)", maxLength: 512, nullable: true),
                    SourceHash = table.Column<string>(type: "character varying(128)", maxLength: 128, nullable: true),
                    ExtractionModelId = table.Column<string>(type: "character varying(128)", maxLength: 128, nullable: true),
                    ReviewStatus = table.Column<int>(type: "integer", nullable: false),
                    CreatedAt = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_Instruments", x => x.Id);
                });

            migrationBuilder.CreateIndex(
                name: "IX_DirectiveCrosswalks_DirectiveId",
                table: "DirectiveCrosswalks",
                column: "DirectiveId");

            migrationBuilder.CreateIndex(
                name: "IX_DirectiveCrosswalks_Target_TargetRef",
                table: "DirectiveCrosswalks",
                columns: new[] { "Target", "TargetRef" },
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_Directives_InstrumentId",
                table: "Directives",
                column: "InstrumentId");

            migrationBuilder.CreateIndex(
                name: "IX_Directives_Ref",
                table: "Directives",
                column: "Ref",
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_DirectiveStatusChanges_DirectiveId_EffectiveDate",
                table: "DirectiveStatusChanges",
                columns: new[] { "DirectiveId", "EffectiveDate" });

            migrationBuilder.CreateIndex(
                name: "IX_InstrumentRelations_FromInstrumentId",
                table: "InstrumentRelations",
                column: "FromInstrumentId");

            migrationBuilder.CreateIndex(
                name: "IX_InstrumentRelations_ToInstrumentId",
                table: "InstrumentRelations",
                column: "ToInstrumentId");

            migrationBuilder.CreateIndex(
                name: "IX_Instruments_Identifier",
                table: "Instruments",
                column: "Identifier",
                unique: true);
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropTable(
                name: "DirectiveCrosswalks");

            migrationBuilder.DropTable(
                name: "Directives");

            migrationBuilder.DropTable(
                name: "DirectiveStatusChanges");

            migrationBuilder.DropTable(
                name: "InstrumentRelations");

            migrationBuilder.DropTable(
                name: "Instruments");
        }
    }
}
