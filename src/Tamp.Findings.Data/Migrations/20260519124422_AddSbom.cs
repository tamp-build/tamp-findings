using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace Tamp.Findings.Data.Migrations
{
    /// <inheritdoc />
    public partial class AddSbom : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.CreateTable(
                name: "SbomSnapshots",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "uuid", nullable: false),
                    ComponentVersionId = table.Column<Guid>(type: "uuid", nullable: false),
                    SerialNumber = table.Column<string>(type: "character varying(256)", maxLength: 256, nullable: true),
                    SpecVersion = table.Column<string>(type: "character varying(32)", maxLength: 32, nullable: true),
                    ToolName = table.Column<string>(type: "character varying(128)", maxLength: 128, nullable: true),
                    ToolVersion = table.Column<string>(type: "character varying(64)", maxLength: 64, nullable: true),
                    IngestedAt = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_SbomSnapshots", x => x.Id);
                    table.ForeignKey(
                        name: "FK_SbomSnapshots_ComponentVersions_ComponentVersionId",
                        column: x => x.ComponentVersionId,
                        principalTable: "ComponentVersions",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateTable(
                name: "SbomComponents",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "uuid", nullable: false),
                    SbomSnapshotId = table.Column<Guid>(type: "uuid", nullable: false),
                    Purl = table.Column<string>(type: "character varying(1024)", maxLength: 1024, nullable: false),
                    Name = table.Column<string>(type: "character varying(512)", maxLength: 512, nullable: false),
                    Version = table.Column<string>(type: "character varying(128)", maxLength: 128, nullable: false),
                    Kind = table.Column<string>(type: "character varying(32)", maxLength: 32, nullable: true),
                    License = table.Column<string>(type: "character varying(256)", maxLength: 256, nullable: true),
                    LatestVersion = table.Column<string>(type: "character varying(128)", maxLength: 128, nullable: true),
                    LatestReleasedAt = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: true),
                    CurrentReleasedAt = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_SbomComponents", x => x.Id);
                    table.ForeignKey(
                        name: "FK_SbomComponents_SbomSnapshots_SbomSnapshotId",
                        column: x => x.SbomSnapshotId,
                        principalTable: "SbomSnapshots",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateTable(
                name: "SbomDependencies",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "uuid", nullable: false),
                    SbomSnapshotId = table.Column<Guid>(type: "uuid", nullable: false),
                    ParentComponentId = table.Column<Guid>(type: "uuid", nullable: false),
                    ChildComponentId = table.Column<Guid>(type: "uuid", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_SbomDependencies", x => x.Id);
                    table.ForeignKey(
                        name: "FK_SbomDependencies_SbomComponents_ChildComponentId",
                        column: x => x.ChildComponentId,
                        principalTable: "SbomComponents",
                        principalColumn: "Id");
                    table.ForeignKey(
                        name: "FK_SbomDependencies_SbomComponents_ParentComponentId",
                        column: x => x.ParentComponentId,
                        principalTable: "SbomComponents",
                        principalColumn: "Id");
                    table.ForeignKey(
                        name: "FK_SbomDependencies_SbomSnapshots_SbomSnapshotId",
                        column: x => x.SbomSnapshotId,
                        principalTable: "SbomSnapshots",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateTable(
                name: "Vulnerabilities",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "uuid", nullable: false),
                    SbomComponentId = table.Column<Guid>(type: "uuid", nullable: false),
                    AdvisoryId = table.Column<string>(type: "character varying(64)", maxLength: 64, nullable: false),
                    Severity = table.Column<int>(type: "integer", nullable: false),
                    Title = table.Column<string>(type: "character varying(512)", maxLength: 512, nullable: true),
                    Description = table.Column<string>(type: "text", nullable: true),
                    FixedInVersion = table.Column<string>(type: "character varying(128)", maxLength: 128, nullable: true),
                    ReferenceUrl = table.Column<string>(type: "character varying(1024)", maxLength: 1024, nullable: true),
                    Source = table.Column<int>(type: "integer", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_Vulnerabilities", x => x.Id);
                    table.ForeignKey(
                        name: "FK_Vulnerabilities_SbomComponents_SbomComponentId",
                        column: x => x.SbomComponentId,
                        principalTable: "SbomComponents",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateIndex(
                name: "IX_SbomComponents_SbomSnapshotId_Purl",
                table: "SbomComponents",
                columns: new[] { "SbomSnapshotId", "Purl" },
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_SbomDependencies_ChildComponentId",
                table: "SbomDependencies",
                column: "ChildComponentId");

            migrationBuilder.CreateIndex(
                name: "IX_SbomDependencies_ParentComponentId",
                table: "SbomDependencies",
                column: "ParentComponentId");

            migrationBuilder.CreateIndex(
                name: "IX_SbomDependencies_SbomSnapshotId_ParentComponentId_ChildComp~",
                table: "SbomDependencies",
                columns: new[] { "SbomSnapshotId", "ParentComponentId", "ChildComponentId" },
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_SbomSnapshots_ComponentVersionId",
                table: "SbomSnapshots",
                column: "ComponentVersionId",
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_Vulnerabilities_SbomComponentId_AdvisoryId",
                table: "Vulnerabilities",
                columns: new[] { "SbomComponentId", "AdvisoryId" },
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_Vulnerabilities_Severity",
                table: "Vulnerabilities",
                column: "Severity");
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropTable(
                name: "SbomDependencies");

            migrationBuilder.DropTable(
                name: "Vulnerabilities");

            migrationBuilder.DropTable(
                name: "SbomComponents");

            migrationBuilder.DropTable(
                name: "SbomSnapshots");
        }
    }
}
