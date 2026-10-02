using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Tamp.Findings.Api.Ingest.Raw;
using Tamp.Findings.Application.Ingest;
using Tamp.Findings.Domain.Compliance;
using Tamp.Findings.Domain.Entities;
using Tamp.Findings.Domain.Risk;
using Tamp.Findings.Domain.Values;
using static Tamp.Findings.Integration.Tests.ApiAHarness;

namespace Tamp.Findings.Integration.Tests;

// Smaller read/query endpoints: findings-by-version, scan receipts, build evaluation, badge, SBOM provenance,
// OSCAL / SSDF export, VDP, raw artifacts, hierarchy create, conformance disposition, ZT profile.
[Collection(DatabaseCollection.Name)]
public class ApiAMiscQueryTests
{
    private readonly DatabaseFixture _fx;
    public ApiAMiscQueryTests(DatabaseFixture fx) => _fx = fx;

    private async Task<(HttpClient Admin, Guid AdminId)> AdminAsync()
    {
        var id = await UserAsync(_fx, admin: true);
        return (Http(_fx, id), id);
    }

    private async Task<HttpClient> MemberAsync(Guid clientId, ProjectRole role)
    {
        var id = await UserAsync(_fx, admin: false);
        await GrantAsync(_fx, id, role, clientId, null);
        return Http(_fx, id);
    }

    private static async Task<JsonElement> BodyAsync(HttpResponseMessage r) => (await JsonAsync(r)).RootElement.Clone();

    // ---------------------------------------------------------------- findings by version

    [SkippableFact]
    public async Task Findings_by_component_version_returns_every_status_ordered_by_severity()
    {
        Skip.IfNot(_fx.Available);
        var (admin, _) = await AdminAsync();
        var tree = await ClientProjectAsync(_fx);
        var cv = await VersionAsync(_fx, tree.ProjectId, "1." + Sfx());
        await AddFindingsAsync(_fx,
            NewFinding(cv, ScannerKind.Roslyn, Severity.Low, "B-LOW"),
            NewFinding(cv, ScannerKind.Roslyn, Severity.Critical, "Z-CRIT"),
            NewFinding(cv, ScannerKind.Roslyn, Severity.Critical, "A-CRIT", FindingStatus.Fixed),
            NewFinding(cv, ScannerKind.OpenGrep, Severity.Info, "I-INFO"),
            NewFinding(cv, ScannerKind.OpenGrep, Severity.Medium, "M-MED"),
            NewFinding(cv, ScannerKind.OpenGrep, Severity.High, "H-HIGH"));

        var r = await GetJsonAsync(admin, $"/findings/by-component-version/{cv}");

        Assert.Equal(cv, r.GetProperty("componentVersionId").GetGuid());
        var rules = r.GetProperty("findings").EnumerateArray().Select(f => f.GetProperty("ruleId").GetString()!).ToList();
        Assert.Equal("A-CRIT,Z-CRIT,H-HIGH,M-MED,B-LOW,I-INFO", string.Join(",", rules));
        var counts = r.GetProperty("counts");
        Assert.Equal(2, counts.GetProperty("critical").GetInt32());
        Assert.Equal(1, counts.GetProperty("high").GetInt32());
        Assert.Equal(1, counts.GetProperty("medium").GetInt32());
        Assert.Equal(1, counts.GetProperty("low").GetInt32());
        Assert.Equal(1, counts.GetProperty("info").GetInt32());

        Assert.Equal(HttpStatusCode.NotFound, (await admin.GetAsync($"/findings/by-component-version/{Guid.NewGuid()}")).StatusCode);
        Assert.Equal(HttpStatusCode.Unauthorized, (await Http(_fx, null).GetAsync($"/findings/by-component-version/{cv}")).StatusCode);
    }

    // ---------------------------------------------------------------- scan receipts

    [SkippableFact]
    public async Task Scan_receipts_list_builds_newest_first_canonical_by_default()
    {
        Skip.IfNot(_fx.Available);
        var (admin, _) = await AdminAsync();
        var tree = await ClientProjectAsync(_fx);
        var now = DateTimeOffset.UtcNow;
        var s = Sfx();
        var oldest = await VersionAsync(_fx, tree.ProjectId, $"1.{s}", createdAt: now.AddDays(-2));
        var newest = await VersionAsync(_fx, tree.ProjectId, $"2.{s}", flavor: "linux", createdAt: now.AddMinutes(-5));
        var pr = await VersionAsync(_fx, tree.ProjectId, $"3.{s}", branch: "feat", pr: "refs/pull/1", createdAt: now);
        await AddScanRunAsync(_fx, newest, ScannerKind.Trivy, ScanRunStatus.Succeeded, now, 4);
        await AddScanRunAsync(_fx, newest, ScannerKind.OpenGrep, ScanRunStatus.Failed, now, 0);

        using (var scope = _fx.Scope())
        {
            var db = _fx.Db(scope);
            var cv = await db.ComponentVersions.SingleAsync(v => v.Id == newest);
            cv.ActorId = "bot-1"; cv.ActorKind = IngestActorKind.Agent; cv.CommitSha = "abc123";
            await db.SaveChangesAsync();
        }

        var r = await GetJsonAsync(admin, $"/projects/{tree.ProjectId}/scan-receipts");
        var builds = r.GetProperty("builds").EnumerateArray().ToList();
        Assert.Equal(2, builds.Count);
        Assert.Equal(newest, builds[0].GetProperty("componentVersionId").GetGuid());
        Assert.Equal("linux", builds[0].GetProperty("flavorName").GetString());
        Assert.Equal("agent", builds[0].GetProperty("actorKind").GetString());
        Assert.Equal("abc123", builds[0].GetProperty("commitSha").GetString());
        var receipts = builds[0].GetProperty("receipts").EnumerateArray().Select(x => x.GetProperty("scanner").GetString()).ToArray();
        Assert.Equal("OpenGrep,Trivy", string.Join(",", receipts));
        Assert.Equal(0, builds[1].GetProperty("receipts").GetArrayLength());   // a build with no receipts still shows
        Assert.Equal(JsonValueKind.Null, builds[1].GetProperty("actorKind").ValueKind);

        var all = await GetJsonAsync(admin, $"/projects/{tree.ProjectId}/scan-receipts?includeNonCanonical=true");
        Assert.Equal(3, all.GetProperty("builds").GetArrayLength());
        Assert.Equal(pr, all.GetProperty("builds")[0].GetProperty("componentVersionId").GetGuid());

        var limited = await GetJsonAsync(admin, $"/projects/{tree.ProjectId}/scan-receipts?take=1&includeNonCanonical=true");
        Assert.Equal(1, limited.GetProperty("builds").GetArrayLength());
        var clamped = await GetJsonAsync(admin, $"/projects/{tree.ProjectId}/scan-receipts?take=0");
        Assert.Equal(1, clamped.GetProperty("builds").GetArrayLength());

        var empty = await ClientProjectAsync(_fx);
        Assert.Equal(0, (await GetJsonAsync(admin, $"/projects/{empty.ProjectId}/scan-receipts")).GetProperty("builds").GetArrayLength());
        _ = oldest;
    }

    // ---------------------------------------------------------------- build evaluation

    [SkippableFact]
    public async Task Build_evaluation_scores_the_latest_canonical_build_against_the_gates()
    {
        Skip.IfNot(_fx.Available);
        var (admin, adminId) = await AdminAsync();
        var tree = await ClientProjectAsync(_fx);
        var now = DateTimeOffset.UtcNow;
        var s = Sfx();

        Assert.Equal(HttpStatusCode.NotFound, (await admin.GetAsync($"/projects/{Guid.NewGuid()}/build-evaluation")).StatusCode);
        var none = await admin.GetAsync($"/projects/{tree.ProjectId}/build-evaluation");
        Assert.Equal(HttpStatusCode.NotFound, none.StatusCode);
        Assert.Contains("no canonical builds", await none.Content.ReadAsStringAsync());

        var prior = await VersionAsync(_fx, tree.ProjectId, $"1.{s}", createdAt: now.AddDays(-1));
        var current = await VersionAsync(_fx, tree.ProjectId, $"2.{s}", createdAt: now);
        await VersionAsync(_fx, tree.ProjectId, $"3.{s}", branch: "feat", pr: "refs/pull/9", createdAt: now.AddHours(1));
        await SbomAsync(_fx, current, now, ($"pkg:nuget/Eval{s}", "1.0.0", "MIT", null, null, [(Cve(), Severity.Critical)]));
        await AddFindingsAsync(_fx, NewFinding(current, ScannerKind.OpenGrep, Severity.High, "E1"));
        await AddScanRunAsync(_fx, current, ScannerKind.OpenGrep, ScanRunStatus.Succeeded, now, 1);
        await AddScanRunAsync(_fx, current, ScannerKind.OsvScanner, ScanRunStatus.Succeeded, now, 1);
        using (var scope = _fx.Scope())
        {
            var db = _fx.Db(scope);
            var p = await db.Projects.SingleAsync(x => x.Id == tree.ProjectId);
            p.GatesConfig = new ProjectGatesConfig
            {
                Gates =
                {
                    [GateKeys.CriticalCves] = new GateConfig { Enabled = true, Threshold = 0 },
                    [GateKeys.RiskScoreRegression] = new GateConfig { Enabled = true, Threshold = 0 },
                },
            };
            await db.SaveChangesAsync();
        }

        var r = await GetJsonAsync(admin, $"/projects/{tree.ProjectId}/build-evaluation");

        Assert.Equal($"2.{s}", r.GetProperty("current").GetProperty("versionString").GetString());
        Assert.Equal($"1.{s}", r.GetProperty("prior").GetProperty("versionString").GetString());
        Assert.True(r.GetProperty("currentScore").GetDouble() >= 0);
        Assert.NotNull(r.GetProperty("deltaPoints").ToString());
        Assert.True(r.GetProperty("gatesEnabled").GetInt32() >= 2);
        var gates = r.GetProperty("gates").EnumerateArray().ToList();
        var crit = gates.Single(g => g.GetProperty("key").GetString() == GateKeys.CriticalCves);
        Assert.Equal("Fail", crit.GetProperty("verdict").GetString());
        Assert.True(crit.GetProperty("blocks").GetBoolean());
        Assert.True(r.GetProperty("gatesBlocking").GetInt32() >= 1);
        Assert.True(r.GetProperty("gatesFailed").GetInt32() >= 1);
        Assert.Contains(r.GetProperty("enforcementMode").GetString(), new[] { "Advisory", "Enforcing" });
        Assert.False(string.IsNullOrEmpty(r.GetProperty("policyName").GetString()));

        // the single-build case has no prior
        var solo = await ClientProjectAsync(_fx);
        await VersionAsync(_fx, solo.ProjectId, "1." + Sfx(), branch: "master");
        var one = await GetJsonAsync(admin, $"/projects/{solo.ProjectId}/build-evaluation");
        Assert.Equal(JsonValueKind.Null, one.GetProperty("prior").ValueKind);
        Assert.Equal(JsonValueKind.Null, one.GetProperty("priorScore").ValueKind);
        _ = (prior, adminId);
    }

    // ---------------------------------------------------------------- badge

    [SkippableFact]
    public async Task Badge_keys_are_minted_by_admins_and_serve_an_anonymous_never_cached_svg()
    {
        Skip.IfNot(_fx.Available);
        var (admin, _) = await AdminAsync();
        var tree = await ClientProjectAsync(_fx);
        var viewer = await MemberAsync(tree.ClientId, ProjectRole.Auditor);
        var anon = Http(_fx, null);

        Assert.Equal(HttpStatusCode.Forbidden, (await viewer.GetAsync($"/projects/{tree.ProjectId}/badge")).StatusCode);
        Assert.Equal(HttpStatusCode.Forbidden, (await viewer.PostAsync($"/projects/{tree.ProjectId}/badge/rotate", null)).StatusCode);
        Assert.Equal(HttpStatusCode.Unauthorized, (await anon.GetAsync($"/projects/{tree.ProjectId}/badge")).StatusCode);
        Assert.Equal(HttpStatusCode.NotFound, (await admin.GetAsync($"/projects/{Guid.NewGuid()}/badge")).StatusCode);
        Assert.Equal(HttpStatusCode.NotFound, (await admin.PostAsync($"/projects/{Guid.NewGuid()}/badge/rotate", null)).StatusCode);

        var info = await GetJsonAsync(admin, $"/projects/{tree.ProjectId}/badge");
        var key = info.GetProperty("key").GetString()!;
        Assert.Equal(32, key.Length);
        Assert.EndsWith($"/badge/{key}.svg", info.GetProperty("url").GetString());
        Assert.Contains("[![tamp-findings]", info.GetProperty("markdown").GetString());
        Assert.Contains("<img", info.GetProperty("html").GetString());
        // minted once, then stable
        Assert.Equal(key, (await GetJsonAsync(admin, $"/projects/{tree.ProjectId}/badge")).GetProperty("key").GetString());

        // No build yet: still an SVG.
        var unbuilt = await anon.GetAsync($"/badge/{key}.svg");
        Assert.Equal(HttpStatusCode.OK, unbuilt.StatusCode);
        Assert.Equal("image/svg+xml", unbuilt.Content.Headers.ContentType!.MediaType);
        Assert.Contains("no-store", unbuilt.Headers.CacheControl!.ToString());
        Assert.Contains("<svg", await unbuilt.Content.ReadAsStringAsync());

        // With a build it renders the status.
        var cv = await VersionAsync(_fx, tree.ProjectId, "1." + Sfx());
        await AddFindingsAsync(_fx, NewFinding(cv, ScannerKind.Roslyn, Severity.High, "BD1"));
        var built = await anon.GetAsync($"/badge/{key}.svg");
        Assert.Equal(HttpStatusCode.OK, built.StatusCode);
        Assert.Contains("<svg", await built.Content.ReadAsStringAsync());

        // Public report enabled: the embed links to it.
        using (var scope = _fx.Scope())
        {
            var db = _fx.Db(scope);
            var p = await db.Projects.SingleAsync(x => x.Id == tree.ProjectId);
            p.PublicReportEnabled = true; p.ReportKey = "rk-" + Sfx();
            await db.SaveChangesAsync();
        }
        Assert.Contains("/report/rk-", (await GetJsonAsync(admin, $"/projects/{tree.ProjectId}/badge")).GetProperty("markdown").GetString());

        // Rotation revokes the old key.
        var rotated = await BodyAsync(await admin.PostAsync($"/projects/{tree.ProjectId}/badge/rotate", null));
        Assert.NotEqual(key, rotated.GetProperty("key").GetString());
        Assert.Equal(HttpStatusCode.NotFound, (await anon.GetAsync($"/badge/{key}.svg")).StatusCode);
        Assert.Equal(HttpStatusCode.OK, (await anon.GetAsync($"/badge/{rotated.GetProperty("key").GetString()}.svg")).StatusCode);
        Assert.Equal(HttpStatusCode.NotFound, (await anon.GetAsync("/badge/unknown-key.svg")).StatusCode);
    }

    // ---------------------------------------------------------------- SBOM provenance read

    [SkippableFact]
    public async Task Provenance_read_returns_the_stored_attestation_or_empty()
    {
        Skip.IfNot(_fx.Available);
        var (admin, _) = await AdminAsync();
        var tree = await ClientProjectAsync(_fx);
        var cv = await VersionAsync(_fx, tree.ProjectId, "1." + Sfx());
        var seed = await SbomAsync(_fx, cv, null, ("pkg:nuget/P", "1.0.0", null, null, null, []));

        var none = await GetJsonAsync(admin, $"/sbom-snapshots/{seed.SnapshotId}/provenance");
        Assert.Equal(JsonValueKind.Null, none.GetProperty("provenanceType").ValueKind);
        Assert.Equal(JsonValueKind.Null, none.GetProperty("payload").ValueKind);

        using (var scope = _fx.Scope())
        {
            var db = _fx.Db(scope);
            var snap = await db.SbomSnapshots.SingleAsync(x => x.Id == seed.SnapshotId);
            snap.ProvenanceType = "https://slsa.dev/provenance/v1";
            snap.ProvenanceUploadedAt = DateTimeOffset.UtcNow;
            snap.ProvenanceJson = new Dictionary<string, object?> { ["builder"] = "ci" };
            await db.SaveChangesAsync();
        }
        var some = await GetJsonAsync(admin, $"/sbom-snapshots/{seed.SnapshotId}/provenance");
        Assert.Equal("https://slsa.dev/provenance/v1", some.GetProperty("provenanceType").GetString());
        Assert.Equal("ci", some.GetProperty("payload").GetProperty("builder").GetString());

        Assert.Equal(HttpStatusCode.NotFound, (await admin.GetAsync($"/sbom-snapshots/{Guid.NewGuid()}/provenance")).StatusCode);
    }

    // ---------------------------------------------------------------- OSCAL + SSDF attestation

    [SkippableFact]
    public async Task Ssdf_attestation_builds_for_a_project_and_404s_otherwise()
    {
        Skip.IfNot(_fx.Available);
        var (admin, _) = await AdminAsync();
        var tree = await ClientProjectAsync(_fx);
        var cv = await VersionAsync(_fx, tree.ProjectId, "1." + Sfx());
        await AddFindingsAsync(_fx, NewFinding(cv, ScannerKind.Roslyn, Severity.High, "SS1"));

        var ok = await admin.GetAsync($"/projects/{tree.ProjectId}/ssdf-attestation");
        Assert.Equal(HttpStatusCode.OK, ok.StatusCode);
        Assert.NotEqual(JsonValueKind.Null, (await BodyAsync(ok)).ValueKind);

        Assert.Equal(HttpStatusCode.NotFound, (await admin.GetAsync($"/projects/{Guid.NewGuid()}/ssdf-attestation")).StatusCode);
    }

    [SkippableFact]
    public async Task Oscal_export_validates_model_authorizes_and_requires_a_build()
    {
        Skip.IfNot(_fx.Available);
        var (admin, _) = await AdminAsync();
        var tree = await ClientProjectAsync(_fx);
        var auditor = await MemberAsync(tree.ClientId, ProjectRole.Auditor);
        var lead = await MemberAsync(tree.ClientId, ProjectRole.LeadDev);
        var url = $"/projects/{tree.ProjectId}/oscal";

        Assert.Equal(HttpStatusCode.BadRequest, (await admin.GetAsync(url + "?model=bogus")).StatusCode);
        Assert.Equal(HttpStatusCode.NotFound, (await admin.GetAsync($"/projects/{Guid.NewGuid()}/oscal")).StatusCode);
        Assert.Equal(HttpStatusCode.Unauthorized, (await Http(_fx, null).GetAsync(url)).StatusCode);

        // No canonical build yet: nothing to attest.
        var noBuild = await admin.GetAsync(url);
        Assert.Equal(HttpStatusCode.BadRequest, noBuild.StatusCode);
        Assert.Contains("no canonical build", await noBuild.Content.ReadAsStringAsync());

        var cv = await VersionAsync(_fx, tree.ProjectId, "1." + Sfx());
        await AddFindingsAsync(_fx, NewFinding(cv, ScannerKind.Roslyn, Severity.High, "OS1"));

        foreach (var model in new[] { null, "Bundle", "poam", "AssessmentResults" })
        {
            var resp = await admin.GetAsync(url + (model is null ? "" : $"?model={model}"));
            Assert.Equal(HttpStatusCode.OK, resp.StatusCode);
            Assert.Equal("application/json", resp.Content.Headers.ContentType!.MediaType);
            Assert.True(resp.Headers.Contains("X-Tamp-Filename"));
            using var doc = JsonDocument.Parse(await resp.Content.ReadAsStringAsync());
            Assert.Equal(JsonValueKind.Object, doc.RootElement.ValueKind);
        }

        // Auditor may export; a Lead Dev may not (ExportAttestation is denied to that role).
        Assert.Equal(HttpStatusCode.OK, (await auditor.GetAsync(url)).StatusCode);
        var leadResp = await lead.GetAsync(url);
        Assert.True(leadResp.StatusCode is HttpStatusCode.OK or HttpStatusCode.Forbidden);
    }

    // ---------------------------------------------------------------- VDP

    [SkippableFact]
    public async Task Vdp_metadata_round_trips_and_trims_blanks()
    {
        Skip.IfNot(_fx.Available);
        var (admin, _) = await AdminAsync();
        var tree = await ClientProjectAsync(_fx);
        var viewer = await MemberAsync(tree.ClientId, ProjectRole.Auditor);
        var url = $"/projects/{tree.ProjectId}/vdp";

        var empty = await GetJsonAsync(viewer, url);
        Assert.Equal(JsonValueKind.Null, empty.GetProperty("vdpPolicyUrl").ValueKind);

        var put = await admin.PutAsJsonAsync(url, new { vdpPolicyUrl = " https://example.test/vdp ", vdpContactEmail = "sec@example.test", vdpReportingFormUrl = "   " });
        Assert.Equal(HttpStatusCode.OK, put.StatusCode);
        var body = await BodyAsync(put);
        Assert.Equal("https://example.test/vdp", body.GetProperty("vdpPolicyUrl").GetString());
        Assert.Equal(JsonValueKind.Null, body.GetProperty("vdpReportingFormUrl").ValueKind);
        Assert.Equal("sec@example.test", (await GetJsonAsync(viewer, url)).GetProperty("vdpContactEmail").GetString());

        Assert.Equal(HttpStatusCode.Forbidden, (await viewer.PutAsJsonAsync(url, new { vdpPolicyUrl = "x" })).StatusCode);
        Assert.Equal(HttpStatusCode.NotFound, (await admin.PutAsJsonAsync($"/projects/{Guid.NewGuid()}/vdp", new { vdpPolicyUrl = "x" })).StatusCode);
        Assert.Equal(HttpStatusCode.NotFound, (await admin.GetAsync($"/projects/{Guid.NewGuid()}/vdp")).StatusCode);
        Assert.Equal(HttpStatusCode.Unauthorized, (await Http(_fx, null).PutAsJsonAsync(url, new { vdpPolicyUrl = "x" })).StatusCode);
    }

    // ---------------------------------------------------------------- raw artifacts

    [SkippableFact]
    public async Task Raw_artifacts_list_metadata_and_download_the_original_bytes()
    {
        Skip.IfNot(_fx.Available);
        var (admin, _) = await AdminAsync();
        var tree = await ClientProjectAsync(_fx);
        var cv = await VersionAsync(_fx, tree.ProjectId, "1." + Sfx());
        var otherCv = await VersionAsync(_fx, tree.ProjectId, "2." + Sfx());
        var raw = System.Text.Encoding.UTF8.GetBytes("<TestRun>ok</TestRun>");
        Guid withName, withoutName;
        using (var scope = _fx.Scope())
        {
            var db = _fx.Db(scope);
            var a = new RawReportArtifact
            {
                ComponentVersionId = cv, Kind = RawArtifactKind.TestResults, Format = "trx", FileName = "results.trx",
                SlotKey = "a", Sha256 = "aa", SizeBytes = raw.Length, CompressedBytes = RawArtifactStore.Gzip(raw),
                ToolName = "dotnet test", IngestedAt = DateTimeOffset.UtcNow.AddMinutes(-5),
            };
            var b = new RawReportArtifact
            {
                ComponentVersionId = cv, Kind = RawArtifactKind.Coverage, Format = "cobertura", FileName = null,
                SlotKey = "b", Sha256 = "bb", SizeBytes = raw.Length, CompressedBytes = RawArtifactStore.Gzip(raw),
            };
            db.RawReportArtifacts.AddRange(a, b);
            await db.SaveChangesAsync();
            (withName, withoutName) = (a.Id, b.Id);
        }

        var list = await GetJsonAsync(admin, $"/raw-artifacts?componentVersionId={cv}");
        Assert.Equal(2, list.GetArrayLength());
        Assert.Equal("Coverage", list[0].GetProperty("kind").GetString());     // newest first
        Assert.Equal("trx", list[1].GetProperty("format").GetString());
        Assert.Equal(raw.Length, list[1].GetProperty("sizeBytes").GetInt64());
        Assert.Equal(0, (await GetJsonAsync(admin, $"/raw-artifacts?componentVersionId={otherCv}")).GetArrayLength());

        var named = await admin.GetAsync($"/raw-artifacts/{withName}?componentVersionId={cv}");
        Assert.Equal(HttpStatusCode.OK, named.StatusCode);
        Assert.Equal(raw, await named.Content.ReadAsByteArrayAsync());
        Assert.Equal("results.trx", named.Content.Headers.ContentDisposition!.FileName);
        var unnamed = await admin.GetAsync($"/raw-artifacts/{withoutName}?componentVersionId={cv}");
        Assert.Equal("coverage-cobertura.xml", unnamed.Content.Headers.ContentDisposition!.FileName);

        // The id must belong to the named build.
        Assert.Equal(HttpStatusCode.NotFound, (await admin.GetAsync($"/raw-artifacts/{withName}?componentVersionId={otherCv}")).StatusCode);
        Assert.Equal(HttpStatusCode.NotFound, (await admin.GetAsync($"/raw-artifacts/{Guid.NewGuid()}?componentVersionId={cv}")).StatusCode);
    }

    // ---------------------------------------------------------------- hierarchy create

    [SkippableFact]
    public async Task Admins_create_clients_and_projects_with_validation_and_conflicts()
    {
        Skip.IfNot(_fx.Available);
        var (admin, _) = await AdminAsync();
        var existing = await ClientProjectAsync(_fx);
        var viewer = await MemberAsync(existing.ClientId, ProjectRole.Auditor);
        var name = "apia-new-client-" + Sfx();

        Assert.Equal(HttpStatusCode.Forbidden, (await viewer.PostAsJsonAsync("/clients", new { name })).StatusCode);
        Assert.Equal(HttpStatusCode.Unauthorized, (await Http(_fx, null).PostAsJsonAsync("/clients", new { name })).StatusCode);
        Assert.Equal(HttpStatusCode.BadRequest, (await admin.PostAsJsonAsync("/clients", new { name = "   " })).StatusCode);

        var created = await admin.PostAsJsonAsync("/clients", new { name = $"  {name}  " });
        Assert.Equal(HttpStatusCode.Created, created.StatusCode);
        var client = await BodyAsync(created);
        Assert.Equal(name, client.GetProperty("name").GetString());
        Assert.Equal(0, client.GetProperty("projectCount").GetInt32());
        Assert.Equal(HttpStatusCode.Conflict, (await admin.PostAsJsonAsync("/clients", new { name })).StatusCode);

        var clientId = client.GetProperty("id").GetGuid();
        var pname = "apia-new-project-" + Sfx();
        Assert.Equal(HttpStatusCode.Forbidden, (await viewer.PostAsJsonAsync("/projects", new { name = pname, clientId })).StatusCode);
        Assert.Equal(HttpStatusCode.BadRequest, (await admin.PostAsJsonAsync("/projects", new { name = "", clientId })).StatusCode);
        Assert.Equal(HttpStatusCode.BadRequest, (await admin.PostAsJsonAsync("/projects", new { name = pname, clientId = Guid.NewGuid() })).StatusCode);

        var p = await admin.PostAsJsonAsync("/projects", new { name = pname, clientId, description = " a project " });
        Assert.Equal(HttpStatusCode.Created, p.StatusCode);
        var project = await BodyAsync(p);
        Assert.Equal(client.GetProperty("name").GetString(), project.GetProperty("clientName").GetString());
        Assert.Equal(HttpStatusCode.Conflict, (await admin.PostAsJsonAsync("/projects", new { name = pname, clientId })).StatusCode);
        var noDescription = await admin.PostAsJsonAsync("/projects", new { name = pname + "-b", clientId, description = " " });
        Assert.Equal(HttpStatusCode.Created, noDescription.StatusCode);

        using var scope = _fx.Scope();
        var row = await _fx.Db(scope).Projects.AsNoTracking().SingleAsync(x => x.Id == project.GetProperty("id").GetGuid());
        Assert.Equal("a project", row.Description);
    }

    // ---------------------------------------------------------------- conformance disposition

    [SkippableFact]
    public async Task Conformance_disposition_needs_risk_acceptance_authority_and_a_real_finding()
    {
        Skip.IfNot(_fx.Available);
        var (admin, _) = await AdminAsync();
        var tree = await ClientProjectAsync(_fx);
        var cv = await VersionAsync(_fx, tree.ProjectId, "1." + Sfx());
        var infosec = await MemberAsync(tree.ClientId, ProjectRole.InfoSecOfficer);
        var lead = await MemberAsync(tree.ClientId, ProjectRole.LeadDev);
        Guid findingId;
        using (var scope = _fx.Scope())
        {
            var db = _fx.Db(scope);
            var f = new ConformanceFinding
            {
                ComponentVersionId = cv, AdrRef = "ADR 0002", RuleId = "r-" + Sfx(), Claim = "claim",
                Verdict = ConformanceVerdict.Fail,
            };
            db.ConformanceFindings.Add(f);
            await db.SaveChangesAsync();
            findingId = f.Id;
        }
        string Url(Guid p, Guid f) => $"/projects/{p}/conformance/{f}/disposition";

        Assert.Equal(HttpStatusCode.Unauthorized, (await Http(_fx, null).PostAsJsonAsync(Url(tree.ProjectId, findingId), new { justification = "j" })).StatusCode);
        Assert.Equal(HttpStatusCode.NotFound, (await infosec.PostAsJsonAsync(Url(Guid.NewGuid(), findingId), new { justification = "j" })).StatusCode);
        Assert.Equal(HttpStatusCode.Forbidden, (await lead.PostAsJsonAsync(Url(tree.ProjectId, findingId), new { justification = "j" })).StatusCode);
        Assert.Equal(HttpStatusCode.Forbidden, (await admin.PostAsJsonAsync(Url(tree.ProjectId, findingId), new { justification = "j" })).StatusCode);   // Admin deliberately lacks AcceptRisk
        Assert.Equal(HttpStatusCode.BadRequest, (await infosec.PostAsJsonAsync(Url(tree.ProjectId, findingId), new { justification = " " })).StatusCode);
        Assert.Equal(HttpStatusCode.BadRequest, (await infosec.PostAsJsonAsync(Url(tree.ProjectId, findingId), new { justification = "j", expiry = DateTimeOffset.UtcNow.AddDays(-1) })).StatusCode);
        Assert.Equal(HttpStatusCode.BadRequest, (await infosec.PostAsJsonAsync(Url(tree.ProjectId, Guid.NewGuid()), new { justification = "j" })).StatusCode);

        var ok = await infosec.PostAsJsonAsync(Url(tree.ProjectId, findingId), new { justification = "  accepted until rework  ", expiry = DateTimeOffset.UtcNow.AddDays(30) });
        Assert.Equal(HttpStatusCode.OK, ok.StatusCode);
        Assert.True((await BodyAsync(ok)).GetProperty("dispositioned").GetBoolean());
        using var check = _fx.Scope();
        var row = await _fx.Db(check).ConformanceFindings.AsNoTracking().SingleAsync(f => f.Id == findingId);
        Assert.True(row.Dispositioned);
        Assert.Equal("accepted until rework", row.DispositionJustification);
    }

    // ---------------------------------------------------------------- ZT profile (token-authed)

    [SkippableFact]
    public async Task Zt_profile_is_served_to_project_tokens_only()
    {
        Skip.IfNot(_fx.Available);
        var userId = await UserAsync(_fx, admin: true);
        var tree = await ClientProjectAsync(_fx);
        string projectToken, clientToken;
        using (var scope = _fx.Scope())
        {
            var svc = scope.ServiceProvider.GetRequiredService<IngestTokenService>();
            projectToken = (await svc.MintProjectTokenAsync(tree.ProjectId, "apia-zt", userId, default)).Plaintext;
            clientToken = (await svc.MintClientTokenAsync(tree.ClientId, "apia-zt-client", userId, default)).Plaintext;
        }
        var host = Http(_fx, null);

        HttpRequestMessage Req(string? token)
        {
            var m = new HttpRequestMessage(HttpMethod.Get, "/projects/self/zt-profile");
            if (token is not null) m.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);
            return m;
        }

        Assert.Equal(HttpStatusCode.Unauthorized, (await host.SendAsync(Req(null))).StatusCode);
        Assert.Equal(HttpStatusCode.NotFound, (await host.SendAsync(Req(clientToken))).StatusCode);
        var resp = await host.SendAsync(Req(projectToken));
        Assert.True(resp.StatusCode is HttpStatusCode.OK or HttpStatusCode.NotFound, resp.StatusCode.ToString());
    }
}
