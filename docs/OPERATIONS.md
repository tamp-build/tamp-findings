# Operating tamp.findings

Health probes, backup and restore, retention, and what shows up in the logs.

Storage is **bring-your-own Postgres**. The image does not own your backup story — it cannot, since it does not own the database — but it does depend on you having one, and this page says what that needs to cover.

---

## Probes

Two endpoints, and the difference between them matters.

| Endpoint | Answers | Checks the database | Failure means |
|---|---|---|---|
| `GET /health` | Is the process alive? | **No** | Restart the container |
| `GET /ready` | Can it serve a request? | Yes | Take it out of the load balancer |

**Liveness never checks the database, on purpose.** A failing liveness probe restarts the container. Restarting an application because Postgres is down turns a database outage into a crash loop — one that recovers more slowly than the outage itself and destroys the logs that would have explained it. Point your liveness probe at `/health` and leave it that way.

**Readiness does check it**, with a three-second timeout, and returns `503` with a reason when it cannot connect. That is the probe that should gate traffic.

```yaml
livenessProbe:
  httpGet: { path: /health, port: 8080 }
  periodSeconds: 10
  failureThreshold: 3

readinessProbe:
  httpGet: { path: /ready, port: 8080 }
  periodSeconds: 5
  failureThreshold: 2
```

Both are anonymous. `GET /version` reports the running build.

---

## Backup

**Everything that matters is in Postgres.** There is no file storage, no object store, no local state worth keeping: SBOMs, findings, coverage, attestations, audit entries and the Data Protection key ring are all rows. Back up the database and you have backed up the instance.

### What to run

```bash
pg_dump \
  --format=custom \
  --no-owner \
  --no-privileges \
  --file "tamp-findings-$(date -u +%Y%m%dT%H%M%SZ).dump" \
  "$TAMP_FINDINGS_DB"
```

`--format=custom` rather than plain SQL: it compresses, and it restores selectively with `pg_restore`, which is what you want at 3am when one table is wrong. `--no-owner --no-privileges` so the dump restores into a database with different role names — which is the normal case when restoring production into a staging instance to test the restore.

### Cadence

| Kind | Frequency | Keep |
|---|---|---|
| Full `pg_dump` | Daily | 30 days |
| Full `pg_dump` | Weekly | 12 weeks |
| Full `pg_dump` | Monthly | As long as your attestations must stay verifiable |

That last row is the one people get wrong. **An attestation signed three years ago cites findings from three years ago.** If somebody may ask you to substantiate a CISA SSDF attestation five years after you signed it, a 30-day backup retention does not support that claim — and neither does a monthly backup you deleted after a year. Set the monthly retention from your attestation obligations, not from your storage budget.

Daily is the floor rather than a recommendation. An ingest happens on every build, so the window between backups is the window of scan evidence you would lose — if you build fifty times a day, consider WAL archiving / point-in-time recovery instead of a nightly dump.

### Verify the restore, not the backup

A backup you have never restored is a hypothesis. Restore into a scratch database on a schedule you can actually keep — quarterly is a reasonable floor — and check that the instance comes up against it:

```bash
createdb tamp_findings_restore_test
pg_restore --dbname tamp_findings_restore_test --no-owner --no-privileges backup.dump

TAMP_FINDINGS_DB="Host=…;Database=tamp_findings_restore_test;…" \
  docker run --rm -p 8080:8080 -e TAMP_FINDINGS_DB ghcr.io/tamp-build/tamp-findings

curl -fsS localhost:8080/ready
```

`/ready` returning 200 means the schema is intact and the app can talk to it. Then open a project and check a build you recognise.

---

## Restore

```bash
pg_restore \
  --dbname "$TAMP_FINDINGS_DB" \
  --no-owner \
  --no-privileges \
  --clean --if-exists \
  backup.dump
```

Then start the instance. It runs any pending migrations on boot, so restoring an older dump into a newer image is expected to work — the app migrates it forward.

**Restoring a NEWER dump into an OLDER image is not supported.** The schema will be ahead of the code, and EF will not migrate backwards. Pin the image version alongside the dump, or keep the two together in whatever you archive.

### Two things that do not survive a naive restore

**1. The Data Protection key ring.** It lives in the database, so a full restore brings it back. But if you restore *selectively*, or move to a fresh database, and skip that table, every encrypted secret becomes unreadable: identity-provider client secrets and the GitHub App private key. Nothing is lost that cannot be re-entered, but sign-in stops working until somebody does. Symptom: a `CryptographicException` in the logs and a provider that will not authenticate.

**2. Ingest tokens are hashes.** Only the SHA-256 is stored, so a restore brings back the tokens as they were — including the one your CI is using. Restoring an *older* dump therefore re-activates tokens you revoked after it was taken. If you restore around a credential incident, re-check the token lists on every project afterwards.

---

## Retention

Off by default. **Keeping everything is the honest default** for the reason above — evidence you deleted is evidence you cannot produce.

Under **System > Instance settings**:

- **Finding retention (days)** — deletes findings not seen in a build since that cutoff. Measured on last-seen, not first-seen: a finding raised two years ago and still present on last night's build is a current problem, and deleting it because it is old would remove the most overdue items first.
- **Build retention (days)** — deletes component versions older than the cutoff.

The sweep runs daily and **refuses to delete evidence something still refers to**:

- A build an attestation covers.
- A finding a POA&M item links.
- A finding with a suppression against it, or one marked Accepted.

Everything it declines to delete is counted, logged and recorded in the audit log, so a window that is keeping more than you configured is visible rather than a surprise during an audit.

It does not run at startup — a destructive job should not fire on every restart of a crash-looping container.

---

## Logs

Structured throughout, via `ILogger` with named properties rather than interpolated strings, so a log aggregator can filter on them.

Configure levels the usual ASP.NET way, in `appsettings.json` or via `Logging__LogLevel__Default`. For JSON output to a collector, set the console formatter:

```
Logging__Console__FormatterName=json
```

Lines worth alerting on:

| Message | Why |
|---|---|
| `Check-run queue is full` | Ingests are outrunning GitHub; check runs are being dropped, and a missing check looks identical to a passing one |
| `The GitHub App private key cannot be decrypted` | Key ring lost — checks have silently stopped appearing on pull requests |
| `The retention sweep threw` | Data is being kept beyond its window; a data-handling commitment is quietly going unmet |
| `Could not read whether the MCP endpoint is enabled` | The agent surface is failing closed, which is correct, but something is wrong underneath |
| `Reopened N finding(s) whose suppression expired` | Not a problem — this is the line that explains a score moving overnight |

**Telemetry is off and there is no switch.** Self-hosted means self-hosted; a compliance tool that phoned home would be reporting its customers' security posture to a third party. Nothing leaves the instance except what you configure: GitHub check runs, and outbound SMTP if you set it.
