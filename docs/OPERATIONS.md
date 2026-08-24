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

## Wiping an instance

Emptying a test or demo instance to start clean. **This revokes credentials**, which is the
part that surprises people — the data goes, and so does the instance's ability to be talked
to.

### Take a dump first, even for data you do not want

```bash
kubectl exec -n <ns> <postgres-pod> --   pg_dump -U <user> -d <db> --clean --if-exists > preclaim-backup.sql
grep -c "PostgreSQL database dump complete" preclaim-backup.sql   # must print 1
```

Costs seconds and makes the wipe reversible. Check the terminator: a dump that was cut off
mid-write still looks like a file.

### The wipe

```sql
DO $$
DECLARE tables text;
BEGIN
    SELECT string_agg(format('%I.%I', schemaname, tablename), ', ')
      INTO tables FROM pg_tables
     WHERE schemaname = 'public' AND tablename <> '__EFMigrationsHistory';
    EXECUTE format('TRUNCATE TABLE %s RESTART IDENTITY CASCADE', tables);
END $$;
```

`__EFMigrationsHistory` is kept deliberately: the schema then still matches the running image
and startup migrations stay a no-op. Dropping it instead makes the app re-run every migration
against tables that already exist.

Restart the app afterwards. The setup token is armed at startup and only when the user count
is zero, so an instance wiped while running stays unclaimable until it restarts.

### What a wipe revokes

Each of these is a table, so `TRUNCATE` takes it. None of them announce themselves.

| Table | What stops working |
|---|---|
| `IngestTokens` | **Every CI pipeline posting to this instance starts returning 401.** The token is stored as a SHA-256 hash; wiping the row does not invalidate the secret your pipeline holds, it just makes it match nothing. |
| `Clients`, `Projects`, `Components` | The hierarchy tokens are scoped to. A token cannot be re-minted until its client exists again. |
| `DataProtectionKeys` | Every existing session cookie. Also every encrypted identity-provider secret — though after a full wipe there are none left to decrypt. |
| `IdentityProviders` | Google/Entra/other configured sign-in methods. The built-in GitHub scheme survives because it is configured through environment variables, not the database — which is the only reason a wiped instance is still reachable at all. |
| `Users` | The admin seat. This is usually the point: the instance becomes claimable again. |

### Checklist after a wipe

1. **Restart** the deployment so the setup token arms, and read it from the startup log.
2. **Claim the admin seat** — sign in and enter that token. It disarms the moment it succeeds.
3. **Recreate the client** the pipeline posts under.
4. **Mint a new ingest token** and update wherever CI keeps it. Mint it through the API or the
   settings screen rather than with SQL, so it goes through the authorization path and is
   recorded:

   ```bash
   # as an authenticated admin
   curl -X POST "$URL/clients/$CLIENT_ID/tokens"         -H 'Content-Type: application/json'         -d '{"Name":"ci · <what it is for>"}'
   # plaintext is in the response ONCE and is never recoverable
   gh secret set TAMP_FINDINGS_INGEST_TOKEN < token.txt && rm token.txt
   ```

5. **Re-add identity providers** if the instance had any beyond the built-in GitHub scheme.
6. **Run the pipeline** and confirm the ingest returns 2xx rather than 401.

Skipping step 4 is the common one. The scans all still run and pass — it is only the step that
*reports* them that fails, so the pipeline looks broken in a way that has nothing to do with
scanning, and the receipts silently stop arriving.

---

## Pointing a build at an instance

`TAMP_FINDINGS_URL` decides where the Nuke ingest targets post. **Leave it unset locally** — the build then defaults to `http://localhost:5080`.

That default is deliberate. It used to be set to the cluster in the repo-root `.env`, which made production the target of every local run: an ingest invoked while trying something out wrote to the shared instance, and succeeded, so nothing said otherwise. The safe target should be the one you get without thinking about it.

Set it only for a deliberate roll, together with a token minted **on that instance** — tokens are per-instance and a cluster token just 401s against localhost. Comment both back out afterwards. The build prints a banner whenever the target is not localhost, so a forgotten setting is visible rather than silent.

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
