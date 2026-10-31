# Versioning — which build is this instance running?

Every tamp.findings instance can say exactly which build it runs: the product version, the git commit it was built from, and when it was built. Quote that whenever you report a problem, and check it before comparing two instances.

This page exists because, until TFND-267, nobody could. Every instance's OpenAPI document said `"version": "1.0.0"`, `/version` returned the assembly's numeric `0.1.0.0`, and the only real record of the build was a container image tag that nothing outside the cluster can see. On 2026-10-31 a customer instance turned out to be running **newer** code than our own lab (it served the agent-token API; the lab, still on a 2026-10-03 image, did not), and reports about "missing" features could not be triaged without first working out which build had answered.

---

## Reading it

| Where | What you get | Needs credentials |
|---|---|---|
| `GET /version` | The full record, machine-readable (below) | **No** |
| `X-Tamp-Findings-Version` response header | The one-line form, on **every** response, including errors | No |
| `GET /openapi/v1.json` → `info.version` | The one-line form; `info.description` adds the build time | No |
| `GET /health` → `version` | The one-line form | No |
| The UI | Bottom of the sidebar, on every page; hover for commit and build time | Signed in |

```console
$ curl -s https://findings.example.org/version
{
  "service": "tamp.findings.api",
  "version": "0.1.0-alpha",
  "commit": "db8af85443a99ed85f99171a82812a8186c4a215",
  "commitShort": "db8af85",
  "builtAt": "2026-10-31T14:50:25+00:00",
  "display": "0.1.0-alpha+db8af85",
  "runtime": ".NET 10.0.14",
  "source": "https://github.com/tamp-build/tamp-findings/commit/db8af85443a99ed85f99171a82812a8186c4a215"
}
```

`display` is the value to quote. It is identical in the header, the OpenAPI document, `/health` and the UI, so any one of them is enough.

`/version` is anonymous on purpose. A CI job, an agent, or a person filing a report needs it without a token. It carries only what the image is already labelled with — the product version, a commit of the public repository, and the build time — and nothing about the deployment, its configuration or its data.

### When filing a report

Include the `display` value (or the whole `/version` body). Without it, "the server returns X" cannot be checked against code: the instance may be ahead of `main`, behind it, or on a branch.

### Comparing two instances

Read `/version` on both. If the commits differ, `git log --oneline <older>..<newer>` in this repository is exactly what one has that the other does not. Comparing the route lists of the two `/openapi/v1.json` documents is a useful cross-check, but it is the commit that answers the question.

---

## What each field means and where it comes from

| Field | Meaning | Source |
|---|---|---|
| `version` | The **product** version | `<Version>` in `Directory.Build.props`. Bumped by hand when a release is cut; between releases many builds share it, so on its own it does not identify a build. |
| `commit` | The git commit the binary was built **from** | Stamped by the SDK as `+<sha>` on the assembly's informational version (`SourceRevisionId`). Locally, SourceLink reads it from `.git`. In the container, `.git` is not in the build context (`.dockerignore`), so the build passes it as the `GIT_SHA` build argument. |
| `builtAt` | When the image was built (UTC) | The `BUILD_TIMESTAMP` build argument, stamped as `BuildTimestamp` assembly metadata. |
| `display` | `version` + `+` + the 7-character commit | Derived. Without a commit it is just `version`. |

The values are **stamped into the assembly at build time**, so they describe the binary that is actually running. They are not read from environment variables, which a deployment could set to anything.

### How the image build stamps it

`dotnet run --project build -- DockerBuildImage` (and therefore `Deploy`) passes:

```
--build-arg GIT_SHA=<full commit>
--build-arg BUILD_TIMESTAMP=<UTC, ISO-8601>
```

and labels the image with the standard OCI keys `org.opencontainers.image.revision`, `.created` and `.source`, so `docker inspect` agrees with `/version`.

Caveats, so the stamp is not read as more than it is:

- **The commit is what the build started from, not proof the tree was clean.** A build from a working tree with uncommitted changes reports `HEAD`'s commit. Release and lab images are built from a clean checkout of `main`.
- **A bare `docker build` without the arguments reports no commit** (`commit: null`, `display` = the product version). That is deliberate: an unstamped build must never look like a known one.

---

## The ingest contract across versions

Producers (the `Tamp.Ingest.V1` client, tamp wrappers, custom pipelines) talk to many instances at different versions. The contract is kept compatible like this:

- **Additive only within v1.** New endpoints and new optional request fields may appear; existing fields are not removed or repurposed. Fields an older server does not know are ignored, so a newer producer can talk to an older server.
- **Enums travel by name.** `ScannerKind`, `Severity`, `FindingStatus` and the rest are serialised as strings. A value the server does not have is rejected (`400`), never silently mapped to something else, so a producer learns the server is older than it expected. Example: the server has `ScannerKind.Nuclei`; a client library whose enum lacks it must send `Unknown`, which is honest but loses information (TAM-293).
- **Ingest responses carry what was stored**, including the `componentVersionId` of the build the evidence landed on (TFND-266). Log that, not what you sent.
- **Build identity is the commit.** Evidence for one commit lands on one build however many version strings producers stamp on it; two commits are two builds even if they share a version string (TFND-264). Always send `commitSha`.

When a producer and a server disagree, compare `/version` against the producer's library version before anything else.

---

## Operating it

- After a deploy, `curl /version` and check `commit` is the commit you meant to ship. The lab deploy prints the image tag; the two should agree.
- When a report arrives from another instance, ask for its `/version` first. If it is ahead of the lab, redeploy the lab from `main` before reproducing.
