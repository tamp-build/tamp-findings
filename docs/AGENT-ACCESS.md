# Giving an agent access

How to put an AI agent on a tamp.findings instance so it can read findings while it fixes them, and what that agent can and cannot do once it is there.

Written for the case this was first needed for: a tenant whose remediation is done by agents rather than only by people, where more than one agent — belonging to more than one person — needs the same instance.

---

## What the agent gets

A read-only [MCP](https://modelcontextprotocol.io) endpoint at `/mcp`, and five tools on it. No write path: an agent can read every piece of evidence its token reaches and change none of it.

That is a design decision, not an omission. An agent able to file a suppression is an agent able to retire the finding it was asked to fix, and the only reason this product is worth running is that the evidence is not negotiable. Whether agents get a *propose-only* path — ask for a suppression, and a human decides — is an open question tracked as TFND-240.

| Tool | Answers |
|---|---|
| `list_scope` | Which clients and projects this token reaches. Start here; every other tool takes a project id from it |
| `get_gate` | Whether the latest build is clear to ship, and which gates block it — with the evaluator's own reasons |
| `get_score` | The risk score, its band, and which categories are costing it |
| `list_builds` | Recent canonical builds, each scored and gated |
| `get_findings` | Open findings on the latest canonical build, worst first, filterable by severity / scanner / commit / path |
| `get_finding` | One finding in full, with surrounding source where the instance holds it |
| `get_dependencies` | A project's newest SBOM as packages plus flat parent→child edges, advisories attached |
| `get_suppressions` | What has already been muted and why — suppressions and VEX together |
| `get_controls` | Which compliance controls the project owns, inherits or has ruled out — and which are still unmapped |
| `list_poams` | Open POA&M items, their owners and dates — the answer to "why is this still open" |
| `get_conformance` | ADR-conformance verdicts: claims checked against the project's own decision records |
| `get_quality` | Tests and coverage for the latest canonical build |
| `get_license_worklist` | Packages whose licence nobody could classify — the evidence-gathering an agent is good at |
| `get_posture` | Branch protection, required reviews, signed commits, org 2FA |

A remediation agent should start at `get_gate`, not at `get_findings`. Severity ranks findings; a gate decides releases, and the worst finding is often not the thing blocking the build.

---

## Standing it up

### 1. Open the endpoint

**System → Instance settings → MCP.** Off by default, and on a fresh instance you have to turn it on before any token works.

This switch is the kill switch. Turning it off closes the door in one action without revoking anything, so every token survives the pause and nothing has to be re-minted when you open it again. That is what you reach for when something is wrong and you want the agents out *now* — not the revoke button.

A token presented while the switch is off is refused at the door, before the tool layer runs.

### 2. Mint one token per agent

**Project → Settings → Agent access**, or **Client → Agent access** for a token spanning that client's whole tree.

**One token per agent. Never a shared one.** Two agents behind one credential cannot be told apart: `LastUsedAt` becomes meaningless, the audit trail says only "something read this", and revoking the compromised one revokes the other at the same time. The cost of getting this wrong is paid later, under pressure, when you are trying to work out which agent did something and find that the instance cannot tell you.

Name the token after the agent *and* its job — `claude · remediation`, `selena-agent · triage`. The label is the only thing a revoke decision six months from now has to go on, and "token 1" is not a decision you can make.

### 3. Pick the scope deliberately

Tokens are scoped **down, never up**:

| Scope | Sees |
|---|---|
| Project | That project and its builds. Never a sibling project |
| Client | Every project under that client |

There is no instance-wide scope. It is refused at mint, because a read token over every tenant is a standing grant to whatever holds it.

Default to **project scope**. Client scope is right when one agent genuinely works across a tenant's whole portfolio, and wrong the rest of the time — the blast radius of a leaked credential is exactly its scope.

### 4. Pick the role deliberately

A token carries a `ProjectRole`, and every read it makes goes through the same `CapabilityEvaluator` a person's does. There is no separate agent authorization path, because a second path is a second place to get it wrong and the one nobody watches.

| Role | Give it when |
|---|---|
| `Auditor` | The agent should read everything, including exports. The usual answer |
| `LeadDev` / `Architect` | The agent's reads should match a particular human seat's |
| *(none — Viewer)* | Reads evidence, cannot export |

Two rules constrain what you can mint:

- **You cannot mint more than you hold.** An agent is not a way to grant yourself access.
- **No agent carries `InfoSecOfficer`** — not even one minted by an InfoSecOfficer. That role holds `AcceptRisk`, accepting risk is an Authorizing Official's signature, and a credential that produces it on their behalf is a way around the signature rather than an exercise of it. Refused at mint, and absent from the dropdown.

Since the surface is read-only, role mostly decides whether the agent can export. It will decide much more if TFND-240 lands, so mint as though it already matters.

### 5. Connect the agent

The plaintext is shown **once** and is never recoverable. Put it where that agent reads its secrets from before you navigate away.

```
claude mcp add --transport http tamp-findings https://findings.example/mcp \
  --header "Authorization: Bearer mcp_..."
```

### 6. Verify the blast radius before you hand it over

Call `list_scope` with the token and read what comes back. It is the one check that catches a mis-scoped mint, and it takes a second:

```
curl -sS https://findings.example/mcp \
  -H "Authorization: Bearer mcp_..." \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"list_scope","arguments":{}}}'
```

If it lists a project that agent has no business reading, revoke and re-mint narrower. If it lists nothing, the token is scoped to a client with no projects yet, or the role it carries cannot view evidence — the response says which.

---

## Keeping it running

**Tokens expire after 90 days by default.** Agents are given credentials and then forgotten about, and a read token that outlives the agent it was minted for is a standing grant to whatever now holds it. Shorten it if the engagement is shorter; do not lengthen it because rotation is inconvenient.

Nothing warns you before one lapses. Plan the rotation when you mint, because the failure mode is an agent that quietly stops being able to read anything and reports the instance as empty rather than as closed to it.

**Minting and revoking are both recorded as access-class audit entries**, with the label, the scope tier and the role. `LastUsedAt` on each token row is how you find the ones nobody is using — those are the ones to revoke.

**Revoke on any of:** the agent is retired, the person it belongs to leaves, the credential may have leaked, or it has not been used in a while and nobody can say why it exists. Revoking is per-token and immediate; the token stops resolving on its next request.

---

## What not to ask an agent to do with it

The surface is honest about its own limits, and those limits should match what you expect of the agent reading through it.

- **Do not treat a count as complete.** `get_findings` is capped and reports the true total. When `truncated` is true the agent has a filtered view, and "there are 200 findings" is a wrong number carrying this product's name.
- **Do not let it confuse a gate with a severity.** `get_gate` is the release decision; `get_findings` is the work. A critical finding that no gate covers does not block a build, and an `Unknown` verdict blocks one with no finding behind it at all — the remedy there is the pipeline, not the code.
- **Do not let it call an advisory failure a blocked release.** Under `Advisory` enforcement a failing gate is recorded and ships. `get_gate` reports the mode; an agent that ignores it will escalate something that was not blocking.
- **Do not let it quote a verdict for code that has changed.** Every verdict names the commit it belongs to. Once the agent has edited the tree, the verdict it holds describes the build *before* its work.
- **Do not let it read `firstSeen` as a finding's age.** Findings are keyed per build, so a year-old finding gets a fresh `firstSeen` every build it survives. `firstSeenInProject` is the age; `introducedInThisBuild` is what attributes it to the change under review.
- **Do not let it author a compliance claim.** A control disposition is an authored human position with the project as its authority — the agent can read one and must not propose one, and an `Unmapped` control is an unanswered question rather than a pass or a fail.
- **Do not let it read an absence as a pass.** No conformance run is not conformance. No test report is not a green build. No posture observation is not a passing check. Each tool says so in its own words; an agent that skips the `note` will get all three wrong in the same direction.
- **Do not let it re-raise settled work.** A finding on a POA&M has an owner and a date; a dispositioned conformance verdict has a justification. Proposing a fix for either is fine. Presenting either as unaddressed is not.
- **Do not let it infer code it cannot see.** This instance stores source only for files a coverage report brought in. Everywhere else `context` is null and the agent should read the file from the repository rather than reasoning from the scanner's snippet.
- **Do not let it re-raise settled work.** `get_suppressions` is the record of what a person already decided. An expired suppression is the one case where re-raising is right, and it is marked.
- **Do not ask it to attest to anything.** Attestation is a signature. The agent has no write path, holds no `AcceptRisk`, and should not be the author of a compliance claim even in prose.

---

## See also

- [`README.md` § Agent access (MCP)](../README.md#agent-access-mcp) — the short version
- [`OPERATIONS.md`](OPERATIONS.md) — probes, backup, retention, logs
