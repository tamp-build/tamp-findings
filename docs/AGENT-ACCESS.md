# Giving an agent access

How to put an AI agent on a tamp.findings instance so it can read findings while it fixes them, and what that agent can and cannot do once it is there.

Written for the case this was first needed for: a tenant whose remediation is done by agents rather than only by people, where more than one agent — belonging to more than one person — needs the same instance.

---

## What the agent gets

An [MCP](https://modelcontextprotocol.io) endpoint at `/mcp` with seventeen tools on it. Fourteen are reads: an agent can see every piece of evidence its token reaches and change none of it.

That is a design decision, not an omission. An agent able to file a suppression is an agent able to retire the finding it was asked to fix, and the only reason this product is worth running is that the evidence is not negotiable. ADR 0019 settles the shape for anything beyond reading: an agent may propose, and only a person decides.

Two narrow writes exist on top of that, and neither touches evidence:

- **`create_project`** — in the token's own client, for an Architect-roled token. Not reversible.
- **`harden_gate`** — *tighten* one gate. Never loosen, never disable, never lower enforcement. Off until an administrator enables **Let agents help configure policy** under System → Instance settings, and closed outright when the deployment locks enforcement through configuration.

The default is closed on both counts, and the choice is yours to make: a small team may want an agent that helps configure the gates, while somewhere with real exposure will want policy to be a human act. The product does not decide that.

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
| `get_policy` | Gates, thresholds, enforcement — and which layer imposed each value |
| `create_project` | Create a project in the token's client (Architect-roled tokens; not reversible) |
| `harden_gate` | Tighten one gate — never loosen. Needs the instance to allow agent policy authoring |

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

A token carries a `ProjectRole`, and everything it does goes through the same `CapabilityEvaluator` a person's does. There is no separate agent authorization path, because a second path is a second place to get it wrong and the one nobody watches.

**The role now decides more than what the agent can read.** It is what separates an agent that observes from one that can create a project or tighten a gate, so this is a choice worth a moment rather than a default.

| Role | Can read | Can export | Can create a project | Can tighten a gate |
|---|---|---|---|---|
| *(none — Viewer)* | yes | no | no | no |
| `Auditor` | yes | yes | no | no |
| `LeadDev` | yes | yes | no | no |
| `Architect` | yes | yes | **yes** | **yes**¹ |

¹ And only when the instance allows agent policy authoring, and the deployment has not locked enforcement. See [§4a](#4a-decide-whether-agents-may-help-configure-policy).

**`Auditor` is still the right default.** Give an agent `Architect` when you actually want it changing the shape of the project — and remember that a project it creates cannot be deleted.

Two rules constrain what you can mint:

- **You cannot mint more than you hold.** An agent is not a way to grant yourself access.
- **No agent carries `InfoSecOfficer`** — not even one minted by an InfoSecOfficer. That role holds `AcceptRisk`, accepting risk is an Authorizing Official's signature, and a credential that produces it on their behalf is a way around the signature rather than an exercise of it. Refused at mint, absent from the dropdown, and a property of ADR 0019 rather than a setting.

### 4a. Decide whether agents may help configure policy

**System → Instance settings → "Let agents help configure policy".** Off by default, and the default is a choice rather than a precaution.

A small team finding its way toward a posture may want an agent that helps configure the gates — the second pair of hands is help, and the blast radius is their own project. Somewhere with real exposure will want policy to be a human act. Neither is wrong, and the product does not decide it for you.

With it on, an `Architect` token can **tighten** a gate: enable one, or lower a threshold. What no setting grants, ever:

- loosening a threshold,
- disabling a gate,
- lowering enforcement,
- anything at all to the risk-scoring weights.

That asymmetry is the whole guarantee, and the reasoning is in [ADR 0019 §5](adr/0019-agent-proposals-not-decisions.md): **an agent may make a build harder to ship, never easier.** A tightening fails loudly, blocks something, and gets reverted by whoever it inconvenienced within the hour. A loosening ships a build and the record says it was allowed to.

Two other things close policy authoring regardless of this switch:

- **The MCP kill switch.** Closing the surface closes authoring with it — an operator reaching for that switch does not want writes surviving it.
- **A deployment enforcement lock.** If `Enforcement:Locked` is set in configuration, policy editing through this surface is refused with a permission error, because a platform team's posture is not locally negotiable. Policy *reads* keep working.

Policy reads are unconditional in every configuration. An agent that cannot read the policy cannot explain a verdict it is already allowed to see.

### 4b. Or do the whole thing without a browser

Minting used to be UI-only, which meant the agent surface depended on a client page existing — and on a fresh instance it did not, so an operator could not obtain any agent token at all (TFND-259). Every step now has a route:

```bash
# 1. the client (administrator)
curl -sS -X POST https://findings.example/clients   -H 'Content-Type: application/json' -b cookies.txt   -d '{"name":"Indelible"}'

# 2. the project
curl -sS -X POST https://findings.example/projects   -H 'Content-Type: application/json' -b cookies.txt   -d '{"name":"inform","clientId":"<client-id>"}'

# 3. the agent token — PROJECT scope, which is the one to reach for
curl -sS -X POST https://findings.example/projects/<project-id>/agent-tokens   -H 'Content-Type: application/json' -b cookies.txt   -d '{"name":"claude · remediation","role":"Auditor","expiresInDays":90}'
```

The plaintext comes back **once**, in the `token` field. `GET` the same path for metadata on existing tokens, and `DELETE /agent-tokens/{id}` to revoke.

These are cookie-authed like the rest of the management API, and they go through exactly the same rules as the UI: `AssignRoles` to mint, the client-scope requirement, and the refusal to mint `InfoSecOfficer`. A client-scoped variant exists at `POST /clients/{id}/agent-tokens` for an agent that genuinely spans a tenant's portfolio.

Why a project scope needs nothing extra: a project implies its client, so the token carries both. "Mint at the client level" was never the requirement — the requirement is that a token names a client, and a project does.

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
- **Do not let it re-raise settled work.** A finding on a POA&M has an owner and a date; a dispositioned conformance verdict has a justification; a suppression is a decision somebody already made. Proposing a fix for any of them is fine. Presenting them as unaddressed is not. An *expired* suppression is the one case where re-raising is right, and it is marked.
- **Do not let it infer code it cannot see.** This instance stores source only for files a coverage report brought in. Everywhere else `context` is null, and the agent should read the file from the repository rather than reasoning from the scanner's snippet.
- **Do not ask it to attest to anything.** Attestation is a signature. An agent holds no `AcceptRisk`, cannot touch evidence, and should not be the author of a compliance claim even in prose.

And two about the writes, which are newer and less obvious:

- **Do not expect it to undo a project.** `create_project` is irreversible — there is no delete or rename anywhere in the application. An agent that offers to clean up after itself is wrong about what it can do.
- **Do not let it report a gate change it did not make.** Policy layers merge to the strictest value, so a tightening that is looser than what a template or client already imposes changes nothing. `harden_gate` refuses those and names the layer, but an agent that paraphrases the refusal as success has told you the release contract moved when it did not. Ask it which layer is in force; `get_policy` says.

---

## See also

- [`README.md` § Agent access (MCP)](../README.md#agent-access-mcp) — the short version
- [`OPERATIONS.md`](OPERATIONS.md) — probes, backup, retention, logs
