# Library-archetype control dispositions — decision ledger (TFND-209 follow-on / noUnmapped)

**Status: IN PROGRESS.** This is the durable record of control-disposition decisions for the
**Library** archetype under **FedRAMP Rev 5 High**, worked against the real unmapped set on
`tamp-core` (client Tamp). It is the *source of truth* for the eventual content pack — the
`ArchetypeLayers`/template `ControlAssertion`s are generated from these rules, not the other way
round. Nothing here is live in prod until the pack is built + deployed (dispositions are derived from
policy assertions we haven't authored yet).

Baseline snapshot (tamp-core, FedRAMP High) at start: **inScope 370 · Gated 14 · Inherited 127 ·
NotApplicable 0 · Unmapped 229.** The 229 below are what we're dispositioning. Already-inherited
operational families (PE, CP, MP, IR, PS, MA, AT) are in the 127 and out of scope here.

Disposition kinds: **Gated** (we own it and evidence proves it), **Inherited** (applies, provided by a
layer below this artifact — carries `InheritedFrom` + justification), **NotApplicable** (precondition
absent — carries justification). Merge rule: an archetype `NotApplicable`/`Inherited` only *fills*
otherwise-Unmapped controls; it never overrides a template `Gated` claim (`PolicyLayerMerge`
strictness Gated<Inherited<NotApplicable). Everything is downgrade-proof (findings-authored per
archetype) with a reviewed per-project override for genuine edges.

---

## Decision rules (the pack is generated from these)

### Rule L-INHERIT-OPS — runtime/operational families a code library does not implement
For **Library**, these are provided by the deploying/hosting **system**, not the artifact:
- **AC** (Access Control) — all account/session/remote-access/least-privilege controls. *(38 controls; a library has no users, sessions, or runtime access surface.)*
- **IA** (Identification & Authentication) — all. *(No users to authenticate in a library.)*
- **AU** (Audit & Accountability) — all. *(Runtime audit logging is the deployed system's job.)*
- **SC** (System & Communications Protection) — boundary, DNS, DoS, isolation, session, **and the crypto cluster** (see Borderline #1). *(A library terminates no connections and stores nothing.)*
- **PL** (Planning) — `PL-2/4/4(1)/8` (SSP, rules of behavior, architecture — org authorization docs).

`InheritedFrom` = "the system that deploys this library (hosting platform + consuming service, under its ATO)". **Archetype-specific: these flip to Gated/Owned for a Service archetype.**

### Rule L-INHERIT-PROGRAM — org/authorization common controls (all archetypes under an ATO)
Documentation/assessment/program controls owned by the org's authorization boundary, not any artifact:
- **CA**: `CA-2/2(1)/2(2)`, `CA-3/3(6)`, `CA-6`, `CA-8(1)`, `CA-9`
- **SA**: `SA-2/3/4*/5/8/9*/16/17/21` (SDLC/acquisition/dev-program docs)
- **SR**: `SR-2/2(1)/5/6/8/12`, `SR-11(1)`
- **RA**: `RA-2/3/7/9`
`InheritedFrom` = "organizational common-control provider / authorization boundary".

### Rule L-NA — genuine not-applicable (precondition absent anywhere)
- Wireless: `AC-18/18(1)/18(3)/18(4)/18(5)`, `SI-4(14)`, `SC-40` — "system implements no wireless."
- Mobile devices: `AC-19/19(5)` — "no mobile devices."
- Collaborative computing: `SC-15` — "no cameras/microphones."
- Mail: `SI-8/8(2)` — "no messaging/mail service."

### Rule L-OWN — controls tamp's own evidence proves (map to a gate → Gated)
Candidates (pending gate-existence confirmation — see Open questions):
- `CA-5` Plan of Action & Milestones → the POA&M board
- `CA-7`/`CA-7(4)` Continuous Monitoring / Risk Monitoring → findings itself
- `SI-2(2)` Automated flaw-remediation status → findings lifecycle
- `SI-7`/`SI-7(1)`/`SI-7(15)` Software/firmware/code integrity → EO provenance + SLSA + SHA-256 digests
- `SR-9`/`SR-9(1)` Tamper resistance/detection, `SR-10` component inspection → provenance + SBOM
- `RA-3(1)` Supply-chain risk assessment → SBOM + vuln
- `CM-8(1..4)` inventory enhancements → SBOM + diff

---

## Borderline resolutions (walked one at a time)

### #1 — Crypto cluster → **Inherited** ✔ RESOLVED
`SC-8`, `SC-8(1)`, `SC-13`, `SC-28`, `SC-28(1)`, `SC-12`, `SC-12(1)`, `SC-17`, `IA-7`.
Read `/c/repos/tamp` directly: tamp-core's only `System.Security.Cryptography` use is SHA-256 content
digests (`AbsolutePath.cs:294-310`), the `sha256:` artifact hash + input-hash build cache
(`Executor.cs:265`), and a CSPRNG span id (`Executor.cs:124`). **No encryption, signing, key
management, TLS, or third-party crypto lib.** So no confidentiality cryptography or crypto module is
implemented in-component → Inherited from the validated platform module (.NET/OS) and the deploying
system. Note: the SHA-256 hashing is *integrity*, not confidentiality — it feeds `SI-7`/`SR-9`
(already Owned), and does **not** move this cluster to Owned.

### Open borderline queue (not yet decided)
- `SI-11` error handling, `SI-12` retention — service-owns / library-inherits (archetype-dependent)
- `SC-18` mobile code — is the artifact mobile code?
- `SA-22` unsupported components — own via SBOM EOL detection? (do we detect EOL today?)
- `CM-8(3)` unauthorized-component detection, `CM-3(1)` automated change control, `CM-6(1)` automated config verification — gate-if-we-build-the-signal
- `RA-5(11)` public disclosure / VDP — org vs us
- `PL-10`/`PL-11` baseline selection & tailoring — findings-meta (arguably the tool that does this)
- `SA-10` developer config mgmt, `SA-15(3)` criticality analysis — hybrid

---

## Open questions before the pack build
1. Confirm each **L-OWN** control has (or gets) a real gate to assert against — otherwise it's Inherited, not Gated. `CA-5`→`poamPastDue` exists; `SI-7`→EO-provenance gate?; `CA-7`→no single gate (whole-system).
2. Template layer vs archetype layer placement: program/common controls (L-INHERIT-PROGRAM) + L-OWN are the same for all High systems → **template**; the archetype-varying ops (L-INHERIT-OPS) → **archetype layer**.
3. Whether L-NA (wireless/mail/mobile) is safe at template level for all tamp projects, or belongs on the Library archetype / per-project.
