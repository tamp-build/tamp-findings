# Embedded OSCAL control catalog

These files ship **with the product** so a fresh deploy (Docker image / Helm /
Bicep) stands up with the full NIST SP 800-53 Rev 5 control catalog by default —
no admin upload, no network fetch, air-gap safe. They are ingested into the
`ControlCatalog` at startup (see `Program.cs` → OSCAL seed).

- `catalog.json` — NIST SP 800-53 Rev 5 OSCAL 1.2 catalog (control text + params)
- `baseline-{low,moderate,high}.json` — NIST 800-53B baseline profiles (control
  membership per baseline)

Source: https://github.com/usnistgov/oscal-content (`nist.gov/SP800-53/rev5/json`).
NIST OSCAL content is a work of the U.S. Government and is in the public domain
(17 U.S.C. §105) — redistribution here is unrestricted.

To update: replace these files with a newer OSCAL release; the startup seed
imports the new version as the current catalog and retains the prior one (an
attestation cites the catalog version it signed against).
