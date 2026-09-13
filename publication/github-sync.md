# detections.ai GitHub Sync — Readiness and Steps

**Status: repository organized and publication-ready. External sync has NOT been performed or
verified from this environment — no authenticated detections.ai session or GitHub push
credential is available here.**

## Repository organization for discoverability

Detection rule files are grouped by language under `detections/`, one file per rule (plus
component/correlation files for Track 3's Sigma content), so a GitHub Sync integration scanning
the repository for rule files can find them predictably:

```
detections/sigma/*.yml      -- 7 files: 3 detection rules (2 for Track 1, 1 for Track 2),
                                3 Track 3 component rules, 1 Track 3 correlation rule
detections/kql/*.kql        -- 3 files, one per track
detections/spl/*.spl        -- 3 files, one per track
detections/README.md        -- full documentation per rule
detections/field-mapping.md -- exact field/placeholder-table reference
```

No rule's YAML/KQL/SPL structure was altered to guess undocumented parser behavior — every file
already conforms to the standard Sigma rule/correlation-rule specification (verified
structurally in `tests/detections/sigma_structure.test.js`) or to plain, documented KQL/SPL
syntax. If a specific sync integration has an undocumented preference (e.g., a particular
directory depth or naming convention), that should be confirmed against the actual integration
at connection time rather than guessed here.

## Steps to connect (per the documented GitHub Sync workflow)

1. **Make the repository public** on GitHub (this project's content contains no secrets, real
   credentials, or private paths — see the repository cleanup review in
   `publication/novelty-check.md`'s sibling files and this project's `.gitignore`).
2. In detections.ai, go to **Integrations**.
3. Select **GitHub** → **Configure**.
4. Provide the **public repository URL**.
5. Click **Connect**.
6. Choose **manual** or **automatic** sync, depending on how often this repository's detection
   content is expected to change.
7. After the first sync, **verify the imported rules in the Detection Library** — confirm rule
   count, titles, and that the Track 3 Sigma correlation content (if included) is not displayed
   as equivalent to the Track 3 KQL/SPL detections.

## What is NOT claimed

- **This project has not pushed this repository to a public GitHub URL from this environment,**
  and has not connected or run an actual GitHub Sync with detections.ai. No authenticated
  publishing mechanism (GitHub push credentials, a detections.ai session) is available from
  this tool environment.
- **Publication package complete; external publication pending.** The steps above are the
  documented workflow to complete manually once the repository is pushed to a public GitHub
  URL under the user's own account/organization.

## Recommended sync scope for the first pass

Given `publication/detections-ai/submission-notes.md`'s priority order, if the sync integration
allows scoping (e.g., by path or tag), the first-pass import should prioritize Detection 1 and
Detection 2's Sigma rules plus all three KQL/SPL files, and should either exclude or clearly
annotate the Track 3 Sigma correlation content per its documented, non-equivalent status.
