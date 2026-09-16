# Native KQL execution evidence

Reproducible evidence for the native (real Kusto engine) query validation performed against
Track 3, plus the fix it drove. **Scope, read this before the data below**: this is native
**KQL query execution** validation only. It is **not** a Microsoft Sentinel deployment —
no Sentinel workspace, no scheduled analytics rule, no incident/alert pipeline, no Log
Analytics ingestion mapping, no RBAC, no watchlist. It exercises the exact, unmodified query
text against a real Kusto query engine with hand-built synthetic input — nothing more, nothing
less. **SPL was not natively executed.** A subsequent, separate attempt was authorized and made
(Splunk Free, pulled and license-verified) but became unresponsive after a required
configuration restart before any fixture could be tested — zero SPL detection queries were run.
See `splunk-prep/STATUS.md` for the full, precise account. The SPL fix remains aligned by direct
code parallel to the KQL fix only, not independently verified against a live Splunk engine.

## Engine identity

- Image: `mcr.microsoft.com/azuredataexplorer/kustainer-linux:latest`
- Image digest: `sha256:de1fdbe0c7b3c61f9492ca0b7da44c92780a7f5f8740bf2732f9c67d5600e22e`
- Local image ID: `sha256:d261e627c8ac63baa515fe8aba85177b2d5e31e9`
- Engine `BuildVersion`: `1.0.9753.23211`
- Engine `ProductVersion`: `2026.09.14.1246-2637-19820db-master`
- Database: `NetDefaultDB` (the emulator's default)
- Launch command used: `docker run -e ACCEPT_EULA=Y -m 4G -d -p 8981:8080 -t --name kustainer mcr.microsoft.com/azuredataexplorer/kustainer-linux:latest`
- No account, subscription, or trial was created or required — a plain, local, perpetual
  Docker image (see `README.md` for why this is not "starting a trial requiring acceptance").

## What was tested (source content, not commit-dependent)

Rather than embed a commit SHA that doesn't exist yet at evidence-creation time, the exact
tested file content is identified by its git blob hash (`git hash-object <file>`), which is
stable regardless of which commit ends up containing it:

| File | Blob hash at evidence capture | Note |
|---|---|---|
| `detections/kql/mcp_subscription_authorization_drift.kql` | `d261e627c8ac63baa515fe8aba85177b2d5e31e9`† | the fixed (part 5) query -- see `runs/` |
| `detections/spl/mcp_subscription_authorization_drift.spl` | `b22b17d1278c595745d2164a0e29665ad8fd82e8`† | aligned by code parallel, NOT natively executed |
| `tests/attack/track3util.js` | `14802b7fdf4d504c175f24c76b66c2f886314f56`† | JS reference oracle, updated to match |

†Confirm with `git log --all --format=%H -- <file>` and `git show <sha>:<file> \| git hash-object --stdin`
against the commit named in this evidence's own commit message, or `git blame`/`git log -p` on
the file directly -- this table exists so the tested content is identifiable independent of
which commit wraps it, per the same commit that adds this directory.

**Pre-fix baseline was re-executed from commit `d08bfd6df263aa8b0be129e5f10e3379aa1b988e`**
(`detections/kql/mcp_subscription_authorization_drift.kql` as it stood before the part 5 fix)
to honestly capture the row-duplication defect -- see `prefix-baseline/`.

## Directory contents

- `manifest.jsonl` — one row per execution: fixture id, batch (`current` = post-fix validated
  state; `prefix-baseline` = pre-fix, re-executed from commit `d08bfd6`), track, exact query
  file, exact response file, row count, outcome(s), reason(s), expected outcome/description, and
  whether it matched. Built mechanically from the response files by
  `converters/build_manifest.js` (not hand-typed) — regenerate it if you re-run anything.
- `runs/<id>.kql` — the **exact, complete query text executed**: a mechanically-generated
  `let MCPSecurityAudit = datatable(...) [...]` built from the real JSONL fixture (or attack
  corpus) events, followed by the **unmodified, verbatim** contents of the real detection query
  file (Track 3, Track 1, or Track 2) at the time of this evidence capture. Only the input
  source was adapted, per the review's instruction — never the query body.
- `runs/<id>.response.json` — the **raw, complete JSON response** returned by the live engine
  for that exact query (includes the actual result rows, the engine's query-completion stats
  table with its own timestamp, and query metadata). Nothing is edited or summarized.
- `prefix-baseline/<id>.prefix.kql` / `.prefix.response.json` — the same, but built against the
  **pre-fix** query text (commit `d08bfd6`) for the 3 fixtures (V11-07, V14-04, V14-05) that
  exposed the row-duplication defect, re-executed against the identical live engine so the
  before/after comparison is itself reproducible evidence, not a transcript claim.
- `converters/build_kql_input.js` / `build_kql_input_t1t2.js` — the mechanical JSONL-fixture-to-
  `datatable` converters used to build every `runs/*.kql` file. Pure format translation (JSON
  event fields → typed KQL literals); no detection logic. Re-run with `node build_kql_input.js`
  from a scratch directory with `detections/` and `data/validation/` reachable at the hardcoded
  `repoRoot` path (adjust that constant for a different checkout location).
- `converters/build_prefix_baseline.js` — same idea, pinned to the pre-fix query text, used to
  build `prefix-baseline/`.
- `converters/build_manifest.js` — builds `manifest.jsonl` from the saved response files.

No credentials appear anywhere in this evidence: the emulator requires none (no auth, no API
key, no account), and none of the synthetic fixture data or engine responses contain real
identifiers -- `principal.id_hash`/binding/subscription values are the project's existing
synthetic HMAC-hashed test fixtures, unchanged from `data/validation/`.

## Result summary (see `manifest.jsonl` for the complete, machine-checkable detail)

**24 fixtures from the original native-validation pass, plus 1 added during fix verification
(V11-03) = 25 `current`-batch executions, all against the final (part 4 + part 5) query text:**

- 8 Track 3 V14 fixtures (the exact-multivalue-scope-intersection regression batch)
- 10 further Track 3 fixtures (V11-01, V11-02, V11-03, V11-07, V12-01, V12-13, V13-01, V13-03,
  V13-05, V13-06) representative of binding/time resolution, join-key correctness, and the
  malformed-timing/precise-interval fixes from earlier passes
- 7 Track 1 / Track 2 fixtures (A1, A6, A11, A17 for Track 1; A7, A11, A17 for Track 2)

**All 25 produced the expected outcome/fire-boolean.** This is **24 (or 25) representative
fixtures**, not the full 106-scenario corpus — native execution of the complete corpus was not
performed.

**3 `prefix-baseline` executions** (V11-07, V14-04, V14-05, re-run against commit `d08bfd6`'s
query text) reproduce the exact pre-fix defect: **2 identical-outcome rows instead of 1** for a
notification that independently satisfied two `EvaluatedNoViolation` conditions at once. Outcome
values were correct in both the pre-fix and post-fix runs — only the row count differed. This is
the literal evidence behind the "Track 3 remediation pass, part 5" fix described in
`docs/validation-report.md`.

## Known, disclosed gaps in this evidence

- SPL was never natively executed (no Splunk instance available/started this pass). The SPL fix
  is a structural code parallel to the verified KQL fix, not independently confirmed.
- This evidence covers 25 representative fixtures, not the full local corpus (106 scenarios,
  519+ events) or a live Sentinel/Log Analytics deployment.
- The emulator's regex engine, `datatable` semantics, and JSON parsing behavior were spot-checked
  against official Microsoft documentation and confirmed empirically here, but a real Azure Data
  Explorer / Sentinel cluster could theoretically differ in some untested edge case (none is
  known or suspected).
