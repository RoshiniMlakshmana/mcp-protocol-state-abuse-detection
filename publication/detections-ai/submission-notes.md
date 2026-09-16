# detections.ai Submission Notes

## Recommended initial publication priority

1. **Detection 1 — MCP Task Routing Header/Body Desynchronization Attempt.** Simplest, highest
   confidence, single-event, no known environmental false-positive class beyond an
   instrumentation dependency that is itself clearly documented.
2. **Detection 2 — MCP Cross-Principal Task Authorization Violation.** Single-event, highest
   confidence of the three (no environmental false positive found during stress testing), but
   requires the consuming SOC to understand it credits, not claims discovery of, an
   already-known SEP-2663 risk class.
3. **Detection 3 KQL/SPL — MCP Long-Lived Subscription Authorization Drift.** Multi-event
   correlation with an explicit, must-read deployment prerequisite (grace periods / open-stream
   exemptions). Publish the KQL/SPL as the real detection; **treat the Sigma correlation as a
   separate, clearly-labeled hunting artifact, not part of this priority group** — see below.

## Per-track detail

### Detection 1

- **What to publish:** the Sigma rule (`detections/sigma/mcp_task_routing_desynchronization.yml`)
  as the primary submission, with the KQL and SPL as implemented counterparts (same single-event
  filter logic. Separately written JS predicates agree on the tested fixtures
  (`tests/validation/language_equivalence.test.js`) — this does not establish native query
  equivalence; KQL has since also been natively executed for a representative sample, see
  below, but SPL has not). The diagnostic
  rule (`mcp_task_routing_missing_header_diagnostic.yml`) should be submitted as a clearly
  separate, Low-severity item — never merged into the primary submission.
- **Preferred language:** Sigma (single-event, fully expressible, no known limitation).
- **Known limitations:** entirely dependent on upstream canonicalization; see
  `publication/detections-ai/detection-1-task-routing-desynchronization/metadata.md`.
- **Required telemetry:** `mcp.request.validation` event and its `mcp.validation.*` fields —
  see `telemetry/schema.md`.
- **Validation scenarios:** true positives Block 4 A1–A5, A17; Block 6 V2-01 (Track 1 leg);
  true negatives all of Block 3, plus Block 6 V1-01…V1-07, V1-09.
- **Known operational false positives:** V1-08 (collector canonicalization artifact) —
  mechanically fires, confirmed benign, not a rule defect. See
  `docs/validation-report.md`, View 2.

### Detection 2

- **What to publish:** the Sigma rule
  (`detections/sigma/mcp_cross_principal_task_authorization.yml`) as the primary submission,
  with KQL and SPL as implemented counterparts (same single-event filter logic. Separately
  written JS predicates agree on the tested fixtures
  (`tests/validation/language_equivalence.test.js`) — this does not establish native query
  equivalence; KQL has since also been natively executed for a representative sample, see
  below, but SPL has not).
- **Preferred language:** Sigma (single-event, fully expressible, no known limitation).
- **Known limitations:** depends on trustworthy server-side `mcp.authz.reason` labeling; cannot
  see identity/credential theft upstream of the authorization decision. See
  `docs/evasion-limitations.md`.
- **Required telemetry:** `mcp.task.authorization` event and its `mcp.authz.*`/`mcp.task.*`
  fields — see `telemetry/schema.md`.
- **Validation scenarios:** true positives Block 4 A7–A10, A17; true negatives all of Block 3
  (including N7's three benign-denial sub-cases), Block 4 A11, Block 6 V3-01…V3-07, V4-01, V4-02.
- **Known operational false positives:** none found during Block 6 stress testing — the only
  bucket item related to Track 2 (V3-02) was determined to be a genuine historical true
  positive, not a false positive, and is documented as such (`docs/validation-report.md`,
  View 2).

### Detection 3 — publish KQL/SPL and Sigma **separately**

- **What to publish (priority group above):** the KQL and SPL queries only, each carrying the
  explicit deployment-prerequisite warning verbatim (grace periods / open-stream exemptions).
  Do not publish this as a "no known limitations" detection.
- **Preferred language:** KQL or SPL — both implement the same documented resolution algorithm
  (SPL is a direct structural port of KQL, not an independent re-derivation). Two separate,
  non-equivalent claims exist here — do not merge them: (1) **JS-model comparison** — two
  independently-coded JS models of each language's own written semantics compared row-for-row
  across the full stress corpus (`tests/validation/language_equivalence.test.js`), agreeing
  except for one intentional, named exception (fixture V14-07 — see below); (2) **native KQL
  execution** — KQL alone has since been executed against a real Kusto engine (see "Validation
  and native-execution disclosures" below). **KQL execution alone does not verify agreement with
  SPL — SPL has not been natively executed at all**, so native execution establishes nothing
  about cross-language equivalence, only about KQL's own behavior. Do not read "equivalent" as
  meaning both languages carry the same native-execution confidence.
- **Track 3 Sigma — treat separately, not as part of the initial priority group.** The Sigma
  correlation rule and its component rules should be submitted, if at all, explicitly labeled
  **"best-effort correlation / hunting content — not semantically equivalent to KQL/SPL"** in
  the submission's own title or description, with the comparison matrix from
  `publication/detections-ai/detection-3-subscription-authorization-drift/metadata.md` included
  verbatim. Do not let a detections.ai listing imply parity between the Sigma artifact and the
  KQL/SPL queries.
- **Required telemetry:** `mcp.subscription.*`, `mcp.authz.change.*`, `mcp.authz.valid_until` —
  see `telemetry/schema.md`.
- **Validation scenarios:** true positives Block 4 A12–A14 (and experimental A-EXP1); Block 6
  V5-07, V6-02; true negatives Block 4 A15, A16, all of Block 3, Block 6 V5-01, V5-04, V5-05,
  V5-06, V6-01.
- **Known operational false positives:** V5-02 (grace period), V5-09 (permanent exemption) —
  both mechanically fire, both confirmed benign, neither is a rule defect. **Any consumer of
  this detection must read this before enabling it as a paging alert.**

## Validation and native-execution disclosures (include in every submission)

- **All validation data is synthetic**, generated by this project's own deterministic reference
  harness (`tools/harness/`) — never production telemetry, never captured from a real MCP
  deployment.
- **Every one of these three detections requires custom MCP security audit instrumentation and
  field mapping.** None of the required fields are emitted by Sentinel, Splunk, or any
  OpenTelemetry deployment by default — see `telemetry/schema.md` and `telemetry/field-mapping.md`.
- **An alert from any of these rules does not, by itself, prove compromise or successful
  unauthorized access.** Each has documented, confirmed conditions under which it fires on
  entirely benign activity (see each track's "Known operational false positives" above) — treat
  a hit as an investigation starting point, not a verdict.
- **Native KQL execution status, precisely:** 25 (fixture × detection-track) test cases — 23
  unique synthetic event fixtures, 2 of which were each run against two different tracks — were
  executed against a real Kusto query engine: Microsoft's local "Kusto emulator" Docker image
  (`mcr.microsoft.com/azuredataexplorer/kustainer-linux`). **This is native KQL query execution
  only — it is NOT a deployed Microsoft Sentinel analytics rule, workspace, scheduled rule, or
  alert pipeline.** All 25 produced the expected outcome. A further 3 executions re-ran the
  pre-fix query text specifically to document a row-duplication defect before/after its fix (28
  total native KQL query executions are recorded). Breakdown: Detection 1 — 4 executions (A1,
  A6, A11, A17); Detection 2 — 3 executions (A7, A11, A17); Detection 3 — 18 executions (V11-01,
  V11-02, V11-03, V11-07, V12-01, V12-13, V13-01, V13-03, V13-05, V13-06, V14-01 through V14-08)
  plus the 3 pre-fix re-executions (V11-07, V14-04, V14-05). Full per-execution record:
  `evidence/native-execution/manifest.jsonl`.
- **Native SPL execution has not been performed for any of the three detections. Zero SPL
  fixtures were executed.** An authorized attempt was made using a local Splunk Free instance
  (license verified genuinely Free, not a trial) but the instance became unresponsive after a
  required configuration restart before any fixture could be tested; the root cause of the
  unresponsiveness is unconfirmed. See `evidence/native-execution/splunk-prep/STATUS.md` for the
  full account. SPL remains verified only by hand-review and structural parallel to KQL.

## General submission guidance

- Every query file already states, in its own header comment, that `MCPSecurityAudit`
  (KQL) / `index=mcp_security_audit sourcetype=mcp:audit:json` (SPL) is a project/example
  placeholder, not a built-in table. Preserve that language verbatim in any detections.ai
  listing — do not let a platform's default table-name convention silently imply these fields
  exist out of the box.
- Do not submit any query with its false-positive/limitations section stripped, even if
  detections.ai's submission form makes that section optional. This project's standing rule
  (`CONTRIBUTING.md`) is that limitations are documented in the same submission that introduces
  the detection.
