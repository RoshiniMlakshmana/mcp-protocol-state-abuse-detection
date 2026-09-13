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
  as the primary submission, with the KQL and SPL as parity implementations. The diagnostic
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
  with KQL and SPL as parity implementations.
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
- **Preferred language:** KQL or SPL — both are the authoritative implementation and are
  mutually equivalent (`tests/validation/language_equivalence.test.js`).
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
