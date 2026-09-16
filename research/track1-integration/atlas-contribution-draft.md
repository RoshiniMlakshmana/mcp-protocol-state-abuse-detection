# Draft: ATLAS mitigation update -- routing-header/body consistency

Status: internal draft, not submitted. No new technique; no ATLAS ID requested.

## 1. Proposed contribution

An update to two existing ATLAS mitigations' guidance text, naming routing-header/request-body
consistency checking as a concrete instance of validation they already cover in general terms --
supported by audit-telemetry guidance and a controlled integration exercise showing the behavior
end-to-end against a real, pinned SDK.

**Candidate placements.** Existing MITRE wording below is quoted verbatim from MITRE's own
`atlas-data` repository: `https://raw.githubusercontent.com/mitre-atlas/atlas-data/3259f388d19cbcca11bacf12a0ef97f4198f711b/dist/v6/ATLAS-2026.09.yaml`
-- release `2026.09`, commit `3259f388d19cbcca11bacf12a0ef97f4198f711b`, SHA-256
`935efa93e28294432d3e2f537eb94991ef8d1f8c58341cd360ea3321ddb66688`, retrieved 2026-09-16. (Prior
sourcing history and the mirror correction are recorded in `REPORT.md`, not repeated here.)

Each bullet quotes MITRE's own description verbatim (partial quotes marked `...`), followed by
this draft's own commentary -- clearly not MITRE text.

- **AML.M0033, "Input and Output Validation for AI Agent Components"** (MITRE's own text):
  "Implement validation on inputs and outputs for the tools and data sources used by AI agents.
  Validation includes enforcing a common data format, schema validation... Validation should be
  performed external to the AI agent." -- *Commentary (ours):* a routing header disagreeing with
  the request body it accompanies (e.g. MCP's `Mcp-Method`/`Mcp-Name`) is a data-format consistency
  problem between two representations of the same invocation. We propose explicitly extending this
  guidance to semantic consistency between routing metadata and the corresponding request-body
  values, even when each representation is individually well-formed.
- **AML.M0024, "AI Telemetry Logging"** (MITRE's own text): "Implement logging of inputs and
  outputs of deployed AI models... implement logging of the intermediate steps of agentic actions
  and decisions, data access and tool use... Monitoring logs can help to detect security threats
  and mitigate impacts." -- *Commentary (ours):* the addition below is narrower -- the logged
  validation decision should be correlated with what a downstream component actually did, using
  correlation context the logging layer itself generates, not a client-supplied identifier, so a
  rejected attempt is not conflated with an executed one.

## 2. Demonstrated behavior

Five bounded cases, run against the real, pinned MCP SDK
(`@modelcontextprotocol/{client,server,node}@2.0.0`) plus one clearly-labeled, non-SDK stand-in
used only for case 3.

| # | Case | Server execution | Client response validation | Authorization outcome |
|---|------|------|------|------|
| 1 | Matching header/body (standard enforcement) | Executed; real server's own SEP-2243 check active | Accepted | Not evaluated |
| 2 | Conflicting header/body (standard enforcement) | **Rejected** by the real server's own check (`-32020` HeaderMismatch) | Rejected (server error) | Request rejected; authorization not evaluated |
| 3 | Same conflict, **explicitly weakened lab-only mode** | **Executed** (proven independently, not by response alone -- see below) | Rejected (unrelated client-side envelope-shape error) | `outcome_unknown` -- no authorization evidence collected |
| 4 | Encoded/decoded identity, matching (standard enforcement) | Executed; no false-positive mismatch | Accepted | Not evaluated |
| 5 | Concurrent requests, reused JSON-RPC id (standard enforcement) | Both executed independently, no cross-contamination | Both accepted | Not evaluated |

Case 3's stand-in is a hand-written `node:http` process, not the SDK, used because no documented
disable option was identified in the pinned real server. Its execution was proven by corroborating
wire, execution-log, and persisted-state evidence keyed to one gateway-issued correlation ID -- not
response status alone. The execution log and state counter are instrumentation added to that same
lab stand-in process, not an independent observer external to it, and are separate from the
detector's verdict (`evaluate-detector.js`'s JS-model evaluation of the derived telemetry, which
answers a different question -- whether the existing Track 1 rule condition fires -- not whether
execution occurred). Execution is not labeled unknown; only whether it was *authorized* is (no
separate authorization evidence exists).

## 3. Proposed mitigation text (two independently usable additions)

Both blocks below are entirely this draft's own proposed text, not MITRE's -- each usable on its
own, without requiring the other:

**Addition to AML.M0033:**

> Validate corresponding action/target values at the relevant trust boundary before relying on
> them for routing or execution. Apply protocol-defined decoding and comparison rules; reject
> conflicts.

**Addition to AML.M0024:**

> Log validation decisions and correlate them with downstream execution evidence using trustworthy
> request context. Distinguish rejection, observed execution, and unavailable execution evidence.
> Note that execution does not itself establish unauthorized access.

## 4. Supporting evidence

All evidence is local to this repository (`mcp-protocol-state-abuse-detection`, branch
`research/track1-integration-evidence`), which **has not been pushed and is not publicly
accessible.** Every path below is given in full from the repository root -- none are relative to
the lab directory alone.

- Report and case-by-case evidence: `research/track1-integration/REPORT.md`
- Raw wire records: `research/track1-integration/evidence/raw/*.json`
- Case 3 independent-execution cross-check: `research/track1-integration/evidence/case3-verification.json`,
  `research/track1-integration/evidence/weakened-server-execution-log.jsonl`,
  `research/track1-integration/evidence/weakened-server-state.json`
- Derived telemetry/detector evaluation: `research/track1-integration/evidence/telemetry-events.json`,
  `research/track1-integration/evidence/detector-evaluation.json`
- Pinned dependencies: `research/track1-integration/package.json`,
  `research/track1-integration/package-lock.json`
- Reproduction (working directory: repository root): `cd research/track1-integration && npm
  install && bash run-lab.sh` (see `research/track1-integration/README.md`)
- Existing published detection this telemetry maps to (unchanged by this lab):
  `detections/sigma/mcp_task_routing_desynchronization.yml`,
  `detections/sigma/mcp_task_routing_missing_header_diagnostic.yml`,
  `detections/kql/mcp_task_routing_desynchronization.kql`,
  `detections/spl/mcp_task_routing_desynchronization.spl`

## 5. Limitations

- Controlled, local-only lab, two fictional resources; not a discovered product vulnerability, not
  a proven unauthorized-access exploit.
- Case 3's stand-in is explicitly weakened, non-SDK, clearly labeled -- the real SDK's check was
  never bypassed, patched, or disabled. No documented disable option was identified in the pinned
  SDK.
- This exercise uses project-defined audit instrumentation (`lib/audit.js`); deployment requires
  verifying telemetry availability and field mapping.
- Correlation uses a gateway-issued request-instance ID, not one from the MCP server SDK itself --
  verified not overridable by client input (`REPORT.md`), but lab-specific, not a standardized field.
- The weakened stand-in trusts whatever gateway-supplied identifier it receives, unsigned -- this
  exercise does not demonstrate protection against direct access to the stand-in bypassing the
  gateway, or against a compromised gateway itself.
- No claim of a new ATLAS technique; only wording additions to two existing mitigations.
- The project's native-KQL testing (a local Kusto emulator, `evidence/native-execution/`) is
  unrelated to this exercise, whose own detector evaluation used a JS reference-oracle model
  (`tests/detections/oracle.js`), not a native query engine; Splunk was not involved or restarted.
