# Draft: ATLAS mitigation update -- routing-header/body consistency

Status: internal draft, not submitted. No new technique; no ATLAS ID requested.

## 1. Proposed contribution

An update to two existing ATLAS mitigations' guidance text, naming routing-header/request-body
consistency checking as a concrete instance of validation they already cover in general terms --
supported by audit-telemetry guidance and a controlled integration exercise showing the behavior
end-to-end against a real, pinned SDK.

**Candidate placements.** Existing MITRE wording below is quoted verbatim from a fresh
primary-source verification (not a mirror, not memory): MITRE's own `atlas-data` repository,
commit `3259f388d19cbcca11bacf12a0ef97f4198f711b`, release `2026.09`,
`dist/v6/ATLAS-2026.09.yaml`, SHA-256 `935efa93e28294432d3e2f537eb94991ef8d1f8c58341cd360ea3321ddb66688`
(matches the value supplied for this check), retrieved 2026-09-16. An earlier draft cited a
third-party MISP-galaxy mirror instead; that was not first-party verification and is superseded
here. The mirror's text matched MITRE's own except for one silently-truncated quotation (AML.M0024,
corrected below).

Each bullet quotes MITRE's own description verbatim (partial quotes marked `...`), followed by
this draft's own commentary -- clearly not MITRE text.

- **AML.M0033, "Input and Output Validation for AI Agent Components"** (MITRE's own text):
  "Implement validation on inputs and outputs for the tools and data sources used by AI agents.
  Validation includes enforcing a common data format, schema validation... Validation should be
  performed external to the AI agent." -- *Commentary (ours):* a routing header disagreeing with
  the request body it accompanies (e.g. MCP's `Mcp-Method`/`Mcp-Name`) is a data-format consistency
  problem between two representations of the same invocation -- a specific case of "enforcing a
  common data format" at a component boundary, exactly as M0033 already scopes it.
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
| 1 | Matching header/body (standard enforcement) | Executed; real server's own SEP-2243 check active | Accepted | N/A -- no conflict |
| 2 | Conflicting header/body (standard enforcement) | **Rejected** by the real server's own check (`-32020` HeaderMismatch) | Rejected (server error) | N/A -- rejected before execution |
| 3 | Same conflict, **explicitly weakened lab-only mode** | **Executed** (proven independently, not by response alone -- see below) | Rejected (unrelated client-side envelope-shape error) | `outcome_unknown` -- no authorization evidence collected |
| 4 | Encoded/decoded identity, matching (standard enforcement) | Executed; no false-positive mismatch | Accepted | N/A -- no conflict |
| 5 | Concurrent requests, reused JSON-RPC id (standard enforcement) | Both executed independently, no cross-contamination | Both accepted | N/A -- no conflict |

Case 3's stand-in is a hand-written `node:http` process, not the SDK, used because the real server
has no documented option to disable its own check. Its execution was proven by three independent,
mutually-corroborating sources keyed to one gateway-issued correlation ID -- the raw HTTP exchange,
an out-of-band execution log, and a persisted state-change (a read counter, 0->1) -- not response
status alone. Execution is not labeled unknown; only whether it was *authorized* is (no separate
authorization evidence exists).

## 3. Proposed mitigation text (addition)

The block below is entirely this draft's own proposed text, not MITRE's:

> Where a routing-layer signal (e.g., a header) and the request body it accompanies each carry a
> value identifying the same tool, resource, or task, validate that the two values agree before
> routing or executing the request -- applying the protocol's required decoding first (e.g.,
> reversing any header encoding convention) so equivalent representations of the same identity are
> not flagged as conflicting. Reject requests where the values disagree rather than routing on one
> and executing on the other. Record the validation decision (agreement, conflict, or
> missing/malformed) in telemetry, and correlate it with independent evidence of what a downstream
> component actually did, using request context generated by a trustworthy component in the
> request path -- not a client-supplied or otherwise attacker-influenceable identifier. The
> resulting record should distinguish a rejected attempt from one that reached execution.

## 4. Supporting evidence

All evidence is local to this repository, on branch `research/track1-integration-evidence`, which
**has not been pushed and is not publicly accessible** -- the paths below are repository-relative
for a reviewer with local access, not links to a public GitHub URL.

- Report and case-by-case evidence: `research/track1-integration/REPORT.md`
- Raw wire records: `evidence/raw/*.json`
- Case 3 independent-execution cross-check: `evidence/case3-verification.json`,
  `evidence/weakened-server-execution-log.jsonl`, `evidence/weakened-server-state.json`
- Derived telemetry/detector evaluation: `evidence/telemetry-events.json`, `evidence/detector-evaluation.json`
- Pinned dependencies and reproduction: `package.json`, `package-lock.json`,
  `README.md` ("Reproduction": `npm install && bash run-lab.sh`)
- Existing published detection this telemetry maps to (unchanged by this lab, paths from repo
  root): `detections/sigma/mcp_task_routing_desynchronization.yml`,
  `detections/sigma/mcp_task_routing_missing_header_diagnostic.yml`,
  `detections/kql/mcp_task_routing_desynchronization.kql`,
  `detections/spl/mcp_task_routing_desynchronization.spl`

## 5. Limitations

- Controlled, local-only lab, two fictional resources; not a discovered product vulnerability, not
  a proven unauthorized-access exploit.
- Case 3's stand-in is explicitly weakened, non-SDK, clearly labeled -- the real SDK's check was
  never bypassed, patched, or disabled; it has no such option.
- Requires custom telemetry instrumentation (`lib/audit.js`); no product ships this by default.
- Correlation uses a gateway-issued request-instance ID, not one from the MCP server SDK itself --
  verified not overridable by client input (`REPORT.md`), but lab-specific, not a standardized field.
- No claim of a new ATLAS technique; only wording additions to two existing mitigations.
- The project's native-KQL testing (a local Kusto emulator, `evidence/native-execution/`) is
  unrelated to this exercise, whose own detector evaluation used a JS reference-oracle model
  (`tests/detections/oracle.js`), not a native query engine; Splunk was not involved or restarted.
