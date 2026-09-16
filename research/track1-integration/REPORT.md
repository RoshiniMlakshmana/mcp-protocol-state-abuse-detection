# Track 1 integration lab -- report

Research evidence toward a potential MITRE ATLAS contribution. Does not claim a new
vulnerability, does not assign an ATLAS ID, and was not submitted anywhere. Local-only; nothing
here was pushed or merged.

## Pinned versions / environment

- `@modelcontextprotocol/client@2.0.0`, `@modelcontextprotocol/server@2.0.0`,
  `@modelcontextprotocol/node@2.0.0` (exact pins in `package.json`; resolved versions confirmed
  via `npm ls --depth=0`).
- Node.js v24.18.0 (`node --version`), Windows.
- Reproduction: `cd research/track1-integration && npm install && bash run-lab.sh`.

## Evaluation method (explicit, per instruction)

`evaluate-detector.js` runs `track1PrimaryFires`/`track1DiagnosticFires` from the main project's
own `tests/detections/oracle.js`, unmodified -- a **plain-JS reference-oracle model**, the same
approach the main project's existing test suite uses (see `detections/README.md`). This is **NOT**
execution against a native query engine (no Sigma backend, no Sentinel/KQL, no Splunk/SPL).
**Splunk was not restarted or otherwise touched by this lab.** The main project's own native-Splunk
attempt remains permanently closed out per
`../../evidence/native-execution/splunk-prep/STATUS.md`; this lab does not reference or reuse that
container.

## Bounded cases: expected vs. observed

All outcomes below are read directly from `evidence/raw/*.json` (what the gateway put on the wire
and what each target actually returned) and `evidence/telemetry-events.json` (events derived from
those raw records), not assumed.

| # | Case | Expected | Observed | Source |
|---|------|----------|----------|--------|
| 1 | Matching header/body: normal operation | success | **success.** Real server returned the resource; `server_native` and `collector_derived` events both resolve `method=match, name=match, result=valid`. | `evidence/raw/`, real server response body |
| 2 | Conflicting identifiers: validation rejects | rejected | **rejected**, genuinely, by the real server's own unconditional SEP-2243 check: HTTP 400, `{"error":{"code":-32020,"message":"...the body carries params.uri=\"lab://demo/task-a-alpha\" but the Mcp-Name header names \"lab://demo/task-b-bravo\""}}`. Both `server_native` and `collector_derived` independently agree: `name=conflict, result=invalid`. | `evidence/raw/` (real-server-routed `resources/read` record) |
| 3 | Same conflict, weakened lab-only mode: observe, don't assume | **not assumed** | **The conflicting operation DID execute** at the weakened stand-in: HTTP 200, `result.contents[0].uri = "lab://demo/task-a-alpha"` (the body's identity, not the header's) -- i.e. the stand-in acted on the body while ignoring the conflicting header, exactly as its lack of a SEP-2243 check implies. Separately, the **real client SDK reported this request as a client-side error** (`INVALID_RESULT`: the stand-in's minimal JSON response lacks the modern-era-required `resultType` envelope field) -- this is a client-side envelope-shape rejection, not evidence the server-side operation didn't happen; the raw HTTP evidence is the authoritative record here, and it shows execution occurred. **This does not, by itself, establish unauthorized access** -- no separate authorization evidence was collected in this lab, so that question is recorded as `outcome_unknown` in `evidence/telemetry-events.json`'s `weakenedModeExecutionFacts`, not asserted either way. | `evidence/raw/` (weakened-routed record) + `evidence/client-observed-cases.json` (case 3 entry) + `evidence/telemetry-events.json.weakenedModeExecutionFacts` |
| 4 | Encoded/decoded identity: no false mismatch | no mismatch | **no false mismatch.** Header re-encoded into the `=?base64?...?=` sentinel form by the gateway; both `server_native` (real server decodes it correctly) and `collector_derived` (this lab's own decode-then-hash) resolve `name=match, result=valid`. | `evidence/raw/`, `evidence/telemetry-events.json` |
| 5 | Concurrent requests, reused JSON-RPC id: no cross-request correlation errors | no cross-contamination | **No cross-contamination.** Two independent `Client`/transport pairs were fired concurrently; both naturally negotiated JSON-RPC `id: 0` for their first request (confirmed in `evidence/raw/` -- not forced by this lab). Because correlation used the gateway-generated request-instance ID (`lib/correlate.js`), not the JSON-RPC id, the two requests produced two distinct entries throughout `evidence/raw/`, `evidence/telemetry-events.json`, and `evidence/detector-evaluation.json` -- never merged into one. Both branches succeeded independently, reading their respective (different) fictional resources. | `evidence/raw/`, `evidence/detector-evaluation.json.perRequest` |

## Detector evaluation result

`evidence/detector-evaluation.json`: the existing Track 1 primary condition
(`mcp.validation.method.result=conflict OR mcp.validation.name.result=conflict`) fires for exactly
the two cases where a genuine header/body conflict is present in the collected evidence (case 2
and case 3), and does not fire for cases 1, 4, or either branch of case 5. `matchesExpectation:
true`. The diagnostic condition (missing/malformed) never fires, since no bounded case here
produces a missing or malformed header -- consistent with what was actually exercised.

## What this lab demonstrates vs. what it assumes

**Demonstrated** (from actual request processing against real, pinned SDK code, read from its own
compiled source before being relied on -- not assumed from documentation):
- The real server's SEP-2243 header/body check is genuinely enforced, unconditionally, and rejects
  a real conflicting request with `-32020`.
- The real client never itself sends a mismatched header; the gateway is the only place this lab
  introduces one, matching the project's existing threat model.
- The Base64-sentinel encoding convention decodes correctly on both the real server's own check and
  this lab's independent collector-side recomputation -- no false-positive mismatch.
- Independent concurrent connections naturally reuse JSON-RPC ids, and request-instance
  correlation (not JSON-RPC id) keeps them distinct through the whole audit pipeline.
- In the deliberately unprotected lab-only mode, the conflicting operation genuinely executes at
  the HTTP/server level.

**Not demonstrated / explicitly out of scope:**
- Whether case 3's executed operation constitutes *unauthorized* access -- this lab collected no
  separate authorization evidence, so that question is recorded as `outcome_unknown`, not answered.
- Native query-engine behavior (Sigma backend / Sentinel KQL / Splunk SPL) -- this lab's detector
  evaluation is a JS reference-oracle model only, same as the main project's own test suite; it
  says nothing new about native execution one way or the other.
- Anything about Tracks 2 or 3, or about the published `detections/` rules, all of which are
  unchanged by this lab.

## Known limitation of this evidence

Bounded case 3's client-observed outcome (`error`, `INVALID_RESULT`) is a byproduct of the
weakened stand-in's minimal, hand-written response shape not including fields a real 2026-07-28
server is required to include -- it is not a finding about SEP-2243 enforcement, and is called out
here specifically so it is not misread as "the weakened case failed to execute" when the raw
evidence shows the opposite.
