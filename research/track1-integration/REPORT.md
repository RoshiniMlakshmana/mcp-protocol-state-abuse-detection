# Track 1 integration lab -- report

Research evidence toward a potential MITRE ATLAS contribution. Does not claim a new
vulnerability, does not assign an ATLAS ID, and was not submitted anywhere. Local-only; nothing
here was pushed or merged.

**Scope statement.** This is a controlled integration exercise against code this lab wrote and ran
on localhost, using two fictional resources and no real principal, credential, or production
system. It is **not** a discovered product vulnerability, **not** a proven unauthorized-access
exploit, and **not** evidence of a new MITRE ATLAS technique -- it demonstrates, with independent
corroborating evidence, how an existing, already-documented class of behavior (SEP-2243 header/body
desynchronization) manifests end-to-end against the real SDK, for use as supporting material in a
potential future ATLAS contribution.

**Revision note.** This report was revised after an internal review identified two gaps in the
original version: (1) case 3's "execution occurred" claim rested on response body/status alone,
without independent corroboration; (2) one telemetry event mislabeled an inference this lab's own
script made (from a successful response) as `server_native`, when no such verdict was actually
emitted by the server. Both are corrected below and in the code; superseded claims are not left
standing.

## Pinned versions / environment

- `@modelcontextprotocol/client@2.0.0`, `@modelcontextprotocol/server@2.0.0`,
  `@modelcontextprotocol/node@2.0.0` (exact pins in `package.json`; resolved versions confirmed
  via `npm ls --depth=0`).
- Node.js v24.18.0 (`node --version`), Windows.
- Reproduction: `cd research/track1-integration && npm install && bash run-lab.sh`.

## Every SDK adjustment made (complete list)

- **Exact versions:** `@modelcontextprotocol/client@2.0.0`, `@modelcontextprotocol/server@2.0.0`,
  `@modelcontextprotocol/node@2.0.0` -- all three pinned to an exact version (no `^`/`~` range) in
  `package.json`, resolved versions confirmed matching via `npm ls --depth=0`.
- **No files under `node_modules/` were edited.** Every package is installed exactly as published.
  `node_modules/` is git-ignored and was never staged; a fresh `npm install` against the committed
  `package.json`/`package-lock.json` reproduces the identical installed code -- no patch step, no
  `patch-package`, no manual edit is needed or was used.
- **One runtime configuration override is in effect**, a documented `ClientOptions` field, not a
  source change: `new Client(serverInfo, { versionNegotiation: { mode: { pin: '2026-07-28' } } })`
  in `client-runner.js` and `verify-case3.js`. Without it, the client's own default is
  `mode: 'legacy'` (confirmed in the shipped `.d.cts`: "The default is `'legacy'`... no probe, no
  new headers") -- Mcp-Method/Mcp-Name are never sent at all under that default, so this override is
  required to exercise SEP-2243 in the first place. This is stock, documented client behavior being
  invoked, not modified.
- **The server uses `createMcpHandler` + `toNodeHandler`** (`server.js`), both stock exports of the
  installed packages, instead of manually pairing a persistent `McpServer` with a per-request
  `NodeStreamableHTTPServerTransport`. This is a choice between two documented API surfaces of the
  same unmodified package, not a configuration override or a source edit -- see `server.js`'s own
  header comment for why the manual-pairing approach was abandoned (its `server/discover` pre-probe
  never succeeded). No `supportedProtocolVersions` override is present in the code that produced
  this report's evidence; an earlier attempt used one, before the switch to `createMcpHandler` made
  it unnecessary, and is described only in that comment as history, not as current behavior.
- **What "weakened mode" changes, precisely:** nothing about the real SDK. `weakened-server.js` is
  a separate, hand-written, clearly-labeled `node:http` process that imports neither
  `@modelcontextprotocol/client` nor `@modelcontextprotocol/server`, used only for bounded case 3.
  The real server (`server.js`) is never patched, configured, or otherwise made to skip its own
  check -- confirmed by reading its shipped source that no such bypass option exists at all (cited
  in `weakened-server.js`'s own header). Any behavior difference in case 3 is the stand-in process
  behaving differently from the real SDK, never the real SDK behaving differently from itself.

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
| 1 | Matching header/body: normal operation | success | **success.** Real server returned the resource. The `collector_derived` event resolves `method=match, name=match, result=valid`. (No `server_native` event is emitted for this or any success case -- see "Telemetry provenance correction" below for why.) | `evidence/raw/`, real server response body |
| 2 | Conflicting identifiers: validation rejects | rejected | **rejected**, genuinely, by the real server's own unconditional SEP-2243 check: HTTP 400, `{"error":{"code":-32020,"message":"...the body carries params.uri=\"lab://demo/task-a-alpha\" but the Mcp-Name header names \"lab://demo/task-b-bravo\""}}`. This -32020 error object IS the server's own validation path explicitly emitting a decision, so it is the one case that legitimately produces a `server_native` event; `collector_derived` independently agrees: both resolve `name=conflict, result=invalid`. | `evidence/raw/` (real-server-routed `resources/read` record) |
| 3 | Same conflict, weakened lab-only mode: observe, don't assume | **not assumed** | **The conflicting operation DID execute**, proven by THREE independent, mutually-corroborating sources keyed to the same request-instance ID, not response body/status alone: (a) the raw HTTP exchange (HTTP 200, `result.contents[0].uri = "lab://demo/task-a-alpha"` -- the body's identity, not the header's); (b) the weakened stand-in's own execution log, written by that process as a side effect of handling the request, before its response was sent (`action: "read_executed"`); (c) that process's own persisted read-counter state, incremented 0->1 for the requested URI. Separately, the **real client SDK reported this request as a client-side error** (`INVALID_RESULT`: the stand-in's minimal JSON response lacks the modern-era-required `resultType` envelope field) -- a client-side envelope-shape rejection, not evidence the server-side operation didn't happen. **Execution is proven and is not labeled unknown.** Whether it constitutes *unauthorized* access is a separate question this lab collected no evidence for, and stays `outcome_unknown`. | `evidence/case3-verification.json` (all three sources + findings), `evidence/raw/` (weakened-routed record), `evidence/weakened-server-execution-log.jsonl`, `evidence/weakened-server-state.json`, `evidence/client-observed-cases.json` (case 3 entry) |
| 4 | Encoded/decoded identity: no false mismatch | no mismatch | **no false mismatch.** Header re-encoded into the `=?base64?...?=` sentinel form by the gateway; the real server accepted it (200 success, implying no rejection was triggered) and `collector_derived` (this lab's own decode-then-hash) resolves `name=match, result=valid`. | `evidence/raw/`, `evidence/telemetry-events.json` |
| 5 | Concurrent requests, reused JSON-RPC id: no cross-request correlation errors | no cross-contamination | **No cross-contamination.** Two independent `Client`/transport pairs were fired concurrently; both naturally negotiated JSON-RPC `id: 0` for their first request (confirmed in `evidence/raw/` -- not forced by this lab). Because correlation used the gateway-generated request-instance ID (`lib/correlate.js`), not the JSON-RPC id, the two requests produced two distinct entries throughout `evidence/raw/`, `evidence/telemetry-events.json`, and `evidence/detector-evaluation.json` -- never merged into one. Both branches succeeded independently, reading their respective (different) fictional resources. | `evidence/raw/`, `evidence/detector-evaluation.json.perRequest` |

## Detector evaluation result

`evidence/detector-evaluation.json`: the existing Track 1 primary condition
(`mcp.validation.method.result=conflict OR mcp.validation.name.result=conflict`) fires for exactly
the two cases where a genuine header/body conflict is present in the collected evidence (case 2
and case 3), and does not fire for cases 1, 4, or either branch of case 5. `matchesExpectation:
true`. The diagnostic condition (missing/malformed) never fires, since no bounded case here
produces a missing or malformed header -- consistent with what was actually exercised.

## Telemetry provenance correction

The original `lib/audit.js` labeled a second event `server_native` for every request routed to the
real server, including successes -- reasoning that a 200 response implied the server's own
unconditional check had passed. That reasoning is wrong as a provenance label: the server's SDK
never separately surfaces a positive "validation passed" signal anywhere this lab can observe: a
success response only means no rejection was returned. Treating "no error" as an observed
`server_native: match` verdict meant this lab's own script was the one deriving that verdict from
captured traffic -- which is `collector_derived` by definition, even though the traffic originated
from a real server, per the standing rule in `telemetry/schema.md`.

**Fix:** `serverNativeVerdictIfEmitted()` in `lib/audit.js` now emits a `server_native` event ONLY
when the target response contains an explicit validation decision the server's own validation path
actually composed and returned -- in this lab, only the `-32020` HeaderMismatch error object
qualifies. Every other request (all four success cases) now carries only its `collector_derived`
event; no `server_native` event is fabricated for them. `evidence/telemetry-events.json` was
regenerated: 7 events (6 `collector_derived`, 1 `server_native`), down from the original,
partially-mislabeled 11. `evidence/detector-evaluation.json` was regenerated too; the detector's
result is unaffected (`matchesExpectation: true` before and after) since the corrected labeling
changes *provenance*, not which requests contain a conflict.

## What this lab demonstrates vs. what it assumes

**Demonstrated** (from actual request processing against real, pinned SDK code, read from its own
compiled source before being relied on -- not assumed from documentation):
- The real server's SEP-2243 header/body check is genuinely enforced, unconditionally, and rejects
  a real conflicting request with `-32020`.
- The real client never itself sends a mismatched header; the gateway is the only place this lab
  introduces one, matching the project's existing threat model.
- The Base64-sentinel encoding convention decodes to the correct identity under this lab's
  independent collector-side recomputation, and the real server accepted the request rather than
  rejecting it -- no false-positive mismatch. (The server itself does not emit an explicit
  "decoded correctly" verdict to confirm *how* it reached that outcome; only the absence of a
  rejection is observed -- see "Telemetry provenance correction.")
- Independent concurrent connections naturally reuse JSON-RPC ids, and request-instance
  correlation (not JSON-RPC id) keeps them distinct through the whole audit pipeline.
- In the deliberately unprotected lab-only mode, the conflicting operation genuinely executes --
  proven by an independent, out-of-band server-side execution log and a persisted state change,
  each correlated to the same request-instance ID, not inferred from the HTTP response alone.

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
