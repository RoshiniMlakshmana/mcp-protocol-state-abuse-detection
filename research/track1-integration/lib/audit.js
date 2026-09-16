'use strict';
/**
 * Derives telemetry-contract (telemetry/schema.md) `mcp.request.validation` events from the RAW
 * gateway/server records under evidence/raw/*.json -- i.e. from what was actually observed on
 * the wire and actually returned by a target process, never from the client SDK's own outcome
 * classification (client-observed-cases.json is a separate, client-side view; see REPORT.md for
 * why the two can and do disagree for bounded case 3).
 *
 * Only `resources/read` requests are identity-bearing under this lab (the only method exercised
 * that telemetry/schema.md lists as carrying an Mcp-Name-comparable identity); `server/discover`,
 * `initialize` and `notifications/initialized` are protocol plumbing and produce no
 * `mcp.request.validation` event, matching the schema's own scope for that event type.
 *
 * Two independent verdict sources per applicable request, per telemetry/schema.md's
 * `mcp.validation.source` field:
 *  - `server_native`: emitted ONLY when the real server's (@modelcontextprotocol/server@2.0.0)
 *    own validation path actually produced a decision this lab can read back verbatim -- in
 *    practice, its -32020 HeaderMismatch error object. A 200 success is deliberately NOT treated
 *    as an observed server_native verdict: the SDK never separately surfaces a positive
 *    "validation passed" signal, so inferring "match" from "no error was returned" would make
 *    THIS SCRIPT the source of that verdict, which is collector_derived by definition even though
 *    the traffic came from a real server. See serverNativeVerdictIfEmitted's own comment. Never
 *    emitted for the weakened stand-in, which performs no such check by design.
 *  - `collector_derived`: independently recomputed here by hashing the header-side identity
 *    (decoding the Base64 sentinel form first, per schema) and the body-side identity with the
 *    same HMAC scheme (tools/harness/lib/hash.js) and comparing for equality -- emitted for EVERY
 *    applicable request (including successes and requests routed to the weakened stand-in), since
 *    this comparison needs no cooperation from the target at all -- it is derived purely from the
 *    raw header/body values this lab itself sent.
 */
const fs = require('node:fs');
const path = require('node:path');
const { hmacHash } = require('../../../tools/harness/lib/hash');

const RAW_DIR = path.join(__dirname, '..', 'evidence', 'raw');
const OUT_FILE = path.join(__dirname, '..', 'evidence', 'telemetry-events.json');
const WEAKENED_EXECUTION_LOG = path.join(__dirname, '..', 'evidence', 'weakened-server-execution-log.jsonl');

const REAL_SERVER_PORT = Number(process.env.TRACK1_LAB_SERVER_PORT || 4001);

/** Independent execution-log entries written by weakened-server.js itself, keyed by the
 * gateway-issued requestInstanceId it received via X-Lab-Request-Instance -- see gateway.js and
 * weakened-server.js. Used to corroborate (or fail to corroborate) execution independent of the
 * HTTP response the gateway proxied back. */
function loadWeakenedExecutionLog() {
  const map = new Map();
  let raw;
  try {
    raw = fs.readFileSync(WEAKENED_EXECUTION_LOG, 'utf8');
  } catch {
    return map;
  }
  for (const line of raw.split('\n')) {
    if (!line.trim()) continue;
    const entry = JSON.parse(line);
    if (entry.requestInstanceId) map.set(entry.requestInstanceId, entry);
  }
  return map;
}

const SENTINEL_RE = /^=\?base64\?([A-Za-z0-9+/=]*)\?=$/;
function decodeSentinel(value) {
  if (value === null || value === undefined) return value;
  const m = SENTINEL_RE.exec(value);
  if (!m) return value;
  return Buffer.from(m[1], 'base64').toString('utf8');
}

function safeParseJson(raw) {
  if (!raw) return null;
  // Streamable HTTP responses may be plain JSON or a one-event SSE frame
  // ("event: message\ndata: {...}\n\n") -- both were observed in this lab's own evidence.
  const sseMatch = /^event:\s*message\s*\ndata:\s*(\{[\s\S]*\})\s*$/m.exec(raw.trim());
  const jsonText = sseMatch ? sseMatch[1] : raw;
  try {
    return JSON.parse(jsonText);
  } catch {
    return null;
  }
}

function loadRawRecords() {
  const files = fs.readdirSync(RAW_DIR).filter((f) => f.endsWith('.json'));
  return files.map((f) => JSON.parse(fs.readFileSync(path.join(RAW_DIR, f), 'utf8')));
}

function collectorDerivedEvent(record, headerIdentityHash, bodyIdentityHash) {
  const headerMethod = record.gatewayForwarded.headers['mcp-method'] ?? null;
  const bodyMethod = record.gatewayObserved.body.method;
  const methodResult = headerMethod === null ? 'missing' : headerMethod === bodyMethod ? 'match' : 'conflict';
  const nameResult =
    headerIdentityHash === null || bodyIdentityHash === null
      ? 'missing'
      : headerIdentityHash === bodyIdentityHash
      ? 'match'
      : 'conflict';
  return {
    'event.name': 'mcp.request.validation',
    requestInstanceId: record.requestInstanceId,
    labCase: record.labCase,
    'mcp.body.method': bodyMethod,
    'jsonrpc.request.id': String(record.gatewayObserved.body.id),
    'mcp.header.method': headerMethod,
    'mcp.header.name_hash': headerIdentityHash,
    'mcp.body.identity_hash': bodyIdentityHash,
    'mcp.validation.method.result': methodResult,
    'mcp.validation.name.result': nameResult,
    'mcp.validation.result': methodResult === 'match' && nameResult === 'match' ? 'valid' : 'invalid',
    'mcp.validation.source': 'collector_derived',
    'mcp.validation.reason':
      nameResult === 'conflict'
        ? 'collector-recomputed hash comparison: Mcp-Name header identity hash does not equal params.uri identity hash'
        : undefined,
    'error.type': nameResult === 'conflict' || methodResult === 'conflict' ? 'HeaderMismatch' : undefined,
  };
}

/**
 * Returns a `server_native` event ONLY when the real server's own validation path explicitly
 * emitted a decision we can read back verbatim -- i.e. its -32020 HeaderMismatch error object,
 * composed by `validateStandardRequestHeaders` itself and returned as the response. That is a
 * verdict the server's validation path actually produced.
 *
 * A 200 success response is NOT such a verdict: the server's SDK does not separately surface a
 * positive "validation passed" signal anywhere this lab can observe -- a success only means no
 * rejection was returned. Treating "no error" as an observed `server_native: match` would mean
 * THIS SCRIPT is the one deriving a verdict from captured traffic, which is collector_derived by
 * definition, even though the traffic happened to originate from a real server. So on success (or
 * any other non-rejection shape), this returns null: the collector_derived event (computed
 * separately, directly from the raw header/body values this lab itself sent) is the only verdict
 * emitted for that request, and it is labeled accordingly.
 */
function serverNativeVerdictIfEmitted(record, headerIdentityHash, bodyIdentityHash) {
  const parsed = record.targetResponse && safeParseJson(record.targetResponse.bodyRaw);
  if (!(parsed && parsed.error && parsed.error.code === -32020)) return null;
  return {
    'event.name': 'mcp.request.validation',
    requestInstanceId: record.requestInstanceId,
    labCase: record.labCase,
    'mcp.body.method': record.gatewayObserved.body.method,
    'jsonrpc.request.id': String(record.gatewayObserved.body.id),
    'mcp.header.method': record.gatewayForwarded.headers['mcp-method'] ?? null,
    'mcp.header.name_hash': headerIdentityHash,
    'mcp.body.identity_hash': bodyIdentityHash,
    'mcp.validation.source': 'server_native',
    'mcp.validation.method.result': 'match',
    'mcp.validation.name.result': 'conflict',
    'mcp.validation.result': 'invalid',
    'mcp.validation.reason': parsed.error.message,
    'error.type': 'HeaderMismatch',
  };
}

function main() {
  const records = loadRawRecords().filter((r) => r.gatewayObserved.body.method === 'resources/read');
  const executionLogByInstanceId = loadWeakenedExecutionLog();
  const events = [];
  const executionFacts = [];

  for (const record of records) {
    const rawHeaderIdentity = record.gatewayForwarded.headers['mcp-name'] ?? null;
    const rawBodyIdentity = record.gatewayObserved.body.paramsUri ?? null;
    const headerIdentityHash = hmacHash(decodeSentinel(rawHeaderIdentity));
    const bodyIdentityHash = hmacHash(rawBodyIdentity);

    events.push(collectorDerivedEvent(record, headerIdentityHash, bodyIdentityHash));

    const routedToRealServer = record.gatewayForwarded.targetPort === REAL_SERVER_PORT;
    if (routedToRealServer) {
      const serverNativeEvent = serverNativeVerdictIfEmitted(record, headerIdentityHash, bodyIdentityHash);
      if (serverNativeEvent) events.push(serverNativeEvent);
      // else: success case -- no explicit server-emitted verdict exists; collector_derived above
      // is the only event for this request. See serverNativeVerdictIfEmitted's own comment.
    } else {
      // Weakened stand-in: no server_native verdict exists to report (see file header). Record,
      // as a SEPARATE fact (not a telemetry-contract validation event), only what the raw HTTP
      // exchange actually shows about whether the conflicting operation executed -- corroborated,
      // where available, by the target's OWN independent execution log/state file (written as a
      // side effect of handling the request, out-of-band from the HTTP response) -- per
      // instruction, none of this alone establishes unauthorized access, and no separate
      // authorization evidence was collected in this lab, so that question stays outcome_unknown.
      const parsed = record.targetResponse && safeParseJson(record.targetResponse.bodyRaw);
      const executedPerHttpResponse = Boolean(
        record.targetResponse && record.targetResponse.statusCode === 200 && parsed && parsed.result && parsed.result.contents
      );
      const independentLogEntry = executionLogByInstanceId.get(record.requestInstanceId) || null;
      executionFacts.push({
        requestInstanceId: record.requestInstanceId,
        labCase: record.labCase,
        note: 'weakened stand-in has no SEP-2243 check; no server_native validation verdict exists for this request',
        executed_per_http_response: executedPerHttpResponse,
        returned_uri: executedPerHttpResponse ? parsed.result.contents[0]?.uri ?? null : null,
        independent_server_execution_log_entry: independentLogEntry,
        independent_evidence_confirms_execution: independentLogEntry ? independentLogEntry.action === 'read_executed' : null,
        conflicting_operation_executed:
          independentLogEntry !== null ? independentLogEntry.action === 'read_executed' : executedPerHttpResponse,
        header_named_identity_hash: headerIdentityHash,
        body_requested_identity_hash: bodyIdentityHash,
        unauthorized_access_proven: 'outcome_unknown',
        unauthorized_access_note:
          'execution of the conflicting read alone does not establish unauthorized access; that requires separate authorization evidence, which this lab did not collect',
      });
    }
  }

  const outDir = path.dirname(OUT_FILE);
  fs.mkdirSync(outDir, { recursive: true });
  fs.writeFileSync(OUT_FILE, JSON.stringify({ events, weakenedModeExecutionFacts: executionFacts }, null, 2), 'utf8');
  console.log(`[audit] wrote ${events.length} mcp.request.validation event(s) and ${executionFacts.length} weakened-mode execution fact(s) to evidence/telemetry-events.json`);
}

main();
