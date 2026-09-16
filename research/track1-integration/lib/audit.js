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
 *  - `server_native`: the REAL server's (@modelcontextprotocol/server@2.0.0) own SEP-2243 check,
 *    read directly off its HTTP response (a -32020 error, or a successful result implying its
 *    unconditional pre-dispatch check passed). Only emitted for requests routed to the real
 *    server -- the weakened stand-in performs NO such check by design (that is its entire
 *    purpose), so fabricating a server_native verdict for it would misrepresent evidence that
 *    does not exist. This is the higher-trust source per schema guidance.
 *  - `collector_derived`: independently recomputed here by hashing the header-side identity
 *    (decoding the Base64 sentinel form first, per schema) and the body-side identity with the
 *    same HMAC scheme (tools/harness/lib/hash.js) and comparing for equality -- emitted for every
 *    applicable request, including ones routed to the weakened stand-in, since this comparison
 *    needs no cooperation from the target at all.
 */
const fs = require('node:fs');
const path = require('node:path');
const { hmacHash } = require('../../../tools/harness/lib/hash');

const RAW_DIR = path.join(__dirname, '..', 'evidence', 'raw');
const OUT_FILE = path.join(__dirname, '..', 'evidence', 'telemetry-events.json');

const REAL_SERVER_PORT = Number(process.env.TRACK1_LAB_SERVER_PORT || 4001);

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

function serverNativeEventForRealServer(record, headerIdentityHash, bodyIdentityHash) {
  const bodyMethod = record.gatewayObserved.body.method;
  const parsed = record.targetResponse && safeParseJson(record.targetResponse.bodyRaw);
  const base = {
    'event.name': 'mcp.request.validation',
    requestInstanceId: record.requestInstanceId,
    labCase: record.labCase,
    'mcp.body.method': bodyMethod,
    'jsonrpc.request.id': String(record.gatewayObserved.body.id),
    'mcp.header.method': record.gatewayForwarded.headers['mcp-method'] ?? null,
    'mcp.header.name_hash': headerIdentityHash,
    'mcp.body.identity_hash': bodyIdentityHash,
    'mcp.validation.source': 'server_native',
  };
  if (parsed && parsed.error && parsed.error.code === -32020) {
    return {
      ...base,
      'mcp.validation.method.result': 'match',
      'mcp.validation.name.result': 'conflict',
      'mcp.validation.result': 'invalid',
      'mcp.validation.reason': parsed.error.message,
      'error.type': 'HeaderMismatch',
    };
  }
  if (record.targetResponse && record.targetResponse.statusCode === 200 && parsed && parsed.result) {
    return {
      ...base,
      'mcp.validation.method.result': 'match',
      'mcp.validation.name.result': 'match',
      'mcp.validation.result': 'valid',
      'mcp.validation.reason':
        "real server's own unconditional SEP-2243 pre-dispatch check passed (inferred from a successful result; the SDK does not separately surface a positive verdict)",
    };
  }
  // Anything else (network error, unexpected status/shape) is genuinely unclassifiable from the
  // server's own response -- do not guess a verdict.
  return {
    ...base,
    'mcp.validation.method.result': 'malformed',
    'mcp.validation.name.result': 'malformed',
    'mcp.validation.result': 'invalid',
    'mcp.validation.reason': 'server_native verdict could not be determined from the target response (unexpected shape/status)',
    'error.type': 'UnclassifiedResponse',
  };
}

function main() {
  const records = loadRawRecords().filter((r) => r.gatewayObserved.body.method === 'resources/read');
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
      events.push(serverNativeEventForRealServer(record, headerIdentityHash, bodyIdentityHash));
    } else {
      // Weakened stand-in: no server_native verdict exists to report (see file header). Record,
      // as a SEPARATE fact (not a telemetry-contract validation event), only what the raw HTTP
      // exchange actually shows about whether the conflicting operation executed -- per
      // instruction, this alone does not prove unauthorized access, and no separate authorization
      // evidence was collected in this lab, so any access-proof question stays outcome_unknown.
      const parsed = record.targetResponse && safeParseJson(record.targetResponse.bodyRaw);
      const executed = Boolean(
        record.targetResponse && record.targetResponse.statusCode === 200 && parsed && parsed.result && parsed.result.contents
      );
      executionFacts.push({
        requestInstanceId: record.requestInstanceId,
        labCase: record.labCase,
        note: 'weakened stand-in has no SEP-2243 check; no server_native validation verdict exists for this request',
        conflicting_operation_executed: executed,
        returned_uri: executed ? parsed.result.contents[0]?.uri ?? null : null,
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
