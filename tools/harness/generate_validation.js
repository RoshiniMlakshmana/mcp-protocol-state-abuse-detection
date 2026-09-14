'use strict';
/**
 * Block 6 validation/stress-test corpus generator.
 *
 * Separate from the Block 3 normal corpus and Block 4 attack corpus (never mixed with them on
 * disk). Purpose: adversarial-but-benign and boundary-condition fixtures designed to expose
 * false positives, false negatives, and telemetry-dependency limits in the Block 5 detection
 * rules -- not to look good on a scorecard.
 *
 * Reuses tools/harness/lib/hash.js and lib/protocol.js UNCHANGED (same hashing scheme, same
 * real Track 1 validation logic) so this corpus is directly comparable to Block 3/4.
 */
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { hmacHash, HASH_KEY_ID, HASH_ALGORITHM } = require('./lib/hash');
const { validateField, validateName, rollup, taskOperationFor } = require('./lib/protocol');

const DATA_DIR = path.join(__dirname, '..', '..', 'data', 'validation');
const PROTOCOL_VERSION = '2026-07-28';
const TRANSPORT = 'streamable-http';

class Clock {
  constructor(startIso) { this.t = Date.parse(startIso); }
  iso() { return new Date(this.t).toISOString(); }
  advance(ms) { this.t += ms; return this.iso(); }
}

function finalizeHashMeta(evt, keyId) {
  const hasHash = Object.keys(evt).some((k) => k.endsWith('_hash') && evt[k] !== null && evt[k] !== undefined);
  if (hasHash) {
    evt['security.hash.key_id'] = keyId || HASH_KEY_ID;
    evt['security.hash.algorithm'] = HASH_ALGORITHM;
  }
  return evt;
}

function envelope(ts, name, category, extra) {
  return finalizeHashMeta({
    timestamp: ts,
    'event.name': name,
    'event.category': category,
    'mcp.protocol.version': extra.protocolVersion || PROTOCOL_VERSION,
    'mcp.transport': extra.transport || TRANSPORT,
    ...extra.fields
  }, extra.keyId);
}

class Corpus {
  constructor() { this.files = new Map(); this.manifest = []; }
  push(rel, evt) { if (!this.files.has(rel)) this.files.set(rel, []); this.files.get(rel).push(evt); }
  pushAll(rel, evts) { evts.forEach((e) => this.push(rel, e)); }
  record(row) { this.manifest.push(row); }
  writeOut() {
    for (const [rel, evts] of this.files) {
      const full = path.join(DATA_DIR, rel);
      fs.mkdirSync(path.dirname(full), { recursive: true });
      fs.writeFileSync(full, evts.map((e) => JSON.stringify(e)).join('\n') + '\n', 'utf8');
    }
    fs.mkdirSync(DATA_DIR, { recursive: true });
    fs.writeFileSync(path.join(DATA_DIR, 'manifest.jsonl'), this.manifest.map((r) => JSON.stringify(r)).join('\n') + '\n', 'utf8');
  }
}
const corpus = new Corpus();

function seedTaskState(evts, clock, taskHash, ctx, status) {
  evts.push(envelope(clock.iso(), 'mcp.task.state', 'process', {
    ...ctx, fields: { 'mcp.task.id_hash': taskHash, 'mcp.task.state': status || 'working', 'mcp.task.previous_state': null }
  }));
}

function requestValidationResponse(evts, clock, ctx, opt) {
  const { reqId, method, headerMethod, headerNameHash, bodyIdentityHash, protocolVersion, source, extraValidationFields, responseOverrides, noValidationEvent } = opt;
  const pv = protocolVersion || PROTOCOL_VERSION;
  evts.push(envelope(clock.iso(), 'mcp.request.received', 'network', {
    ...ctx, protocolVersion: pv, fields: {
      'rpc.system.name': 'jsonrpc', 'rpc.method': method, 'mcp.body.method': method,
      'jsonrpc.request.id': reqId, 'mcp.header.method': headerMethod,
      'mcp.header.name_hash': headerNameHash, 'mcp.body.identity_hash': bodyIdentityHash,
      'http.request.method': 'POST'
    }
  }));
  if (noValidationEvent) return { methodResult: null, nameResult: null, overallResult: null };
  const methodResult = validateField(pv, { present: headerMethod !== null && headerMethod !== undefined, value: headerMethod }, method);
  const nameResult = validateName(pv, { present: headerNameHash !== null && headerNameHash !== undefined, value: headerNameHash }, bodyIdentityHash, method);
  const overallResult = rollup(methodResult, nameResult);
  evts.push(envelope(clock.advance(3), 'mcp.request.validation', 'network', {
    ...ctx, protocolVersion: pv, fields: {
      'event.outcome': overallResult === 'valid' ? 'success' : 'failure',
      'jsonrpc.request.id': reqId, 'mcp.body.method': method, 'mcp.header.method': headerMethod,
      'mcp.header.name_hash': headerNameHash, 'mcp.body.identity_hash': bodyIdentityHash,
      'mcp.validation.method.result': methodResult, 'mcp.validation.name.result': nameResult,
      'mcp.validation.result': overallResult, 'mcp.validation.source': source || 'server_native',
      ...(extraValidationFields || {})
    }
  }));
  if (responseOverrides !== null) {
    evts.push(envelope(clock.advance(4), 'mcp.response', 'network', {
      ...ctx, protocolVersion: pv, fields: { 'jsonrpc.request.id': reqId, ...(responseOverrides || (overallResult === 'valid'
        ? { 'event.outcome': 'success', 'http.response.status_code': 200 }
        : { 'event.outcome': 'failure', 'rpc.status_code': '-32020', 'error.type': 'HeaderMismatch', 'http.response.status_code': 400 })) }
    }));
  }
  return { methodResult, nameResult, overallResult };
}

function authorizationEvent(evts, clock, ctx, opt) {
  evts.push(envelope(clock.advance(4), 'mcp.task.authorization', 'iam', {
    ...ctx, fields: {
      'event.outcome': opt.decision === 'allow' ? 'success' : 'failure',
      'principal.id_hash': opt.principalHash, 'principal.authenticated': opt.authenticated !== false,
      'mcp.task.id_hash': opt.taskHash, 'mcp.task.authz_context_id_hash': opt.contextHash === undefined ? opt.taskHash : opt.contextHash,
      'mcp.task.operation': opt.operation, 'mcp.authz.decision': opt.decision,
      'mcp.authz.allowed': opt.decision === 'allow', 'mcp.authz.reason': opt.reason,
      ...(opt.policyVersion ? { 'mcp.authz.policy_version': opt.policyVersion } : {}),
      ...(opt.extra || {})
    }
  }));
}

function record(row) { corpus.record(row); }

// ===========================================================================
// TRACK 1 -- V1 benign/boundary fixtures
// ===========================================================================

function t1_versionIncompatibleResourcesRead() {
  const file = 'track1/v1_version_incompatible_resources_read.jsonl';
  const clock = new Clock('2026-10-01T09:00:00.000Z');
  const ctx = { protocolVersion: '2025-06-18', transport: TRANSPORT };
  const evts = [];
  const uriHash = hmacHash('resource:file:///v1/legacy.txt');
  requestValidationResponse(evts, clock, ctx, {
    reqId: '1', method: 'resources/read', headerMethod: null, headerNameHash: null, bodyIdentityHash: uriHash,
    protocolVersion: '2025-06-18'
  });
  corpus.pushAll(file, evts);
  record({
    scenario_id: 'V1-01', file, purpose: 'Protocol version 2025-06-18 negotiated -- predates SEP-2243, so Mcp-Method/Mcp-Name are legitimately absent on a resources/read call (not just tools/call, diversifying beyond the Block 3/4 examples).',
    expected_detection_track_1: false, expected_detection_track_2: false, expected_detection_track_3: false,
    expected_confidence: 'not_applicable', false_positive_test: true, evasion_test: false,
    telemetry_limitation: null,
    notes: 'Both validation results resolve to version_incompatible; rollup=valid.'
  });
}

function t1_missingUnderRequiredVersion() {
  // GENUINE "missing" case -- protocol version DOES require the header, but a mid-migration
  // client has not yet implemented sending it. Unlike A6/V1-01, this is NOT version_incompatible.
  const file = 'track1/v1_missing_header_migration.jsonl';
  const clock = new Clock('2026-10-01T09:05:00.000Z');
  const ctx = { protocolVersion: PROTOCOL_VERSION, transport: TRANSPORT };
  const evts = [];
  const taskHash = hmacHash('task-v1-02-0001');
  seedTaskState(evts, clock, taskHash, ctx);
  clock.advance(500);
  const { methodResult, nameResult, overallResult } = requestValidationResponse(evts, clock, ctx, {
    reqId: '2', method: 'tasks/get', headerMethod: null, headerNameHash: null, bodyIdentityHash: taskHash,
    responseOverrides: { 'event.outcome': 'failure', 'rpc.status_code': '-32020', 'error.type': 'HeaderMismatch', 'http.response.status_code': 400 },
    extraValidationFields: { 'mcp.validation.reason': 'Client negotiated 2026-07-28 but its Streamable HTTP transport layer has not yet been updated to send Mcp-Method/Mcp-Name (mid-migration client bug), not a compatible legacy version.' }
  });
  corpus.pushAll(file, evts);
  record({
    scenario_id: 'V1-02', file, purpose: 'A client negotiates the CURRENT protocol version (which requires the headers) but a migration-in-progress client library has not implemented sending them yet -- genuinely "missing", not "version_incompatible". Fills a real gap: no prior corpus (Block 3, 4, or 5\'s own test suite) exercised this exact case.',
    expected_detection_track_1: false, expected_detection_track_2: false, expected_detection_track_3: false,
    expected_confidence: 'not_applicable',
    false_positive_test: true, evasion_test: false,
    telemetry_limitation: 'The primary Track 1 rule correctly does not fire (result is "missing", not "conflict"). The diagnostic rule (low severity) DOES fire here -- verified in tests/validation. This is the intended, documented split.',
    notes: `methodResult=${methodResult} nameResult=${nameResult} overall=${overallResult}`
  });
}

function t1_collectorDerivedCorrect() {
  const file = 'track1/v1_collector_derived_correct.jsonl';
  const clock = new Clock('2026-10-01T09:10:00.000Z');
  const ctx = { protocolVersion: PROTOCOL_VERSION, transport: TRANSPORT };
  const evts = [];
  const taskHash = hmacHash('task-v1-03-0001');
  seedTaskState(evts, clock, taskHash, ctx);
  clock.advance(500);
  requestValidationResponse(evts, clock, ctx, {
    reqId: '3', method: 'tasks/cancel', headerMethod: 'tasks/cancel', headerNameHash: taskHash, bodyIdentityHash: taskHash,
    source: 'collector_derived',
    extraValidationFields: { 'mcp.validation.reason': 'Collector independently recomputed hash equality after correctly decoding the Base64 sentinel header value; result agrees with a hypothetical server_native check.' }
  });
  corpus.pushAll(file, evts);
  record({
    scenario_id: 'V1-03', file, purpose: 'A collector without access to the server\'s own validation outcome correctly decodes and hashes the header before comparing -- collector_derived source, correct result. Demonstrates collector_derived is not inherently unreliable, only lower-trust than server_native when it disagrees or cannot be cross-checked.',
    expected_detection_track_1: false, expected_detection_track_2: false, expected_detection_track_3: false,
    expected_confidence: 'not_applicable', false_positive_test: true, evasion_test: false, telemetry_limitation: null,
    notes: 'mcp.validation.source=collector_derived, result=match/match.'
  });
}

function t1_proxyHeaderCasingNormalized() {
  const file = 'track1/v1_proxy_header_casing.jsonl';
  const clock = new Clock('2026-10-01T09:15:00.000Z');
  const ctx = { protocolVersion: PROTOCOL_VERSION, transport: TRANSPORT };
  const evts = [];
  const taskHash = hmacHash('task-v1-04-0001');
  seedTaskState(evts, clock, taskHash, ctx);
  clock.advance(500);
  // HTTP header NAMES are case-insensitive (RFC 9110); an intermediary that re-cases
  // "Mcp-Method" to "MCP-METHOD" must not change the outcome, since only the VALUE matters
  // for this comparison (the collector/server normalizes header name lookup, not the field
  // captured here -- mcp.header.method already reflects the resolved value).
  requestValidationResponse(evts, clock, ctx, {
    reqId: '4', method: 'tasks/get', headerMethod: 'tasks/get', headerNameHash: taskHash, bodyIdentityHash: taskHash,
    extraValidationFields: { 'mcp.validation.reason': 'An intermediary proxy re-cased the Mcp-Method header name (MCP-METHOD) in transit; per RFC 9110 header names are case-insensitive and the resolved value is unaffected.' }
  });
  corpus.pushAll(file, evts);
  record({
    scenario_id: 'V1-04', file, purpose: 'A proxy normalizes/re-cases the HTTP header NAME (not value) in transit. Header value content is unaffected and comparison still succeeds.',
    expected_detection_track_1: false, expected_detection_track_2: false, expected_detection_track_3: false,
    expected_confidence: 'not_applicable', false_positive_test: true, evasion_test: false, telemetry_limitation: null,
    notes: 'Tests that case-insensitive header NAME handling does not get confused with header VALUE comparison.'
  });
}

function t1_malformedRejectedBeforeRouting() {
  const file = 'track1/v1_malformed_json_no_validation.jsonl';
  const clock = new Clock('2026-10-01T09:20:00.000Z');
  const ctx = { protocolVersion: PROTOCOL_VERSION, transport: TRANSPORT };
  const evts = [];
  evts.push(envelope(clock.iso(), 'mcp.request.received', 'network', {
    ...ctx, fields: {
      'rpc.system.name': 'jsonrpc', 'jsonrpc.request.id': '5', 'http.request.method': 'POST'
      // mcp.body.method / mcp.header.* deliberately absent: the body never parsed as valid
      // JSON-RPC, so there is nothing to compare header against.
    }
  }));
  evts.push(envelope(clock.advance(2), 'mcp.response', 'network', {
    ...ctx, fields: { 'event.outcome': 'failure', 'jsonrpc.request.id': '5', 'rpc.status_code': '-32700', 'error.type': 'ParseError', 'http.response.status_code': 400 }
  }));
  corpus.pushAll(file, evts);
  record({
    scenario_id: 'V1-05', file, purpose: 'Request body fails JSON-RPC parsing (-32700) before routing validation can even run. No mcp.request.validation event is emitted at all -- there is nothing to compare.',
    expected_detection_track_1: false, expected_detection_track_2: false, expected_detection_track_3: false,
    expected_confidence: 'not_applicable', false_positive_test: true, evasion_test: false,
    telemetry_limitation: 'Confirms the Track 1 rule (which requires event.name=mcp.request.validation) correctly stays silent when no such event exists, rather than treating absence-of-evaluation as suspicious.',
    notes: null
  });
}

function t1_unsupportedMethod() {
  const file = 'track1/v1_unsupported_method.jsonl';
  const clock = new Clock('2026-10-01T09:25:00.000Z');
  const ctx = { protocolVersion: PROTOCOL_VERSION, transport: TRANSPORT };
  const evts = [];
  const nameHash = hmacHash('tool:not_implemented_tool');
  requestValidationResponse(evts, clock, ctx, {
    reqId: '6', method: 'tools/call', headerMethod: 'tools/call', headerNameHash: nameHash, bodyIdentityHash: nameHash,
    responseOverrides: { 'event.outcome': 'failure', 'rpc.status_code': '-32601', 'error.type': 'MethodNotFound', 'http.response.status_code': 404 }
  });
  corpus.pushAll(file, evts);
  record({
    scenario_id: 'V1-06', file, purpose: 'Routing is perfectly consistent (server and client agree on method/tool identity); the server simply does not implement the requested tool (-32601). An unsupported method is not a routing desync.',
    expected_detection_track_1: false, expected_detection_track_2: false, expected_detection_track_3: false,
    expected_confidence: 'not_applicable', false_positive_test: true, evasion_test: false, telemetry_limitation: null, notes: null
  });
}

function t1_applicationErrorMatchingRouting() {
  const file = 'track1/v1_application_error_matching_routing.jsonl';
  const clock = new Clock('2026-10-01T09:30:00.000Z');
  const ctx = { protocolVersion: PROTOCOL_VERSION, transport: TRANSPORT };
  const evts = [];
  const taskHash = hmacHash('task-v1-07-0001');
  seedTaskState(evts, clock, taskHash, ctx);
  clock.advance(500);
  requestValidationResponse(evts, clock, ctx, {
    reqId: '7', method: 'tasks/cancel', headerMethod: 'tasks/cancel', headerNameHash: taskHash, bodyIdentityHash: taskHash,
    responseOverrides: { 'event.outcome': 'failure', 'rpc.status_code': '-32603', 'error.type': 'InternalError', 'http.response.status_code': 500 }
  });
  corpus.pushAll(file, evts);
  record({
    scenario_id: 'V1-07', file, purpose: 'A normal application-level failure (internal error executing the cancel) with fully matching routing. An unrelated error must not be conflated with a routing desync.',
    expected_detection_track_1: false, expected_detection_track_2: false, expected_detection_track_3: false,
    expected_confidence: 'not_applicable', false_positive_test: true, evasion_test: false, telemetry_limitation: null, notes: null
  });
}

function t1_canonicalizationInstrumentationGap() {
  const file = 'track1/v1_canonicalization_instrumentation_gap.jsonl';
  const clock = new Clock('2026-10-01T09:35:00.000Z');
  const ctx = { protocolVersion: PROTOCOL_VERSION, transport: TRANSPORT };
  const evts = [];
  const taskRaw = 'task-v1-08-0001';
  const correctHash = hmacHash(taskRaw); // what the value hashes to once canonically decoded
  // Simulate a BUGGY collector that hashes the raw Base64-sentinel-encoded header string
  // WITHOUT decoding it first, producing a different hash for the SAME underlying taskId.
  const buggyRawHeaderString = `=?base64?${Buffer.from(taskRaw, 'utf8').toString('base64')}?=`;
  const buggyHeaderHash = hmacHash(buggyRawHeaderString); // hashed pre-decode -- wrong
  seedTaskState(evts, clock, correctHash, ctx);
  clock.advance(500);
  const { overallResult } = requestValidationResponse(evts, clock, ctx, {
    reqId: '8', method: 'tasks/get', headerMethod: 'tasks/get', headerNameHash: buggyHeaderHash, bodyIdentityHash: correctHash,
    source: 'collector_derived',
    extraValidationFields: {
      'mcp.validation.reason': 'ARTIFACT: collector hashed the Mcp-Name header\'s raw Base64-sentinel string without decoding it first (per telemetry/schema.md SS6 rule 5, decoding MUST happen before hashing). The true underlying taskId is identical on both sides.'
    }
  });
  corpus.pushAll(file, evts);
  record({
    scenario_id: 'V1-08', file,
    purpose: 'DOCUMENTED FALSE-POSITIVE RISK: a collector that fails to decode a Base64-sentinel-encoded Mcp-Name header before hashing it will compute a hash that differs from the body\'s hash even though the true underlying taskId is identical, producing an artifactual "conflict". The rule itself behaves correctly given its input (a real conflict value IS present in the record) -- the defect is upstream, in the collector\'s canonicalization step.',
    expected_detection_track_1: true, expected_detection_track_2: false, expected_detection_track_3: false,
    expected_confidence: 'high_but_untrustworthy_source', false_positive_test: true, evasion_test: false,
    telemetry_limitation: 'Track 1\'s correctness is entirely dependent on the collector performing canonicalization (Base64-sentinel decoding) BEFORE hashing, per telemetry/schema.md SS6 rule 5. A collector bug here is indistinguishable, from the rule\'s perspective, from a genuine attack. mcp.validation.source=collector_derived is the only signal available to a downstream analyst that this evidence is weaker than a server_native verdict -- see docs/false-positive-analysis.md.',
    notes: `overallResult=${overallResult}; this is a known-bad artifact by construction, not a real routing violation`
  });
}

function t1_canonicalizationCorrectControl() {
  const file = 'track1/v1_canonicalization_correct_control.jsonl';
  const clock = new Clock('2026-10-01T09:40:00.000Z');
  const ctx = { protocolVersion: PROTOCOL_VERSION, transport: TRANSPORT };
  const evts = [];
  const taskRaw = 'task-v1-09-0001';
  const correctHash = hmacHash(taskRaw);
  seedTaskState(evts, clock, correctHash, ctx);
  clock.advance(500);
  requestValidationResponse(evts, clock, ctx, {
    reqId: '9', method: 'tasks/get', headerMethod: 'tasks/get', headerNameHash: correctHash, bodyIdentityHash: correctHash,
    source: 'collector_derived',
    extraValidationFields: { 'mcp.validation.reason': 'Contrast fixture for V1-08: same Base64-sentinel header pattern, but decoded correctly BEFORE hashing -- hashes agree.' }
  });
  corpus.pushAll(file, evts);
  record({
    scenario_id: 'V1-09', file, purpose: 'Direct contrast with V1-08: the same Base64-sentinel encoding pattern, but the collector decodes correctly before hashing, producing a correct match.',
    expected_detection_track_1: false, expected_detection_track_2: false, expected_detection_track_3: false,
    expected_confidence: 'not_applicable', false_positive_test: true, evasion_test: false, telemetry_limitation: null, notes: null
  });
}

// ===========================================================================
// TRACK 1 -- V2 evasion illustration (Track 1 correctly silent; Track 2 must catch it)
// ===========================================================================

function t1t2_v2_perfectRoutingStolenHandle() {
  const file = 'track1/v2_perfect_routing_stolen_handle.jsonl';
  const clock = new Clock('2026-10-01T09:45:00.000Z');
  const ctx = { protocolVersion: PROTOCOL_VERSION, transport: TRANSPORT };
  const evts = [];
  const taskHash = hmacHash('task-v2-01-0123');
  const ownerHash = hmacHash('principal:owner-v2-01');
  const attackerHash = hmacHash('principal:attacker-v2-01');
  seedTaskState(evts, clock, taskHash, ctx);
  clock.advance(1000);
  requestValidationResponse(evts, clock, ctx, {
    reqId: '10', method: 'tasks/get', headerMethod: 'tasks/get', headerNameHash: taskHash, bodyIdentityHash: taskHash
  });
  authorizationEvent(evts, clock, ctx, {
    principalHash: attackerHash, taskHash, contextHash: ownerHash, operation: 'get', decision: 'deny', reason: 'principal_mismatch'
  });
  evts.push(envelope(clock.advance(3), 'mcp.response', 'network', {
    ...ctx, fields: { 'event.outcome': 'failure', 'jsonrpc.request.id': '10', 'rpc.status_code': '-32602', 'http.response.status_code': 400 }
  }));
  corpus.pushAll(file, evts);
  record({
    scenario_id: 'V2-01', file,
    purpose: 'EVASION ILLUSTRATION: an attacker who possesses a syntactically valid, correctly-formatted taskId submits a perfectly-routed request (Mcp-Name = params.taskId, exact match). Track 1 has NOTHING to detect here by design. Verifies Track 2 independently catches the authorization violation using the same event set.',
    expected_detection_track_1: false, expected_detection_track_2: true, expected_detection_track_3: false,
    expected_confidence: 'high', false_positive_test: false, evasion_test: true,
    telemetry_limitation: 'Classification: detectable -- but only by Track 2, not Track 1. Track 1 cannot and should not fire here -- routing is genuinely valid. This is not a Track 1 weakness; it demonstrates the tracks are complementary, not redundant (docs/evasion-limitations.md).',
    notes: 'Directly mirrors Block 4 A10\'s narrative, generated fresh in the Block 6 corpus to keep it self-contained for validation-suite purposes.'
  });
}

// ===========================================================================
// TRACK 2 -- V3 benign / false-positive fixtures
// ===========================================================================

function t2_delegatedAccessServicePrincipal() {
  const file = 'track2/v3_delegated_service_principal.jsonl';
  const clock = new Clock('2026-10-01T10:00:00.000Z');
  const ctx = { protocolVersion: PROTOCOL_VERSION, transport: TRANSPORT };
  const evts = [];
  const taskHash = hmacHash('task-v3-01-0001');
  const ownerHash = hmacHash('principal:user-v3-01');
  const servicePrincipalHash = hmacHash('principal:service-agent-v3-01');
  seedTaskState(evts, clock, taskHash, ctx);
  clock.advance(1000);
  requestValidationResponse(evts, clock, ctx, {
    reqId: '20', method: 'tasks/get', headerMethod: 'tasks/get', headerNameHash: taskHash, bodyIdentityHash: taskHash
  });
  authorizationEvent(evts, clock, ctx, {
    principalHash: servicePrincipalHash, taskHash, contextHash: ownerHash, operation: 'get', decision: 'allow', reason: 'authorized_grant',
    extra: { 'principal.auth_method': 'oauth2_client_credentials' }
  });
  evts.push(envelope(clock.advance(5), 'mcp.response', 'network', { ...ctx, fields: { 'event.outcome': 'success', 'jsonrpc.request.id': '20', 'http.response.status_code': 200 } }));
  corpus.pushAll(file, evts);
  record({
    scenario_id: 'V3-01', file, purpose: 'A service principal (acting on behalf of a user, oauth2_client_credentials) accesses a task via an explicit grant, not ownership. Must be recognized as legitimate delegation, not a cross-principal violation -- mcp.authz.reason has no dedicated "delegated" value; authorized_grant covers it, and the rule correctly does not care about WHY it is a grant.',
    expected_detection_track_1: false, expected_detection_track_2: false, expected_detection_track_3: false,
    expected_confidence: 'not_applicable', false_positive_test: true, evasion_test: false, telemetry_limitation: null, notes: null
  });
}

function t2_policyChangeExpandsAccess() {
  const file = 'track2/v3_policy_change_expands_access.jsonl';
  const clock = new Clock('2026-10-01T10:05:00.000Z');
  const ctx = { protocolVersion: PROTOCOL_VERSION, transport: TRANSPORT };
  const evts = [];
  const taskHash = hmacHash('task-v3-02-0001');
  const ownerHash = hmacHash('principal:owner-v3-02');
  const bobHash = hmacHash('principal:bob-v3-02');
  seedTaskState(evts, clock, taskHash, ctx);
  clock.advance(1000);
  // Before the policy change: Bob is denied.
  requestValidationResponse(evts, clock, ctx, { reqId: '21', method: 'tasks/get', headerMethod: 'tasks/get', headerNameHash: taskHash, bodyIdentityHash: taskHash });
  authorizationEvent(evts, clock, ctx, {
    principalHash: bobHash, taskHash, contextHash: ownerHash, operation: 'get', decision: 'deny', reason: 'principal_mismatch', policyVersion: 'policy-v1'
  });
  evts.push(envelope(clock.advance(3), 'mcp.response', 'network', { ...ctx, fields: { 'event.outcome': 'failure', 'jsonrpc.request.id': '21', 'rpc.status_code': '-32602', 'http.response.status_code': 400 } }));
  // Policy is legitimately updated to grant Bob access (e.g., team membership change).
  clock.advance(3600000);
  requestValidationResponse(evts, clock, ctx, { reqId: '22', method: 'tasks/get', headerMethod: 'tasks/get', headerNameHash: taskHash, bodyIdentityHash: taskHash });
  authorizationEvent(evts, clock, ctx, {
    principalHash: bobHash, taskHash, contextHash: ownerHash, operation: 'get', decision: 'allow', reason: 'authorized_grant', policyVersion: 'policy-v2'
  });
  evts.push(envelope(clock.advance(5), 'mcp.response', 'network', { ...ctx, fields: { 'event.outcome': 'success', 'jsonrpc.request.id': '22', 'http.response.status_code': 200 } }));
  corpus.pushAll(file, evts);
  record({
    scenario_id: 'V3-02', file, purpose: 'A denied access is legitimately superseded by a policy update (policy_version bumps from policy-v1 to policy-v2) that grants the same principal access to the same task. The EARLIER deny (principal_mismatch, policy-v1) is a real historical event and correctly still fires as a Track 2 hit at the time it occurred -- it does not retroactively become a false positive just because policy later changed. The LATER allow (authorized_grant, policy-v2) does not fire.',
    expected_detection_track_1: false, expected_detection_track_2: true, expected_detection_track_3: false,
    expected_confidence: 'high', false_positive_test: true, evasion_test: false,
    telemetry_limitation: 'This scenario contains BOTH a true Track 2 hit (the first deny) and a true negative (the later allow) in one file -- see tests/validation for the per-event assertion. A rule that only checks "any event in this file fires" would need per-event evaluation, not per-file, to be exercised meaningfully here.',
    notes: 'mcp.authz.policy_version distinguishes the two authorization epochs.'
  });
}

function t2_genericDenialPolicy() {
  const file = 'track2/v3_generic_denial_policy.jsonl';
  const clock = new Clock('2026-10-01T10:10:00.000Z');
  const ctx = { protocolVersion: PROTOCOL_VERSION, transport: TRANSPORT };
  const evts = [];
  const taskHash = hmacHash('task-v3-03-0001');
  const ownerHash = hmacHash('principal:owner-v3-03');
  seedTaskState(evts, clock, taskHash, ctx);
  clock.advance(1000);
  requestValidationResponse(evts, clock, ctx, { reqId: '23', method: 'tasks/cancel', headerMethod: 'tasks/cancel', headerNameHash: taskHash, bodyIdentityHash: taskHash });
  authorizationEvent(evts, clock, ctx, { principalHash: ownerHash, taskHash, contextHash: ownerHash, operation: 'cancel', decision: 'deny', reason: 'policy_denied' });
  evts.push(envelope(clock.advance(3), 'mcp.response', 'network', { ...ctx, fields: { 'event.outcome': 'failure', 'jsonrpc.request.id': '23', 'rpc.status_code': '-32602', 'http.response.status_code': 400 } }));
  corpus.pushAll(file, evts);
  record({
    scenario_id: 'V3-03', file, purpose: 'The task\'s own owner is denied by an org policy (e.g. change freeze, maintenance mode) -- not a cross-principal issue.',
    expected_detection_track_1: false, expected_detection_track_2: false, expected_detection_track_3: false,
    expected_confidence: 'not_applicable', false_positive_test: true, evasion_test: false, telemetry_limitation: null, notes: null
  });
}

function t2_nonexistentTask() {
  const file = 'track2/v3_nonexistent_task.jsonl';
  const clock = new Clock('2026-10-01T10:15:00.000Z');
  const ctx = { protocolVersion: PROTOCOL_VERSION, transport: TRANSPORT };
  const evts = [];
  const taskHash = hmacHash('task-v3-04-nonexistent');
  const callerHash = hmacHash('principal:caller-v3-04');
  requestValidationResponse(evts, clock, ctx, { reqId: '24', method: 'tasks/get', headerMethod: 'tasks/get', headerNameHash: taskHash, bodyIdentityHash: taskHash });
  authorizationEvent(evts, clock, ctx, { principalHash: callerHash, taskHash, contextHash: null, operation: 'get', decision: 'deny', reason: 'context_unbound' });
  evts.push(envelope(clock.advance(3), 'mcp.response', 'network', { ...ctx, fields: { 'event.outcome': 'failure', 'jsonrpc.request.id': '24', 'rpc.status_code': '-32602', 'http.response.status_code': 400 } }));
  corpus.pushAll(file, evts);
  record({
    scenario_id: 'V3-04', file, purpose: 'A caller references a taskId that does not correspond to any known task. No owner exists to be wronged.',
    expected_detection_track_1: false, expected_detection_track_2: false, expected_detection_track_3: false,
    expected_confidence: 'not_applicable', false_positive_test: true, evasion_test: false, telemetry_limitation: null, notes: null
  });
}

function t2_authenticationFailure() {
  const file = 'track2/v3_authentication_failure.jsonl';
  const clock = new Clock('2026-10-01T10:20:00.000Z');
  const ctx = { protocolVersion: PROTOCOL_VERSION, transport: TRANSPORT };
  const evts = [];
  const taskHash = hmacHash('task-v3-05-0001');
  requestValidationResponse(evts, clock, ctx, {
    reqId: '25', method: 'tasks/get', headerMethod: 'tasks/get', headerNameHash: taskHash, bodyIdentityHash: taskHash,
    responseOverrides: { 'event.outcome': 'failure', 'http.response.status_code': 401 }
  });
  // No mcp.task.authorization event at all: an unauthenticated caller never reaches the
  // per-task authorization check (SEP-2663's check presumes an authenticated caller).
  corpus.pushAll(file, evts);
  record({
    scenario_id: 'V3-05', file, purpose: 'An unauthenticated request (invalid/missing bearer token, HTTP 401) never reaches per-task authorization at all -- this is authentication failure, not cross-principal task misuse, and must not be conflated with it.',
    expected_detection_track_1: false, expected_detection_track_2: false, expected_detection_track_3: false,
    expected_confidence: 'not_applicable', false_positive_test: true, evasion_test: false,
    telemetry_limitation: 'No mcp.task.authorization event exists for this request; the rule correctly has nothing to fire on.', notes: null
  });
}

function t2_missingAuthzContextButAllowed() {
  const file = 'track2/v3_missing_context_allowed.jsonl';
  const clock = new Clock('2026-10-01T10:25:00.000Z');
  const ctx = { protocolVersion: PROTOCOL_VERSION, transport: TRANSPORT };
  const evts = [];
  const taskHash = hmacHash('task-v3-06-0001');
  const principalHash = hmacHash('principal:owner-v3-06');
  requestValidationResponse(evts, clock, ctx, { reqId: '26', method: 'tasks/get', headerMethod: 'tasks/get', headerNameHash: taskHash, bodyIdentityHash: taskHash });
  authorizationEvent(evts, clock, ctx, { principalHash, taskHash, contextHash: null, operation: 'get', decision: 'allow', reason: 'authorized_owner' });
  evts.push(envelope(clock.advance(5), 'mcp.response', 'network', { ...ctx, fields: { 'event.outcome': 'success', 'jsonrpc.request.id': '26', 'http.response.status_code': 200 } }));
  corpus.pushAll(file, evts);
  record({
    scenario_id: 'V3-06', file, purpose: 'Server cannot expose a task-to-context binding (mcp.task.authz_context_id_hash=null) but still reaches and reports a definite allow decision. Per the Block 2 patch, the null must never independently gate the rule in either direction.',
    expected_detection_track_1: false, expected_detection_track_2: false, expected_detection_track_3: false,
    expected_confidence: 'not_applicable', false_positive_test: true, evasion_test: false, telemetry_limitation: null, notes: null
  });
}

function t2_staleOptionalTelemetry() {
  const file = 'track2/v3_stale_optional_telemetry.jsonl';
  const clock = new Clock('2026-10-01T10:30:00.000Z');
  const ctx = { protocolVersion: PROTOCOL_VERSION, transport: TRANSPORT };
  const evts = [];
  const taskHash = hmacHash('task-v3-07-0001');
  const principalHash = hmacHash('principal:owner-v3-07');
  requestValidationResponse(evts, clock, ctx, { reqId: '27', method: 'tasks/update', headerMethod: 'tasks/update', headerNameHash: taskHash, bodyIdentityHash: taskHash });
  // Deliberately omit principal.auth_method and mcp.authz.policy_version (both optional).
  evts.push(envelope(clock.advance(4), 'mcp.task.authorization', 'iam', {
    ...ctx, fields: {
      'event.outcome': 'success', 'principal.id_hash': principalHash, 'principal.authenticated': true,
      'mcp.task.id_hash': taskHash, 'mcp.task.authz_context_id_hash': principalHash,
      'mcp.task.operation': 'update', 'mcp.authz.decision': 'allow', 'mcp.authz.allowed': true, 'mcp.authz.reason': 'authorized_owner'
    }
  }));
  evts.push(envelope(clock.advance(5), 'mcp.response', 'network', { ...ctx, fields: { 'event.outcome': 'success', 'jsonrpc.request.id': '27', 'http.response.status_code': 200 } }));
  corpus.pushAll(file, evts);
  record({
    scenario_id: 'V3-07', file, purpose: 'Several optional fields (principal.auth_method, mcp.authz.policy_version) are absent, but the core decision/reason are present and clean. Missing optional telemetry must not affect the verdict.',
    expected_detection_track_1: false, expected_detection_track_2: false, expected_detection_track_3: false,
    expected_confidence: 'not_applicable', false_positive_test: true, evasion_test: false, telemetry_limitation: null, notes: null
  });
}

// ===========================================================================
// TRACK 2 -- V4 evasion documentation (telemetry-observability limits)
// ===========================================================================

function t2_v4_authzSystemWronglyAllows() {
  const file = 'track2/v4_authz_system_wrongly_allows.jsonl';
  const clock = new Clock('2026-10-01T10:35:00.000Z');
  const ctx = { protocolVersion: PROTOCOL_VERSION, transport: TRANSPORT };
  const evts = [];
  const taskHash = hmacHash('task-v4-01-0001');
  const attackerHash = hmacHash('principal:attacker-v4-01'); // holding a stolen, validly-authenticated identity
  requestValidationResponse(evts, clock, ctx, { reqId: '28', method: 'tasks/get', headerMethod: 'tasks/get', headerNameHash: taskHash, bodyIdentityHash: taskHash });
  // The authorization system itself is fooled (e.g. the attacker holds the victim's own valid
  // credentials) and genuinely believes this IS the authorized principal.
  authorizationEvent(evts, clock, ctx, { principalHash: attackerHash, taskHash, contextHash: attackerHash, operation: 'get', decision: 'allow', reason: 'authorized_owner' });
  evts.push(envelope(clock.advance(5), 'mcp.response', 'network', { ...ctx, fields: { 'event.outcome': 'success', 'jsonrpc.request.id': '28', 'http.response.status_code': 200 } }));
  corpus.pushAll(file, evts);
  record({
    scenario_id: 'V4-01', file,
    purpose: 'EVASION -- NOT DETECTABLE WITH CURRENT TELEMETRY. An attacker has stolen the victim\'s own valid authenticated identity/token. From the MCP server\'s and the audit pipeline\'s point of view, this is indistinguishable from a legitimate access: decision=allow, reason=authorized_owner, principal.id_hash resolves (correctly, per the token) to what the system believes is the rightful owner. Track 2 detects a MISMATCH between caller and authorization context -- it cannot detect that the caller\'s own claimed identity is itself fraudulent.',
    expected_detection_track_1: false, expected_detection_track_2: false, expected_detection_track_3: false,
    expected_confidence: 'not_applicable', false_positive_test: false, evasion_test: true,
    telemetry_limitation: 'NOT DETECTABLE: identity/token compromise is upstream of anything MCP task-authorization telemetry can observe. This would require separate identity/credential-theft detection (e.g. impossible-travel, token-binding anomalies) entirely outside this project\'s three tracks.',
    notes: 'Classification: not detectable with current telemetry.'
  });
}

function t2_v4_authorizationTelemetryDisabled() {
  const file = 'track2/v4_authorization_telemetry_disabled.jsonl';
  const clock = new Clock('2026-10-01T10:40:00.000Z');
  const ctx = { protocolVersion: PROTOCOL_VERSION, transport: TRANSPORT };
  const evts = [];
  const taskHash = hmacHash('task-v4-02-0001');
  requestValidationResponse(evts, clock, ctx, {
    reqId: '29', method: 'tasks/cancel', headerMethod: 'tasks/cancel', headerNameHash: taskHash, bodyIdentityHash: taskHash,
    responseOverrides: { 'event.outcome': 'failure', 'rpc.status_code': '-32602', 'http.response.status_code': 400 }
  });
  // No mcp.task.authorization event at all -- as if the audit pipeline's instrumentation for
  // this event type were disabled or failed silently, even though the server itself did
  // perform (and enforce) a real authorization check per SEP-2663.
  corpus.pushAll(file, evts);
  record({
    scenario_id: 'V4-02', file,
    purpose: 'EVASION / TELEMETRY GAP -- PARTIALLY DETECTABLE. The server correctly enforces authorization (the response is denied) but the mcp.task.authorization audit event is never emitted -- e.g. audit instrumentation disabled, crashed, or intentionally suppressed by a compromised component. Routing telemetry (request/validation/response) still exists and is clean, so Track 1 correctly stays silent, but Track 2 has zero evidence to act on.',
    expected_detection_track_1: false, expected_detection_track_2: false, expected_detection_track_3: false,
    expected_confidence: 'not_applicable', false_positive_test: false, evasion_test: true,
    telemetry_limitation: 'PARTIALLY DETECTABLE: not by Track 2 itself, but the ABSENCE of an expected mcp.task.authorization event for every request that reaches a task operation is itself a detectable telemetry-health signal (a coverage/completeness monitor, not a security rule) -- recommended as a companion operational check, out of scope for the three locked tracks. See docs/evasion-limitations.md.',
    notes: 'Classification: partially detectable (via telemetry-completeness monitoring, not via Track 2 itself).'
  });
}

// ===========================================================================
// TRACK 3 -- V5 benign / boundary fixtures
// ===========================================================================

function sub(evts, clock, ctx, opt) {
  evts.push(envelope(clock.iso(), 'mcp.subscription.open', 'session', {
    ...ctx, keyId: opt.keyId, fields: {
      'jsonrpc.request.id': opt.subId, 'mcp.subscription.id': opt.subId,
      ...(opt.instanceId ? { 'mcp.subscription.instance_id': opt.instanceId } : {}),
      'principal.id_hash': opt.principalHash, 'principal.authenticated': true,
      'mcp.authz.grant_snapshot_hash': hmacHash('grant:' + opt.subId),
      ...(opt.bindingId ? { 'mcp.authz.binding_id': opt.bindingId } : {}),
      ...(opt.requiredScope ? { 'mcp.subscription.required_scope': opt.requiredScope } : {}),
      ...(opt.validUntil ? { 'mcp.authz.grant_expiry': opt.validUntil, 'mcp.authz.valid_until': opt.validUntil } : {})
    }
  }));
  evts.push(envelope(clock.advance(50), 'mcp.subscription.acknowledged', 'session', {
    ...ctx, fields: { 'event.outcome': 'success', 'mcp.subscription.id': opt.subId, 'principal.id_hash': opt.principalHash, 'mcp.subscription.state': 'acknowledged' }
  }));
}
function notify(evts, clock, ctx, opt) {
  evts.push(envelope(clock.iso(), 'mcp.subscription.notification', 'session', {
    ...ctx, keyId: opt.keyId, fields: {
      'mcp.subscription.id': opt.subId === undefined ? undefined : opt.subId,
      ...(opt.instanceId ? { 'mcp.subscription.instance_id': opt.instanceId } : {}),
      'principal.id_hash': opt.principalHash, 'mcp.subscription.state': 'active',
      'mcp.subscription.notification_type': opt.type || 'notifications/resources/updated',
      ...(opt.uriHash ? { 'mcp.subscription.notification.resource_uri_hash': opt.uriHash } : {}),
      ...(opt.bindingId ? { 'mcp.authz.binding_id': opt.bindingId } : {}),
      ...(opt.validUntil ? { 'mcp.authz.valid_until': opt.validUntil } : {})
    }
  }));
}
function change(evts, clock, ctx, opt) {
  evts.push(envelope(clock.iso(), 'mcp.subscription.authorization_change', 'iam', {
    ...ctx, fields: {
      'principal.id_hash': opt.principalHash, 'mcp.authz.change.type': opt.type,
      'mcp.authz.change.source': opt.source || 'authorization_server_event',
      ...(opt.effectiveAt ? { 'mcp.authz.change.effective_at': opt.effectiveAt } : {}),
      'mcp.authz.change.detected_at': opt.detectedAt,
      'mcp.authz.change.timing_confidence': opt.confidence,
      ...(opt.affectedScope ? { 'mcp.authz.change.affected_scope': opt.affectedScope } : {}),
      ...(opt.affectedBindingIds ? { 'mcp.authz.change.affected_binding_ids': opt.affectedBindingIds } : {}),
      ...(opt.removedScope ? { 'mcp.authz.change.removed_scope': opt.removedScope } : {})
    }
  }));
}
function closeSub(evts, clock, ctx, opt) {
  evts.push(envelope(clock.iso(), 'mcp.subscription.close', 'session', {
    ...ctx, fields: {
      'event.outcome': 'success', 'mcp.subscription.id': opt.subId,
      ...(opt.instanceId ? { 'mcp.subscription.instance_id': opt.instanceId } : {}),
      'principal.id_hash': opt.principalHash, 'mcp.subscription.state': opt.state || 'closed_graceful', 'mcp.subscription.close.reason': opt.reason
    }
  }));
}

function t3_effectiveAtAfterNotification() {
  const file = 'track3/v5_effective_at_after_notification.jsonl';
  const clock = new Clock('2026-10-01T11:00:00.000Z');
  const ctx = { protocolVersion: PROTOCOL_VERSION, transport: TRANSPORT };
  const evts = [];
  const p = hmacHash('principal:alice-v5-01');
  sub(evts, clock, ctx, { subId: '5001', principalHash: p, validUntil: '2026-10-01T12:00:00.000Z' });
  clock.t = Date.parse('2026-10-01T11:05:00.000Z');
  notify(evts, clock, ctx, { subId: '5001', principalHash: p, uriHash: hmacHash('resource:v5-01') });
  clock.t = Date.parse('2026-10-01T11:10:00.000Z');
  change(evts, clock, ctx, { principalHash: p, type: 'revoked', effectiveAt: clock.iso(), detectedAt: clock.iso(), confidence: 'authoritative' });
  corpus.pushAll(file, evts);
  record({
    scenario_id: 'V5-01', file, purpose: 'The notification (11:05) precedes the authoritative revocation effective_at (11:10) -- the notification was legitimate at the time it was sent. Direct boundary-direction test.',
    expected_detection_track_1: false, expected_detection_track_2: false, expected_detection_track_3: false,
    expected_confidence: 'not_applicable', false_positive_test: true, evasion_test: false, telemetry_limitation: null, notes: null
  });
}

function t3_gracePeriodPolicy() {
  const file = 'track3/v5_grace_period_policy.jsonl';
  const clock = new Clock('2026-10-01T11:15:00.000Z');
  const ctx = { protocolVersion: PROTOCOL_VERSION, transport: TRANSPORT };
  const evts = [];
  const p = hmacHash('principal:alice-v5-02');
  sub(evts, clock, ctx, { subId: '5002', principalHash: p, validUntil: '2026-10-01T13:00:00.000Z' });
  clock.t = Date.parse('2026-10-01T11:20:00.000Z');
  const effAt = clock.iso();
  change(evts, clock, ctx, { principalHash: p, type: 'scope_downgraded', effectiveAt: effAt, detectedAt: effAt, confidence: 'authoritative' });
  clock.t = Date.parse('2026-10-01T11:23:00.000Z'); // 3 minutes after revocation -- inside a hypothetical 5-minute grace period
  notify(evts, clock, ctx, { subId: '5002', principalHash: p, type: 'notifications/tools/list_changed' });
  corpus.pushAll(file, evts);
  record({
    scenario_id: 'V5-02', file,
    purpose: 'RECLASSIFIED BY THE SCOPE-AWARE TRACK 3 CORRECTION (see docs/validation-report.md "Track 3 remediation pass, part 2"): a notification is delivered 3 minutes after a scope downgrade, within a hypothetical deployment-defined 5-minute grace period. This fixture predates mcp.subscription.required_scope/mcp.authz.change.removed_scope: neither the subscription\'s required scope nor the specific scope removed by the downgrade is known. Per the corrected model, a scope_downgraded change does NOT necessarily remove permission for a given subscription (verified against MCP\'s authorization spec, which requires servers to reason about scope per operation, not as a blanket grant) -- relevance is unresolved without both scope values, and this now correctly reports insufficient_evidence rather than mechanically firing as a "confirmed but accepted" false positive. This is a genuine improvement, not a relabel: the previous behavior conflated "we don\'t know if this matters" with "this is a real, if excusable, violation."',
    expected_detection_track_1: false, expected_detection_track_2: false, expected_detection_track_3: false,
    expected_confidence: 'insufficient_evidence', false_positive_test: true, evasion_test: false,
    telemetry_limitation: 'Previously: no mcp.*.grace_period field exists in the locked telemetry contract, so the rule mechanically fired and the false positive was "accepted." Now: no mcp.subscription.required_scope/mcp.authz.change.removed_scope exist in this legacy-shaped fixture either, so scope relevance cannot be evaluated at all -- correctly insufficient_evidence rather than confirmed. A deployment wanting a definitive answer here needs to emit both scope fields; a deployment additionally wanting to suppress a genuinely-relevant downgrade during a grace window still needs deployment-side tuning (a grace-period constant), which remains out of scope for this project\'s base query. See docs/false-positive-analysis.md.',
    notes: 'PRE-CORRECTION: reported confirmed_drift (fired=true), an accepted false positive. POST-CORRECTION: reports insufficient_evidence (still flagged false_positive_test=true, since it remains a fixture specifically probing this false-positive-prone shape -- it just no longer mechanically fires while probing it).'
  });
}

function t3_renewalMisclassifiedAsRevocation() {
  // *** This scenario is expected to expose a REAL rule bug (scope_upgraded treated as
  // invalidating). See docs/validation-report.md for before/after behavior once fixed. ***
  const file = 'track3/v5_renewal_before_expiry.jsonl';
  const clock = new Clock('2026-10-01T11:30:00.000Z');
  const ctx = { protocolVersion: PROTOCOL_VERSION, transport: TRANSPORT };
  const evts = [];
  const p = hmacHash('principal:alice-v5-03');
  sub(evts, clock, ctx, { subId: '5003', principalHash: p, validUntil: '2026-10-01T12:00:00.000Z' });
  clock.t = Date.parse('2026-10-01T11:35:00.000Z');
  const effAt = clock.iso();
  // A RENEWAL: the principal's grant is extended/upgraded BEFORE it would have expired. This
  // is NOT a revocation -- authorization remains (and becomes more) valid, not less.
  change(evts, clock, ctx, { principalHash: p, type: 'scope_upgraded', effectiveAt: effAt, detectedAt: effAt, confidence: 'authoritative' });
  clock.t = Date.parse('2026-10-01T11:40:00.000Z'); // after the renewal event -- subscription remains legitimately active
  notify(evts, clock, ctx, { subId: '5003', principalHash: p, uriHash: hmacHash('resource:v5-03') });
  corpus.pushAll(file, evts);
  record({
    scenario_id: 'V5-03', file,
    purpose: 'A legitimate authorization RENEWAL (mcp.authz.change.type=scope_upgraded) occurs before expiry, then a normal notification is delivered afterward. This must NOT be flagged -- a renewal expands access, it does not invalidate the subscription.',
    expected_detection_track_1: false, expected_detection_track_2: false, expected_detection_track_3: false,
    expected_confidence: 'not_applicable', false_positive_test: true, evasion_test: false,
    telemetry_limitation: 'See docs/validation-report.md: the ORIGINAL Track 3 rule logic treated ANY authoritative authorization_change event as an invalidating boundary, regardless of mcp.authz.change.type -- meaning a scope_upgraded (renewal) event was incorrectly treated the same as a revoked/expired event, producing a false positive here. This was found by this fixture, root-caused, and fixed (KQL/SPL/Sigma component rule + tests/attack/track3util.js now only treat revoked/expired/scope_downgraded as invalidating). See docs/validation-report.md "false positives discovered".',
    notes: 'PRE-FIX: rule incorrectly fired true. POST-FIX: rule correctly fires false. This is the headline finding of Block 6.'
  });
}

function t3_streamClosesExactlyAtBoundary() {
  const file = 'track3/v5_close_exactly_at_boundary.jsonl';
  const clock = new Clock('2026-10-01T11:45:00.000Z');
  const ctx = { protocolVersion: PROTOCOL_VERSION, transport: TRANSPORT };
  const evts = [];
  const p = hmacHash('principal:alice-v5-04');
  sub(evts, clock, ctx, { subId: '5004', principalHash: p, validUntil: '2026-10-01T13:00:00.000Z' });
  clock.t = Date.parse('2026-10-01T11:50:00.000Z');
  const effAt = clock.iso();
  change(evts, clock, ctx, { principalHash: p, type: 'revoked', effectiveAt: effAt, detectedAt: effAt, confidence: 'authoritative' });
  // Close event's OWN timestamp is exactly equal to effective_at.
  closeSub(evts, clock, ctx, { subId: '5004', principalHash: p, reason: 'server_forced_authz' });
  corpus.pushAll(file, evts);
  record({
    scenario_id: 'V5-04', file, purpose: 'The subscription closes at the exact same instant authorization becomes invalid (close.timestamp == effective_at). No notification is ever delivered. Boundary-equality edge case.',
    expected_detection_track_1: false, expected_detection_track_2: false, expected_detection_track_3: false,
    expected_confidence: 'not_applicable', false_positive_test: true, evasion_test: false, telemetry_limitation: null, notes: null
  });
}

function t3_notificationEqualsEffectiveAt() {
  const file = 'track3/v5_notification_equals_effective_at.jsonl';
  const clock = new Clock('2026-10-01T12:00:00.000Z');
  const ctx = { protocolVersion: PROTOCOL_VERSION, transport: TRANSPORT };
  const evts = [];
  const p = hmacHash('principal:alice-v5-05');
  sub(evts, clock, ctx, { subId: '5005', principalHash: p, validUntil: '2026-10-01T14:00:00.000Z' });
  clock.t = Date.parse('2026-10-01T12:05:00.000Z');
  const effAt = clock.iso();
  change(evts, clock, ctx, { principalHash: p, type: 'revoked', effectiveAt: effAt, detectedAt: effAt, confidence: 'authoritative' });
  // Notification's own timestamp is EXACTLY equal to effective_at (not strictly after).
  clock.t = Date.parse('2026-10-01T12:05:00.000Z');
  notify(evts, clock, ctx, { subId: '5005', principalHash: p, uriHash: hmacHash('resource:v5-05') });
  corpus.pushAll(file, evts);
  record({
    scenario_id: 'V5-05', file,
    purpose: 'Notification timestamp exactly equals effective_at (not strictly after). Documents the project\'s chosen convention: authorization is treated as valid up to and including the exact instant of change; a violation requires the notification to be STRICTLY after the boundary.',
    expected_detection_track_1: false, expected_detection_track_2: false, expected_detection_track_3: false,
    expected_confidence: 'not_applicable', false_positive_test: true, evasion_test: false,
    telemetry_limitation: 'This is a documented interpretive convention (strict > ), not a spec-mandated one -- a deployment with sub-second-critical requirements should be aware the boundary is exclusive of the exact instant. See docs/validation-report.md.',
    notes: null
  });
}

function t3_clockSkewFalseNegative() {
  const file = 'track3/v5_clock_skew.jsonl';
  const clock = new Clock('2026-10-01T12:10:00.000Z');
  const ctx = { protocolVersion: PROTOCOL_VERSION, transport: TRANSPORT };
  const evts = [];
  const p = hmacHash('principal:alice-v5-06');
  sub(evts, clock, ctx, { subId: '5006', principalHash: p, validUntil: '2026-10-01T14:00:00.000Z' });
  // TRUE revocation (wall-clock reality) happens at 12:15, but the authorization server's
  // clock is running 3 minutes fast, so it REPORTS effective_at=12:18. The MCP server's clock
  // is correct and logs the notification at 12:16 -- a REAL violation in true time, but
  // reported effective_at (12:18) is still after it, so this cannot be flagged.
  clock.t = Date.parse('2026-10-01T12:16:00.000Z');
  notify(evts, clock, ctx, { subId: '5006', principalHash: p, uriHash: hmacHash('resource:v5-06') });
  clock.t = Date.parse('2026-10-01T12:18:00.000Z'); // AS-clock-skewed effective_at
  change(evts, clock, ctx, { principalHash: p, type: 'revoked', effectiveAt: clock.iso(), detectedAt: clock.iso(), confidence: 'authoritative' });
  corpus.pushAll(file, evts);
  record({
    scenario_id: 'V5-06', file,
    purpose: 'BENIGN OPERATIONAL LIMITATION (false negative, not a rule bug): the authorization server\'s clock runs 3 minutes fast relative to the MCP server. In true wall-clock time the revocation (12:15) preceded the notification (12:16) -- a real violation -- but the AS reports effective_at as 12:18 (its own skewed clock), which is after the notification, so the current rule logic does not flag it.',
    expected_detection_track_1: false, expected_detection_track_2: false, expected_detection_track_3: false,
    expected_confidence: 'not_applicable', false_positive_test: false, evasion_test: false,
    telemetry_limitation: 'NOT DETECTABLE without synchronized clocks (e.g. NTP) across the authorization server and MCP server, or a clock-skew-compensation mechanism -- neither exists in the locked telemetry contract. This is an operational/deployment dependency, not a rule defect. See docs/false-positive-analysis.md "timestamp quality".',
    notes: 'The rule behaves correctly and deterministically GIVEN its inputs; the inputs themselves are the source of the blind spot.'
  });
}

function t3_largeDetectedEffectiveGap() {
  const file = 'track3/v5_large_detected_effective_gap.jsonl';
  const clock = new Clock('2026-10-01T12:20:00.000Z');
  const ctx = { protocolVersion: PROTOCOL_VERSION, transport: TRANSPORT };
  const evts = [];
  const p = hmacHash('principal:alice-v5-07');
  const binding = 'binding:v5-07';
  sub(evts, clock, ctx, { subId: '5007', principalHash: p, bindingId: binding, validUntil: '2026-10-01T16:00:00.000Z' });
  clock.t = Date.parse('2026-10-01T12:25:00.000Z');
  notify(evts, clock, ctx, { subId: '5007', principalHash: p, uriHash: hmacHash('resource:v5-07') });
  // effective_at is only 5 minutes after open, but detected_at is a full 2 HOURS later --
  // authoritative timing must still be trusted regardless of how large this gap is.
  change(evts, clock, ctx, {
    principalHash: p, type: 'revoked', effectiveAt: '2026-10-01T12:22:00.000Z',
    detectedAt: '2026-10-01T14:20:00.000Z', confidence: 'authoritative',
    affectedScope: 'binding', affectedBindingIds: [binding]
  });
  corpus.pushAll(file, evts);
  record({
    scenario_id: 'V5-07', file, purpose: 'detected_at (14:20) is nearly 2 hours after effective_at (12:22), but timing_confidence is authoritative. The notification (12:25) is after effective_at and must still fire -- confirms detection correctness is not accidentally influenced by how large the detection lag is, when the timing is otherwise authoritative.',
    expected_detection_track_1: false, expected_detection_track_2: false, expected_detection_track_3: true,
    expected_confidence: 'high', false_positive_test: false, evasion_test: false, telemetry_limitation: null,
    notes: 'Stress-test variant of Block 4 A14 with a much larger detected_at/effective_at gap.'
  });
}

function t3_policyPermitsOpenStreams() {
  const file = 'track3/v5_policy_permits_open_streams.jsonl';
  const clock = new Clock('2026-10-01T12:30:00.000Z');
  const ctx = { protocolVersion: PROTOCOL_VERSION, transport: TRANSPORT };
  const evts = [];
  const p = hmacHash('principal:alice-v5-09');
  const binding = 'binding:v5-09';
  sub(evts, clock, ctx, { subId: '5009', principalHash: p, bindingId: binding, validUntil: '2026-10-01T14:00:00.000Z' });
  clock.t = Date.parse('2026-10-01T12:35:00.000Z');
  const effAt = clock.iso();
  change(evts, clock, ctx, { principalHash: p, type: 'revoked', effectiveAt: effAt, detectedAt: effAt, confidence: 'authoritative', affectedScope: 'binding', affectedBindingIds: [binding] });
  clock.t = Date.parse('2026-10-01T13:00:00.000Z'); // 25 minutes later -- policy grandfathers this stream indefinitely
  notify(evts, clock, ctx, { subId: '5009', principalHash: p, uriHash: hmacHash('resource:v5-09') });
  corpus.pushAll(file, evts);
  record({
    scenario_id: 'V5-09', file,
    purpose: 'ACCEPTED, DOCUMENTED FALSE POSITIVE: a deployment has an explicit, permanent policy exception (e.g. a legacy compatibility mode) allowing already-open streams for certain principals/policy versions to continue indefinitely after a revocation. Telemetry-wise this is identical to a real violation.',
    expected_detection_track_1: false, expected_detection_track_2: false, expected_detection_track_3: true,
    expected_confidence: 'high', false_positive_test: true, evasion_test: false,
    telemetry_limitation: 'No exemption/allowlist field exists in the locked schema. Tuning recommendation: maintain a deployment-side allowlist (by principal or policy_version) applied AFTER this detection, as a suppression rule in the SIEM, rather than encoding product policy into the base query. Deliberately left unfixed here.',
    notes: null
  });
}

// ===========================================================================
// TRACK 3 -- V6 evasion documentation
// ===========================================================================

function t3_v6_noInvalidityEvidenceAtAll() {
  const file = 'track3/v6_no_invalidity_evidence.jsonl';
  const clock = new Clock('2026-10-01T13:00:00.000Z');
  const ctx = { protocolVersion: PROTOCOL_VERSION, transport: TRANSPORT };
  const evts = [];
  const p = hmacHash('principal:alice-v6-01');
  // No valid_until on open, no authorization_change event ever -- pure silent drift with
  // literally zero invalidity evidence in the telemetry stream.
  sub(evts, clock, ctx, { subId: '6001', principalHash: p });
  clock.t = Date.parse('2026-10-01T15:00:00.000Z'); // hours later, still "active", notification continues
  notify(evts, clock, ctx, { subId: '6001', principalHash: p, uriHash: hmacHash('resource:v6-01') });
  corpus.pushAll(file, evts);
  record({
    scenario_id: 'V6-01', file,
    purpose: 'EVASION / WORST-CASE BLIND SPOT -- NOT DETECTABLE. No mcp.authz.valid_until on open, and no mcp.subscription.authorization_change event ever appears, even though (in an unmodeled ground truth) authorization may have actually lapsed hours ago. There is no invalidity evidence anywhere in this event set for Track 3 to reason from.',
    expected_detection_track_1: false, expected_detection_track_2: false, expected_detection_track_3: false,
    expected_confidence: 'not_applicable', false_positive_test: false, evasion_test: true,
    telemetry_limitation: 'NOT DETECTABLE: Track 3 requires at least one of (a) an authorization_change event or (b) a valid_until/grant_expiry value to reason about invalidity at all. A deployment that emits neither has no drift detection coverage whatsoever, by construction -- this is a telemetry-completeness prerequisite, not a rule weakness.',
    notes: 'Classification: not detectable with current telemetry (in fact, not detectable with ANY telemetry design that omits both fields).'
  });
}

function t3_v6_subscriptionIdMissingOnNotification() {
  const file = 'track3/v6_subscription_id_missing.jsonl';
  const clock = new Clock('2026-10-01T13:10:00.000Z');
  const ctx = { protocolVersion: PROTOCOL_VERSION, transport: TRANSPORT };
  const evts = [];
  const p = hmacHash('principal:alice-v6-02');
  sub(evts, clock, ctx, { subId: '6002', principalHash: p, validUntil: '2026-10-01T13:30:00.000Z' });
  clock.t = Date.parse('2026-10-01T13:20:00.000Z');
  const effAt = clock.iso();
  change(evts, clock, ctx, { principalHash: p, type: 'revoked', effectiveAt: effAt, detectedAt: effAt, confidence: 'authoritative' });
  clock.t = Date.parse('2026-10-01T13:25:00.000Z');
  // Malformed/incomplete telemetry: the notification event is missing mcp.subscription.id
  // entirely (instrumentation defect), breaking the join key.
  evts.push(envelope(clock.iso(), 'mcp.subscription.notification', 'session', {
    ...ctx, fields: {
      'principal.id_hash': p, 'mcp.subscription.state': 'active',
      'mcp.subscription.notification_type': 'notifications/resources/updated',
      'mcp.subscription.notification.resource_uri_hash': hmacHash('resource:v6-02')
    }
  }));
  corpus.pushAll(file, evts);
  record({
    scenario_id: 'V6-02', file,
    purpose: 'RECLASSIFIED by the example-driven Track 3 regression pass (see docs/validation-report.md "Track 3 remediation pass, part 3" and example #6: "revocation scope unknown, even with only one observed candidate, must report insufficient_evidence"). A notification event is missing mcp.subscription.id (malformed/incomplete instrumentation) AND the revocation event carries no mcp.authz.binding_id/affected_scope (legacy shape). A prior revision resolved this via a principal-only join (and, briefly, a "sole surviving candidate" inference); both are now recognized as unsupported inference, not evidence. This fixture now correctly reports insufficient_evidence -- the honest answer when neither the instance nor the revocation\'s target binding is known.',
    expected_detection_track_1: false, expected_detection_track_2: false, expected_detection_track_3: false,
    expected_confidence: 'insufficient_evidence', false_positive_test: false, evasion_test: true,
    telemetry_limitation: 'Classification: NOT DETECTABLE as a resolvable finding from this telemetry shape alone (previously claimed PARTIALLY DETECTABLE via a principal-only/sole-candidate join, which this pass identifies as unsupported inference, not evidence). Recovering a resolved answer requires EITHER fixing the missing mcp.subscription.id (or instance_id) on the notification, OR emitting mcp.authz.binding_id/affected_scope on the revocation -- either alone would make this instance/binding unambiguous. See fixture V12-12 for the corrected counterpart (same "no retained open, no subscription id" shape, but WITH direct binding evidence on both the notification and the change).',
    notes: 'PRE-CORRECTION: reported confirmed_drift via a principal-only join, later softened to a "sole-candidate" inference, both since removed. POST-CORRECTION: reports insufficient_evidence. Still counted in every metrics/coverage total -- not excluded.'
  });
}

// ===========================================================================
// TRACK 3 -- V11 regression fixtures (Track 3 remediation pass: SPL join-key/max=0 fixes,
// close-suppression principal-scoping fix, and oracle multi-boundary/independent-leg fixes --
// see docs/validation-report.md for the full write-up). Each fixture targets one specific
// discrepancy identified between the written KQL/SPL queries and the previous test oracle, or
// one specific regression scenario requested for this pass.
// ===========================================================================

function t3_v11_multipleChangesOutOfOrder() {
  const file = 'track3/v11_multiple_changes_out_of_order.jsonl';
  const clock = new Clock('2026-10-01T17:00:00.000Z');
  const ctx = { protocolVersion: PROTOCOL_VERSION, transport: TRANSPORT };
  const evts = [];
  const p = hmacHash('principal:alice-v11-01');
  const binding = 'binding:v11-01';
  sub(evts, clock, ctx, { subId: '10001', principalHash: p, bindingId: binding, validUntil: '2026-10-01T20:00:00.000Z' });
  clock.t = Date.parse('2026-10-01T17:05:00.000Z');
  // Change A is EMITTED FIRST in the file but carries a LATER (further future) effective_at.
  change(evts, clock, ctx, { principalHash: p, type: 'revoked', effectiveAt: '2026-10-01T18:00:00.000Z', detectedAt: clock.iso(), confidence: 'authoritative', affectedScope: 'binding', affectedBindingIds: [binding] });
  clock.t = Date.parse('2026-10-01T17:10:00.000Z');
  // Change B is EMITTED SECOND in the file but carries an EARLIER effective_at than change A.
  change(evts, clock, ctx, { principalHash: p, type: 'revoked', effectiveAt: '2026-10-01T17:07:00.000Z', detectedAt: clock.iso(), confidence: 'authoritative', affectedScope: 'binding', affectedBindingIds: [binding] });
  clock.t = Date.parse('2026-10-01T17:30:00.000Z');
  // Between B's effective_at (17:07) and A's effective_at (18:00): must fire against B only.
  notify(evts, clock, ctx, { subId: '10001', principalHash: p, uriHash: hmacHash('resource:v11-01-a') });
  clock.t = Date.parse('2026-10-01T18:30:00.000Z');
  // After BOTH boundaries: must fire against BOTH A and B (two independent rows).
  notify(evts, clock, ctx, { subId: '10001', principalHash: p, uriHash: hmacHash('resource:v11-01-b') });
  corpus.pushAll(file, evts);
  record({
    scenario_id: 'V11-01', file,
    purpose: 'REGRESSION (this pass): two authorization_change events for the same principal, EMITTED out of effective_at order (the change with the later/future effective_at appears FIRST in the event stream). Proves the correlation logic considers every applicable change by its field value, not by stream/array position or by taking only the first match found -- an oracle using `.find()` instead of iterating all matches could silently pick the wrong (or only one) boundary.',
    expected_detection_track_1: false, expected_detection_track_2: false, expected_detection_track_3: true,
    expected_confidence: 'high', false_positive_test: false, evasion_test: false,
    telemetry_limitation: null,
    notes: 'See tests/validation/track3_row_regression.test.js for the exact expected alert-row set (1 row for the first notification, 2 rows for the second).'
  });
}

function t3_v11_sameSubIdDifferentPrincipals() {
  const file = 'track3/v11_same_subid_different_principals.jsonl';
  const clock = new Clock('2026-10-01T17:35:00.000Z');
  const ctx = { protocolVersion: PROTOCOL_VERSION, transport: TRANSPORT };
  const evts = [];
  const pA = hmacHash('principal:alice-v11-02');
  const pB = hmacHash('principal:bob-v11-02');
  const bindingA = 'binding:v11-02:alice', bindingB = 'binding:v11-02:bob';
  // mcp.subscription.id is only a per-connection JSON-RPC request id (Block 1 SS7) -- it is not
  // guaranteed globally unique, so two different principals' independent connections can
  // legitimately reuse the same subscription_id string. Each principal has their OWN binding.
  sub(evts, clock, ctx, { subId: '10002', principalHash: pA, bindingId: bindingA, validUntil: '2026-10-01T20:00:00.000Z' });
  clock.t = Date.parse('2026-10-01T17:40:00.000Z');
  sub(evts, clock, ctx, { subId: '10002', principalHash: pB, bindingId: bindingB, validUntil: '2026-10-01T20:00:00.000Z' });
  clock.t = Date.parse('2026-10-01T17:45:00.000Z');
  change(evts, clock, ctx, { principalHash: pA, type: 'revoked', effectiveAt: clock.iso(), detectedAt: clock.iso(), confidence: 'authoritative', affectedScope: 'binding', affectedBindingIds: [bindingA] }); // Alice ONLY
  clock.t = Date.parse('2026-10-01T17:50:00.000Z');
  notify(evts, clock, ctx, { subId: '10002', principalHash: pB, uriHash: hmacHash('resource:v11-02-bob') }); // Bob, unrevoked, same subId string
  clock.t = Date.parse('2026-10-01T17:52:00.000Z');
  closeSub(evts, clock, ctx, { subId: '10002', principalHash: pB, reason: 'client_disconnect' }); // Bob closes HIS OWN subscription
  clock.t = Date.parse('2026-10-01T17:55:00.000Z');
  // Alice's post-revocation notification arrives AFTER Bob's close, sharing the same
  // subscription_id string. Under a subscription_id-ONLY close-suppression join (the pre-fix
  // bug), Bob's close would incorrectly suppress this genuine violation of Alice's. Under the
  // corrected subscription_id+principal_hash join, it must not.
  notify(evts, clock, ctx, { subId: '10002', principalHash: pA, uriHash: hmacHash('resource:v11-02-alice') });
  corpus.pushAll(file, evts);
  record({
    scenario_id: 'V11-02', file,
    purpose: 'REGRESSION (this pass): two different principals independently reuse the identical subscription_id string ("10002") on separate connections. Only Alice is revoked, and Bob later closes his OWN subscription (same subId string) before Alice\'s genuine post-revocation notification arrives. Proves BOTH (a) the revocation-leg join (principal_hash only) correctly fires on Alice\'s notification and not Bob\'s, and (b) the close-suppression join (subscription_id AND principal_hash) correctly does NOT let Bob\'s close suppress Alice\'s violation just because they share a subscription_id string -- the specific defect this pass\'s close-join fix addresses.',
    expected_detection_track_1: false, expected_detection_track_2: false, expected_detection_track_3: true,
    expected_confidence: 'high', false_positive_test: false, evasion_test: false,
    telemetry_limitation: null,
    notes: 'Fires because of Alice\'s notification only -- see tests/validation/track3_row_regression.test.js for the exact row (Bob\'s notification must produce zero rows).'
  });
}

function t3_v11_revocationAndExpiryBothApply() {
  const file = 'track3/v11_revocation_and_expiry_both_apply.jsonl';
  const clock = new Clock('2026-10-01T18:00:00.000Z');
  const ctx = { protocolVersion: PROTOCOL_VERSION, transport: TRANSPORT };
  const evts = [];
  const p = hmacHash('principal:alice-v11-03');
  const binding = 'binding:v11-03';
  sub(evts, clock, ctx, { subId: '10003', principalHash: p, bindingId: binding, validUntil: '2026-10-01T18:10:00.000Z' });
  clock.t = Date.parse('2026-10-01T18:05:00.000Z');
  change(evts, clock, ctx, { principalHash: p, type: 'revoked', effectiveAt: '2026-10-01T18:03:00.000Z', detectedAt: clock.iso(), confidence: 'authoritative', affectedScope: 'binding', affectedBindingIds: [binding] });
  clock.t = Date.parse('2026-10-01T18:20:00.000Z'); // after BOTH valid_until (18:10) and effective_at (18:03)
  notify(evts, clock, ctx, { subId: '10003', principalHash: p, uriHash: hmacHash('resource:v11-03') });
  corpus.pushAll(file, evts);
  record({
    scenario_id: 'V11-03', file,
    purpose: 'REGRESSION (this pass): a single notification is independently a violation under BOTH an authoritative revocation (effective_at=18:03) AND a silent expiry (valid_until=18:10). The previous oracle was an if/else-if chain that stopped at the first non-empty leg; the real KQL/SPL queries `union`/`append` both legs unconditionally, so this must produce TWO independent alert rows for the one notification, not one.',
    expected_detection_track_1: false, expected_detection_track_2: false, expected_detection_track_3: true,
    expected_confidence: 'high', false_positive_test: false, evasion_test: false,
    telemetry_limitation: null,
    notes: 'See tests/validation/track3_row_regression.test.js for the exact 2-row expectation.'
  });
}

function t3_v11_expiryBeforeFutureRevocation() {
  const file = 'track3/v11_expiry_before_future_revocation.jsonl';
  const clock = new Clock('2026-10-01T18:30:00.000Z');
  const ctx = { protocolVersion: PROTOCOL_VERSION, transport: TRANSPORT };
  const evts = [];
  const p = hmacHash('principal:alice-v11-04');
  const binding = 'binding:v11-04';
  sub(evts, clock, ctx, { subId: '10004', principalHash: p, bindingId: binding, validUntil: '2026-10-01T18:35:00.000Z' }); // expires EARLY
  clock.t = Date.parse('2026-10-01T18:36:00.000Z'); // after expiry, before any revocation exists
  notify(evts, clock, ctx, { subId: '10004', principalHash: p, uriHash: hmacHash('resource:v11-04-a') });
  clock.t = Date.parse('2026-10-01T18:40:00.000Z');
  change(evts, clock, ctx, { principalHash: p, type: 'revoked', effectiveAt: '2026-10-01T18:45:00.000Z', detectedAt: clock.iso(), confidence: 'authoritative', affectedScope: 'binding', affectedBindingIds: [binding] }); // FUTURE relative to N1
  clock.t = Date.parse('2026-10-01T18:50:00.000Z'); // after BOTH boundaries now
  notify(evts, clock, ctx, { subId: '10004', principalHash: p, uriHash: hmacHash('resource:v11-04-b') });
  corpus.pushAll(file, evts);
  record({
    scenario_id: 'V11-04', file,
    purpose: 'REGRESSION (this pass): the silent expiry boundary (18:35) is chronologically EARLIER than a revocation that is only recorded later and takes effect afterward (effective_at=18:45). The first notification (18:36) is already a silent-expiry violation before any revocation event exists at all; the second (18:50) is a violation under both. Proves the expiry leg does not wait for, or get confused by, a later-appearing revocation.',
    expected_detection_track_1: false, expected_detection_track_2: false, expected_detection_track_3: true,
    expected_confidence: 'high', false_positive_test: false, evasion_test: false,
    telemetry_limitation: null,
    notes: 'See tests/validation/track3_row_regression.test.js for the exact per-notification row counts (1, then 2).'
  });
}

function t3_v11_revocationNoRetainedOpenEvent() {
  const file = 'track3/v11_revocation_no_open_event.jsonl';
  const clock = new Clock('2026-10-01T19:00:00.000Z');
  const ctx = { protocolVersion: PROTOCOL_VERSION, transport: TRANSPORT };
  const evts = [];
  const p = hmacHash('principal:alice-v11-05');
  // No mcp.subscription.open event at all (e.g. dropped by log retention, or the subscription
  // predates the audit pipeline's deployment) -- only the change and notification remain.
  change(evts, clock, ctx, { principalHash: p, type: 'revoked', effectiveAt: clock.iso(), detectedAt: clock.iso(), confidence: 'authoritative' });
  clock.t = Date.parse('2026-10-01T19:05:00.000Z');
  notify(evts, clock, ctx, { subId: '10005', principalHash: p, uriHash: hmacHash('resource:v11-05') });
  corpus.pushAll(file, evts);
  record({
    scenario_id: 'V11-05', file,
    purpose: 'RETAINED AS AMBIGUOUS LEGACY TELEMETRY (reclassified in the scope-aware Track 3 correction -- see docs/validation-report.md "Track 3 remediation pass, part 2"). This fixture predates mcp.authz.binding_id/affected_scope: a bare principal-scoped revocation with NO retained open event and NO evidence of which binding it targets. The PREVIOUS pass\'s oracle mechanically fired here via a principal-only join -- exactly the join pattern the scope-aware correction identifies as unsound in general (principal identity does not establish revocation scope) and specifically forbids as a fallback. With zero known bindings for this principal and no directly-scoped evidence on the notification itself, this now correctly reports insufficient_evidence rather than a confirmed drift. See V12-09 for the corrected counterpart proving the SAME "no retained open event" shape resolves correctly once real scope evidence is present.',
    expected_detection_track_1: false, expected_detection_track_2: false, expected_detection_track_3: false,
    expected_confidence: 'insufficient_evidence', false_positive_test: false, evasion_test: true,
    telemetry_limitation: 'Classification: DETECTABLE only in the narrow, mechanical, PRE-CORRECTION sense (the previous-pass rule fired here). AMBIGUOUS LEGACY TELEMETRY under the corrected model: no mcp.authz.binding_id, no affected_scope, and no retained mcp.subscription.open event exist anywhere in this fixture, so there is no way to determine which (if any) binding this principal-scoped revocation is meant to invalidate. Reclassified from a previous-pass confirmed_drift finding into insufficient_evidence -- see docs/validation-report.md for why the earlier behavior was a genuine, now-corrected scope-resolution defect, not merely relabeled.',
    notes: 'PRE-CORRECTION: reported confirmed_drift (fired=true) via a principal-only join. POST-CORRECTION: reports insufficient_evidence. This is a deliberate reclassification, not a silent exclusion -- it still counts in coverage metrics, in the insufficient_evidence bucket.'
  });
}

function t3_v11_closeOnOtherSubscription() {
  const file = 'track3/v11_close_on_other_subscription.jsonl';
  const clock = new Clock('2026-10-01T19:15:00.000Z');
  const ctx = { protocolVersion: PROTOCOL_VERSION, transport: TRANSPORT };
  const evts = [];
  const p = hmacHash('principal:alice-v11-06');
  const bindingA = 'binding:v11-06:A', bindingB = 'binding:v11-06:B';
  sub(evts, clock, ctx, { subId: '10006', principalHash: p, bindingId: bindingA, validUntil: '2026-10-01T21:00:00.000Z' }); // subscription A -- stays open
  clock.t = Date.parse('2026-10-01T19:16:00.000Z');
  sub(evts, clock, ctx, { subId: '10007', principalHash: p, bindingId: bindingB, validUntil: '2026-10-01T21:00:00.000Z' }); // subscription B -- same principal, different id AND different binding
  clock.t = Date.parse('2026-10-01T19:20:00.000Z');
  // Explicitly scoped to binding B ONLY -- this fixture tests close-suppression's instance
  // scoping, not scope resolution, so the revocation is unambiguously targeted so as not to
  // collide with the separate (deliberately ambiguous) V11-11/V12-10 scenarios.
  change(evts, clock, ctx, { principalHash: p, type: 'revoked', effectiveAt: clock.iso(), detectedAt: clock.iso(), confidence: 'authoritative', affectedScope: 'binding', affectedBindingIds: [bindingA] });
  clock.t = Date.parse('2026-10-01T19:22:00.000Z');
  closeSub(evts, clock, ctx, { subId: '10007', principalHash: p, reason: 'client_disconnect' }); // closes B, NOT A
  clock.t = Date.parse('2026-10-01T19:25:00.000Z');
  notify(evts, clock, ctx, { subId: '10006', principalHash: p, uriHash: hmacHash('resource:v11-06') }); // A's notification continues
  corpus.pushAll(file, evts);
  record({
    scenario_id: 'V11-06', file,
    purpose: 'REGRESSION: the same principal holds two subscriptions on two distinct bindings (A, B); the revocation explicitly names binding A only (affected_scope=binding). B is closed, A is not. A\'s post-revocation notification must still fire -- B\'s close must not suppress it, AND the explicit binding scoping must correctly exclude B from the revocation regardless. Confirms close-suppression is correctly scoped by instance (not just principal_hash), tested here with unambiguous binding evidence so this fixture exercises the close-scoping fix specifically, not the separate scope-ambiguity handling covered by V11-11/V12-10.',
    expected_detection_track_1: false, expected_detection_track_2: false, expected_detection_track_3: true,
    expected_confidence: 'high', false_positive_test: false, evasion_test: false,
    telemetry_limitation: null,
    notes: null
  });
}

function t3_v11_closeExactlyAtNotification() {
  const file = 'track3/v11_close_exactly_at_notification.jsonl';
  const clock = new Clock('2026-10-01T19:30:00.000Z');
  const ctx = { protocolVersion: PROTOCOL_VERSION, transport: TRANSPORT };
  const evts = [];
  const p = hmacHash('principal:alice-v11-07');
  sub(evts, clock, ctx, { subId: '10008', principalHash: p, validUntil: '2026-10-01T21:00:00.000Z' });
  clock.t = Date.parse('2026-10-01T19:35:00.000Z');
  change(evts, clock, ctx, { principalHash: p, type: 'revoked', effectiveAt: clock.iso(), detectedAt: clock.iso(), confidence: 'authoritative' });
  clock.t = Date.parse('2026-10-01T19:40:00.000Z');
  closeSub(evts, clock, ctx, { subId: '10008', principalHash: p, reason: 'server_forced_authz' });
  // Notification's OWN timestamp is exactly equal to the close's timestamp (not the close
  // preceding it by any margin, and not strictly after).
  notify(evts, clock, ctx, { subId: '10008', principalHash: p, uriHash: hmacHash('resource:v11-07') });
  corpus.pushAll(file, evts);
  record({
    scenario_id: 'V11-07', file,
    purpose: 'REGRESSION (this pass) / boundary-equality: the close event\'s timestamp exactly equals the notification\'s timestamp. Per the query convention (`close_time <= notif_time` suppresses), this notification must be suppressed -- documents the inclusive convention on the close side, contrasting with the exclusive convention on the invalidation-boundary side (V5-05/V11-08).',
    expected_detection_track_1: false, expected_detection_track_2: false, expected_detection_track_3: false,
    expected_confidence: 'not_applicable', false_positive_test: true, evasion_test: false,
    telemetry_limitation: null,
    notes: 'Mirrors V5-05\'s exclusive-boundary convention on the notification side; this fixture documents the inclusive convention on the close side.'
  });
}

function t3_v11_notificationEqualsValidUntil() {
  const file = 'track3/v11_notification_equals_valid_until.jsonl';
  const clock = new Clock('2026-10-01T19:45:00.000Z');
  const ctx = { protocolVersion: PROTOCOL_VERSION, transport: TRANSPORT };
  const evts = [];
  const p = hmacHash('principal:alice-v11-08');
  sub(evts, clock, ctx, { subId: '10009', principalHash: p, validUntil: '2026-10-01T20:00:00.000Z' });
  clock.t = Date.parse('2026-10-01T20:00:00.000Z'); // notification timestamp EXACTLY equals valid_until
  notify(evts, clock, ctx, { subId: '10009', principalHash: p, uriHash: hmacHash('resource:v11-08') });
  corpus.pushAll(file, evts);
  record({
    scenario_id: 'V11-08', file,
    purpose: 'REGRESSION (this pass) / boundary-equality, EXPIRY-LEG variant of V5-05 (which only exercised the revocation leg): notification timestamp exactly equals valid_until, not strictly after. Must not fire -- confirms the exclusive-boundary convention applies identically to the expiry leg.',
    expected_detection_track_1: false, expected_detection_track_2: false, expected_detection_track_3: false,
    expected_confidence: 'not_applicable', false_positive_test: true, evasion_test: false,
    telemetry_limitation: null,
    notes: null
  });
}

function t3_v11_scopeUpgradeNoInvalidation() {
  const file = 'track3/v11_scope_upgrade_no_invalidation.jsonl';
  const clock = new Clock('2026-10-01T20:05:00.000Z');
  const ctx = { protocolVersion: PROTOCOL_VERSION, transport: TRANSPORT };
  const evts = [];
  const p = hmacHash('principal:alice-v11-09');
  sub(evts, clock, ctx, { subId: '10010', principalHash: p, validUntil: '2026-10-01T23:00:00.000Z' }); // far future, not yet reached
  clock.t = Date.parse('2026-10-01T20:10:00.000Z');
  change(evts, clock, ctx, { principalHash: p, type: 'scope_upgraded', effectiveAt: clock.iso(), detectedAt: clock.iso(), confidence: 'authoritative' });
  clock.t = Date.parse('2026-10-01T20:15:00.000Z');
  notify(evts, clock, ctx, { subId: '10010', principalHash: p, uriHash: hmacHash('resource:v11-09') });
  corpus.pushAll(file, evts);
  record({
    scenario_id: 'V11-09', file,
    purpose: 'REGRESSION (this pass), companion to V5-03: an authoritative scope_upgraded event (renewal, non-invalidating) exists, and the subscription\'s own valid_until has not yet been reached either -- a clean double-negative confirming scope_upgraded never leaks into either leg.',
    expected_detection_track_1: false, expected_detection_track_2: false, expected_detection_track_3: false,
    expected_confidence: 'not_applicable', false_positive_test: true, evasion_test: false,
    telemetry_limitation: null,
    notes: null
  });
}

function t3_v11_multipleCloseEvents() {
  const file = 'track3/v11_multiple_close_events.jsonl';
  const clock = new Clock('2026-10-01T20:20:00.000Z');
  const ctx = { protocolVersion: PROTOCOL_VERSION, transport: TRANSPORT };
  const evts = [];
  const p = hmacHash('principal:alice-v11-10');
  const binding = 'binding:v11-10';
  sub(evts, clock, ctx, { subId: '10011', principalHash: p, bindingId: binding, validUntil: '2026-10-01T23:00:00.000Z' });
  clock.t = Date.parse('2026-10-01T20:25:00.000Z');
  change(evts, clock, ctx, { principalHash: p, type: 'revoked', effectiveAt: clock.iso(), detectedAt: clock.iso(), confidence: 'authoritative', affectedScope: 'binding', affectedBindingIds: [binding] });
  clock.t = Date.parse('2026-10-01T20:27:00.000Z'); // after revocation, BEFORE either close -- must fire
  notify(evts, clock, ctx, { subId: '10011', principalHash: p, uriHash: hmacHash('resource:v11-10-a') });
  clock.t = Date.parse('2026-10-01T20:30:00.000Z');
  closeSub(evts, clock, ctx, { subId: '10011', principalHash: p, reason: 'server_forced_authz' }); // duplicate close #1 (retry)
  closeSub(evts, clock, ctx, { subId: '10011', principalHash: p, reason: 'server_forced_authz' }); // duplicate close #2, identical timestamp
  clock.t = Date.parse('2026-10-01T20:35:00.000Z'); // after both (duplicate) closes -- must be suppressed
  notify(evts, clock, ctx, { subId: '10011', principalHash: p, uriHash: hmacHash('resource:v11-10-b') });
  corpus.pushAll(file, evts);
  record({
    scenario_id: 'V11-10', file,
    purpose: 'REGRESSION (this pass): two duplicate/retried close events for the same subscription+principal, at the same timestamp. The first notification (before either close) must fire; the second (after both) must be suppressed. Proves multiple close rows are correctly reduced via an "any close at or before" (`.some`)/earliest-close-time semantic, not accidentally short-circuited or double-counted.',
    expected_detection_track_1: false, expected_detection_track_2: false, expected_detection_track_3: true,
    expected_confidence: 'high', false_positive_test: false, evasion_test: false,
    telemetry_limitation: null,
    notes: 'See tests/validation/track3_row_regression.test.js: exactly one row expected (the first notification only).'
  });
}

function t3_v11_samePrincipalCrossSubscriptionRisk() {
  const file = 'track3/v11_same_principal_cross_subscription_risk.jsonl';
  const clock = new Clock('2026-10-01T20:40:00.000Z');
  const ctx = { protocolVersion: PROTOCOL_VERSION, transport: TRANSPORT };
  const evts = [];
  const p = hmacHash('principal:alice-v11-11');
  sub(evts, clock, ctx, { subId: '10012', principalHash: p, validUntil: '2026-10-01T23:00:00.000Z' }); // subscription A -- the one actually revoked (hypothetical ground truth)
  clock.t = Date.parse('2026-10-01T20:41:00.000Z');
  sub(evts, clock, ctx, { subId: '10013', principalHash: p, validUntil: '2026-10-01T23:00:00.000Z' }); // subscription B -- a SEPARATE, still-legitimately-valid concurrent subscription
  clock.t = Date.parse('2026-10-01T20:45:00.000Z');
  // The change event carries NO subscription id at all (Block 1 SS5/SS16) -- there is no way,
  // from telemetry alone, to know this was meant to apply only to subscription A.
  change(evts, clock, ctx, { principalHash: p, type: 'revoked', effectiveAt: clock.iso(), detectedAt: clock.iso(), confidence: 'authoritative' });
  clock.t = Date.parse('2026-10-01T20:50:00.000Z');
  notify(evts, clock, ctx, { subId: '10013', principalHash: p, uriHash: hmacHash('resource:v11-11') }); // subscription B, still legitimately valid
  corpus.pushAll(file, evts);
  record({
    scenario_id: 'V11-11', file,
    purpose: 'RETAINED, DELIBERATELY UNMODIFIED, AS AMBIGUOUS LEGACY TELEMETRY (reclassified by the scope-aware Track 3 correction -- see docs/validation-report.md "Track 3 remediation pass, part 2"). A principal holds two concurrent subscriptions on this fixture\'s pre-correction, bare telemetry shape (no mcp.authz.binding_id, no affected_scope). A revocation event (principal-scoped, no subscription id, no scope evidence of any kind) is emitted. Subscription B\'s notification is now correctly reported as insufficient_evidence, NOT confirmed_drift -- the corrected resolver finds TWO candidate bindings for this principal at the change\'s effective_at and, per telemetry/correlation.md, explicitly refuses to guess which one (or both) the change affects, rather than mechanically firing on the wrong one as the previous-pass implementation did. See V12-10 for the corrected counterpart: same two-concurrent-subscription shape, but WITH explicit affected_binding_ids naming only the correct one, which resolves cleanly (A fires, B does not).',
    expected_detection_track_1: false, expected_detection_track_2: false, expected_detection_track_3: false,
    expected_confidence: 'insufficient_evidence', false_positive_test: false, evasion_test: true,
    telemetry_limitation: 'Classification: NOT DETECTABLE as a resolvable finding under the corrected model (correctly reported insufficient_evidence, not a confirmed drift or a clean clear). AMBIGUOUS LEGACY TELEMETRY: mcp.subscription.authorization_change carries no subscription id and (in this legacy-shaped fixture) no affected_scope/affected_binding_ids either, so a principal with multiple concurrent bindings genuinely cannot be disambiguated from this event alone. The PREVIOUS pass\'s oracle treated "same principal.id_hash" as sufficient scope and mechanically fired on subscription B -- verified against current MCP/OAuth documentation to be a genuine category error (principal identity does not establish revocation scope), not a stylistic one. The corrected resolver reports insufficient_evidence for BOTH candidate instances instead. Deployments emitting only this legacy shape have no way to resolve this ambiguity without upgrading to emit mcp.authz.binding_id and mcp.authz.change.affected_scope/affected_binding_ids -- see V12-13 for the corrected, resolvable counterpart.',
    notes: 'PRE-CORRECTION: reported confirmed_drift (fired=true) on subscription B, mechanically, via a principal-only join -- the exact defect this pass fixes. POST-CORRECTION: reports insufficient_evidence for both A and B. This is a deliberate, documented reclassification (not a silent relabel, not an exclusion from metrics) -- it is still counted, now in the insufficient_evidence bucket of the coverage report.'
  });
}

// ===========================================================================
// TRACK 3 -- V12 scope-aware correction fixtures (binding/instance-scoped resolution --
// see telemetry/correlation.md "Resolving affected bindings" and docs/validation-report.md
// "Track 3 remediation pass, part 2"). Each fixture targets one specific new-model behavior
// requested for this pass; several are corrected counterparts to a retained, deliberately
// ambiguous legacy fixture (V11-05, V11-11) rather than replacements for it.
// ===========================================================================

function t3_v12_sameprincipalOnlyOneAlerts() {
  const file = 'track3/v12_same_principal_only_a_alerts.jsonl';
  const clock = new Clock('2026-10-02T09:00:00.000Z');
  const ctx = { protocolVersion: PROTOCOL_VERSION, transport: TRANSPORT };
  const evts = [];
  const p = hmacHash('principal:alice-v12-01');
  const bindingA = 'binding:v12-01:A', bindingB = 'binding:v12-01:B';
  sub(evts, clock, ctx, { subId: '20001', principalHash: p, bindingId: bindingA, validUntil: '2026-10-02T12:00:00.000Z' });
  clock.t = Date.parse('2026-10-02T09:01:00.000Z');
  sub(evts, clock, ctx, { subId: '20002', principalHash: p, bindingId: bindingB, validUntil: '2026-10-02T12:00:00.000Z' });
  clock.t = Date.parse('2026-10-02T09:05:00.000Z');
  change(evts, clock, ctx, { principalHash: p, type: 'revoked', effectiveAt: clock.iso(), detectedAt: clock.iso(), confidence: 'authoritative', affectedScope: 'binding', affectedBindingIds: [bindingA] });
  clock.t = Date.parse('2026-10-02T09:10:00.000Z');
  notify(evts, clock, ctx, { subId: '20001', principalHash: p, uriHash: hmacHash('resource:v12-01-a') });
  notify(evts, clock, ctx, { subId: '20002', principalHash: p, uriHash: hmacHash('resource:v12-01-b') });
  corpus.pushAll(file, evts);
  record({
    scenario_id: 'V12-01', file,
    purpose: 'NEW REGRESSION: same principal holds two independently-bound subscriptions (A, B). The revocation explicitly names binding A only (affected_scope=binding). Only A\'s post-revocation notification confirms drift; B\'s is definitively cleared (evaluated_no_violation), not left ambiguous and not swept up by a principal-only join. Directly demonstrates the scope-aware correction\'s core behavior.',
    expected_detection_track_1: false, expected_detection_track_2: false, expected_detection_track_3: true,
    expected_confidence: 'high', false_positive_test: false, evasion_test: false, telemetry_limitation: null,
    notes: 'See tests/validation/track3_row_regression.test.js for the exact per-subscription outcome split.'
  });
}

function t3_v12_sharedGrantBothAlert() {
  const file = 'track3/v12_shared_grant_both_alert.jsonl';
  const clock = new Clock('2026-10-02T09:20:00.000Z');
  const ctx = { protocolVersion: PROTOCOL_VERSION, transport: TRANSPORT };
  const evts = [];
  const p = hmacHash('principal:alice-v12-02');
  const shared = 'binding:v12-02:shared';
  sub(evts, clock, ctx, { subId: '20003', principalHash: p, bindingId: shared, validUntil: '2026-10-02T12:00:00.000Z' });
  clock.t = Date.parse('2026-10-02T09:21:00.000Z');
  sub(evts, clock, ctx, { subId: '20004', principalHash: p, bindingId: shared, validUntil: '2026-10-02T12:00:00.000Z' });
  clock.t = Date.parse('2026-10-02T09:25:00.000Z');
  change(evts, clock, ctx, { principalHash: p, type: 'revoked', effectiveAt: clock.iso(), detectedAt: clock.iso(), confidence: 'authoritative', affectedScope: 'binding', affectedBindingIds: [shared] });
  clock.t = Date.parse('2026-10-02T09:30:00.000Z');
  notify(evts, clock, ctx, { subId: '20003', principalHash: p, uriHash: hmacHash('resource:v12-02-a') });
  notify(evts, clock, ctx, { subId: '20004', principalHash: p, uriHash: hmacHash('resource:v12-02-b') });
  corpus.pushAll(file, evts);
  record({
    scenario_id: 'V12-02', file,
    purpose: 'NEW REGRESSION: two concurrent subscriptions are legitimately opened under the SAME shared binding (e.g. one OAuth grant backing two listen streams). The revocation explicitly names that one binding. BOTH subscriptions correctly confirm drift -- affected_binding_ids correctly reaches every instance that genuinely shares the named binding, not just one arbitrarily-picked instance.',
    expected_detection_track_1: false, expected_detection_track_2: false, expected_detection_track_3: true,
    expected_confidence: 'high', false_positive_test: false, evasion_test: false, telemetry_limitation: null,
    notes: null
  });
}

function t3_v12_unrelatedScopeRemoved() {
  const file = 'track3/v12_unrelated_scope_removed.jsonl';
  const clock = new Clock('2026-10-02T09:40:00.000Z');
  const ctx = { protocolVersion: PROTOCOL_VERSION, transport: TRANSPORT };
  const evts = [];
  const p = hmacHash('principal:alice-v12-03');
  const binding = 'binding:v12-03';
  sub(evts, clock, ctx, { subId: '20005', principalHash: p, bindingId: binding, requiredScope: ['resources:read'], validUntil: '2026-10-02T12:00:00.000Z' });
  clock.t = Date.parse('2026-10-02T09:45:00.000Z');
  change(evts, clock, ctx, { principalHash: p, type: 'scope_downgraded', effectiveAt: clock.iso(), detectedAt: clock.iso(), confidence: 'authoritative', affectedScope: 'binding', affectedBindingIds: [binding], removedScope: ['resources:write'] });
  clock.t = Date.parse('2026-10-02T09:50:00.000Z');
  notify(evts, clock, ctx, { subId: '20005', principalHash: p, uriHash: hmacHash('resource:v12-03') });
  corpus.pushAll(file, evts);
  record({
    scenario_id: 'V12-03', file,
    purpose: 'NEW REGRESSION: a scope_downgraded change correctly names this instance\'s own binding, but removes a permission ("resources:write") this instance never depended on (required_scope=["resources:read"]). Must NOT fire -- a downgrade that correctly targets the right binding still does not invalidate it unless the removed permission is one it actually required.',
    expected_detection_track_1: false, expected_detection_track_2: false, expected_detection_track_3: false,
    expected_confidence: 'not_applicable', false_positive_test: true, evasion_test: false,
    telemetry_limitation: null, notes: null
  });
}

function t3_v12_requiredScopeRemoved() {
  const file = 'track3/v12_required_scope_removed.jsonl';
  const clock = new Clock('2026-10-02T10:00:00.000Z');
  const ctx = { protocolVersion: PROTOCOL_VERSION, transport: TRANSPORT };
  const evts = [];
  const p = hmacHash('principal:alice-v12-04');
  const binding = 'binding:v12-04';
  sub(evts, clock, ctx, { subId: '20006', principalHash: p, bindingId: binding, requiredScope: ['resources:read'], validUntil: '2026-10-02T12:00:00.000Z' });
  clock.t = Date.parse('2026-10-02T10:05:00.000Z');
  change(evts, clock, ctx, { principalHash: p, type: 'scope_downgraded', effectiveAt: clock.iso(), detectedAt: clock.iso(), confidence: 'authoritative', affectedScope: 'binding', affectedBindingIds: [binding], removedScope: ['resources:read'] });
  clock.t = Date.parse('2026-10-02T10:10:00.000Z');
  notify(evts, clock, ctx, { subId: '20006', principalHash: p, uriHash: hmacHash('resource:v12-04') });
  corpus.pushAll(file, evts);
  record({
    scenario_id: 'V12-04', file,
    purpose: 'NEW REGRESSION, contrast with V12-03: the scope_downgraded change removes "resources:read", which this instance\'s required_scope names directly. Must fire -- this is a genuinely relevant downgrade, correctly confirmed via the intersection check.',
    expected_detection_track_1: false, expected_detection_track_2: false, expected_detection_track_3: true,
    expected_confidence: 'high', false_positive_test: false, evasion_test: false, telemetry_limitation: null, notes: null
  });
}

function t3_v12_sameWireIdAcrossTenants() {
  const file = 'track3/v12_same_wire_id_across_tenants.jsonl';
  const clock = new Clock('2026-10-02T10:20:00.000Z');
  const ctx = { protocolVersion: PROTOCOL_VERSION, transport: TRANSPORT };
  const evts = [];
  const p = hmacHash('principal:alice-v12-05');
  const bindingA = 'binding:v12-05:A', bindingB = 'binding:v12-05:B';
  // Both instances reuse the identical WIRE subscription_id ("1") -- plausible since it is only
  // the JSON-RPC id of that connection's own listen request (MCP subscriptions pattern: no
  // state survives a reconnect, and nothing prevents two different servers/tenants from handing
  // out request id "1"). instance_id disambiguates them.
  sub(evts, clock, ctx, { subId: '1', instanceId: 'tenant1:server1:1:nonceA', principalHash: p, bindingId: bindingA, validUntil: '2026-10-02T12:00:00.000Z' });
  clock.t = Date.parse('2026-10-02T10:21:00.000Z');
  sub(evts, clock, ctx, { subId: '1', instanceId: 'tenant2:server9:1:nonceB', principalHash: p, bindingId: bindingB, validUntil: '2026-10-02T12:00:00.000Z' });
  clock.t = Date.parse('2026-10-02T10:25:00.000Z');
  change(evts, clock, ctx, { principalHash: p, type: 'revoked', effectiveAt: clock.iso(), detectedAt: clock.iso(), confidence: 'authoritative', affectedScope: 'binding', affectedBindingIds: [bindingA] });
  clock.t = Date.parse('2026-10-02T10:30:00.000Z');
  notify(evts, clock, ctx, { subId: '1', instanceId: 'tenant1:server1:1:nonceA', principalHash: p, uriHash: hmacHash('resource:v12-05-a') });
  notify(evts, clock, ctx, { subId: '1', instanceId: 'tenant2:server9:1:nonceB', principalHash: p, uriHash: hmacHash('resource:v12-05-b') });
  corpus.pushAll(file, evts);
  record({
    scenario_id: 'V12-05', file,
    purpose: 'NEW REGRESSION: two subscription instances (different tenants/servers, a plausible reconnect/reopen shape) reuse the identical WIRE mcp.subscription.id ("1"). Only the tenant1 instance\'s binding is revoked. Proves mcp.subscription.instance_id (not the wire id) is the true join key -- the tenant2 instance is correctly unaffected despite the identical subscription_id string.',
    expected_detection_track_1: false, expected_detection_track_2: false, expected_detection_track_3: true,
    expected_confidence: 'high', false_positive_test: false, evasion_test: false, telemetry_limitation: null,
    notes: 'Generalizes V11-02 (same wire id, different principals) to the same-principal, different-tenant/reconnect case.'
  });
}

function t3_v12_oldBindingExpiresAfterProvenReplacement() {
  const file = 'track3/v12_old_binding_expires_after_replacement.jsonl';
  const clock = new Clock('2026-10-02T10:40:00.000Z');
  const ctx = { protocolVersion: PROTOCOL_VERSION, transport: TRANSPORT };
  const evts = [];
  const p = hmacHash('principal:alice-v12-06');
  const oldBinding = 'binding:v12-06:old', newBinding = 'binding:v12-06:new';
  sub(evts, clock, ctx, { subId: '20007', principalHash: p, bindingId: oldBinding, validUntil: '2026-10-02T10:50:00.000Z' });
  clock.t = Date.parse('2026-10-02T10:42:00.000Z');
  notify(evts, clock, ctx, { subId: '20007', principalHash: p, uriHash: hmacHash('resource:v12-06-a') }); // before old binding's own expiry -- fine
  // Proven reauthorization: a LATER notification explicitly carries a NEW, still-valid binding_id
  // and its own (later) valid_until -- this is the only telemetry-grounded proof of rebinding.
  clock.t = Date.parse('2026-10-02T10:55:00.000Z'); // AFTER the OLD binding's expiry (10:50)
  notify(evts, clock, ctx, { subId: '20007', principalHash: p, uriHash: hmacHash('resource:v12-06-b'), bindingId: newBinding, validUntil: '2026-10-02T12:00:00.000Z' });
  corpus.pushAll(file, evts);
  record({
    scenario_id: 'V12-06', file,
    purpose: 'NEW REGRESSION: the subscription\'s original binding expires at 10:50. A later notification (10:55, after that expiry) explicitly proves it was re-validated and rebound to a NEW, still-valid binding (its own binding_id + valid_until). Must NOT fire -- the old binding\'s expiry does not contaminate a proven-valid new binding; evaluation follows the binding actually backing each notification, not the instance\'s original one.',
    expected_detection_track_1: false, expected_detection_track_2: false, expected_detection_track_3: false,
    expected_confidence: 'not_applicable', false_positive_test: true, evasion_test: false,
    telemetry_limitation: 'Requires the server to emit mcp.authz.binding_id (and a fresh mcp.authz.valid_until) on the notification itself to prove rebinding -- a deployment that never does this cannot benefit from this leniency, and correctly falls back to evaluating every notification against the instance\'s original open-time binding.',
    notes: null
  });
}

function t3_v12_newUnrelatedAuthDoesNotSuppressOldViolation() {
  const file = 'track3/v12_new_unrelated_auth_no_suppress.jsonl';
  const clock = new Clock('2026-10-02T11:00:00.000Z');
  const ctx = { protocolVersion: PROTOCOL_VERSION, transport: TRANSPORT };
  const evts = [];
  const p = hmacHash('principal:alice-v12-07');
  const oldBinding = 'binding:v12-07:old', newBinding = 'binding:v12-07:new';
  sub(evts, clock, ctx, { subId: '20008', principalHash: p, bindingId: oldBinding, validUntil: '2026-10-02T13:00:00.000Z' });
  clock.t = Date.parse('2026-10-02T11:05:00.000Z');
  change(evts, clock, ctx, { principalHash: p, type: 'revoked', effectiveAt: clock.iso(), detectedAt: clock.iso(), confidence: 'authoritative', affectedScope: 'binding', affectedBindingIds: [oldBinding] });
  clock.t = Date.parse('2026-10-02T11:10:00.000Z');
  // An entirely unrelated NEW binding becomes valid for the SAME principal (e.g. a fresh,
  // unrelated subscription elsewhere) -- its mere existence must not clear the old violation.
  sub(evts, clock, ctx, { subId: '20009', principalHash: p, bindingId: newBinding, validUntil: '2026-10-02T13:00:00.000Z' });
  clock.t = Date.parse('2026-10-02T11:15:00.000Z');
  // This notification is on the ORIGINAL (old-binding) instance and carries no binding_id of
  // its own -- it must still be evaluated against ITS OWN (old, now-revoked) binding.
  notify(evts, clock, ctx, { subId: '20008', principalHash: p, uriHash: hmacHash('resource:v12-07') });
  corpus.pushAll(file, evts);
  record({
    scenario_id: 'V12-07', file,
    purpose: 'NEW REGRESSION, contrast with V12-06: a brand-new, UNRELATED binding becomes valid for the same principal after the old binding was revoked -- but the original subscription\'s own notification is never proven-rebound to it (carries no binding_id of its own). Must still fire -- token refresh/a new unrelated grant existing elsewhere is never assumed to reauthorize an existing stream absent explicit proof.',
    expected_detection_track_1: false, expected_detection_track_2: false, expected_detection_track_3: true,
    expected_confidence: 'high', false_positive_test: false, evasion_test: false, telemetry_limitation: null, notes: null
  });
}

function t3_v12_outOfOrderArrivalTrustworthyTiming() {
  const file = 'track3/v12_out_of_order_arrival.jsonl';
  const clock = new Clock('2026-10-02T11:30:00.000Z');
  const ctx = { protocolVersion: PROTOCOL_VERSION, transport: TRANSPORT };
  const evts = [];
  const p = hmacHash('principal:alice-v12-08');
  const binding = 'binding:v12-08';
  sub(evts, clock, ctx, { subId: '20010', principalHash: p, bindingId: binding, validUntil: '2026-10-02T13:00:00.000Z' });
  // The notification is APPENDED to the event stream FIRST (arrival/log order)...
  clock.t = Date.parse('2026-10-02T11:40:00.000Z');
  notify(evts, clock, ctx, { subId: '20010', principalHash: p, uriHash: hmacHash('resource:v12-08') });
  // ...even though the authoritative change that invalidates it -- by EFFECTIVE time -- precedes
  // the notification, and is only recorded/detected (and appended to the stream) afterward.
  clock.t = Date.parse('2026-10-02T11:45:00.000Z'); // this change's own detected_at/log position
  change(evts, clock, ctx, { principalHash: p, type: 'revoked', effectiveAt: '2026-10-02T11:35:00.000Z', detectedAt: clock.iso(), confidence: 'authoritative', affectedScope: 'binding', affectedBindingIds: [binding] });
  corpus.pushAll(file, evts);
  record({
    scenario_id: 'V12-08', file,
    purpose: 'NEW REGRESSION: the authorization_change event is appended to the event stream AFTER the notification it invalidates (later arrival/detected_at/log position), but its effective_at (11:35) precedes the notification (11:40). Must fire -- resolution depends solely on effective_at field values, never on event array position, arrival order, or detected_at.',
    expected_detection_track_1: false, expected_detection_track_2: false, expected_detection_track_3: true,
    expected_confidence: 'high', false_positive_test: false, evasion_test: false, telemetry_limitation: null, notes: null
  });
}

function t3_v12_missingScopeEvidence() {
  const file = 'track3/v12_missing_scope_evidence.jsonl';
  const clock = new Clock('2026-10-02T12:00:00.000Z');
  const ctx = { protocolVersion: PROTOCOL_VERSION, transport: TRANSPORT };
  const evts = [];
  const p = hmacHash('principal:alice-v12-09');
  const binding = 'binding:v12-09';
  sub(evts, clock, ctx, { subId: '20011', principalHash: p, bindingId: binding, requiredScope: ['resources:read'], validUntil: '2026-10-02T14:00:00.000Z' });
  clock.t = Date.parse('2026-10-02T12:05:00.000Z');
  // scope_downgraded but the authorization server did NOT report which scope was removed.
  change(evts, clock, ctx, { principalHash: p, type: 'scope_downgraded', effectiveAt: clock.iso(), detectedAt: clock.iso(), confidence: 'authoritative', affectedScope: 'binding', affectedBindingIds: [binding] });
  clock.t = Date.parse('2026-10-02T12:10:00.000Z');
  notify(evts, clock, ctx, { subId: '20011', principalHash: p, uriHash: hmacHash('resource:v12-09') });
  corpus.pushAll(file, evts);
  record({
    scenario_id: 'V12-09', file,
    purpose: 'NEW REGRESSION: the downgrade correctly and unambiguously names this instance\'s binding, and the instance\'s own required_scope is known -- but mcp.authz.change.removed_scope is missing (the authorization server did not report which scope was removed). Relevance genuinely cannot be determined from one-sided scope evidence. Must report insufficient_evidence, never default to "irrelevant" (silently clearing a possible real violation) or "invalidating" (a false positive).',
    expected_detection_track_1: false, expected_detection_track_2: false, expected_detection_track_3: false,
    expected_confidence: 'insufficient_evidence', false_positive_test: false, evasion_test: true,
    telemetry_limitation: 'PARTIALLY DETECTABLE: the binding and instance are unambiguously identified, but scope relevance cannot be resolved without mcp.authz.change.removed_scope. A deployment wanting a definitive answer must emit it.',
    notes: null
  });
}

function t3_v12_conflictingEvidence() {
  const file = 'track3/v12_conflicting_evidence.jsonl';
  const clock = new Clock('2026-10-02T12:20:00.000Z');
  const ctx = { protocolVersion: PROTOCOL_VERSION, transport: TRANSPORT };
  const evts = [];
  const p = hmacHash('principal:alice-v12-10');
  const binding = 'binding:v12-10';
  sub(evts, clock, ctx, { subId: '20012', principalHash: p, bindingId: binding, validUntil: '2026-10-02T14:00:00.000Z' });
  clock.t = Date.parse('2026-10-02T12:25:00.000Z');
  change(evts, clock, ctx, { principalHash: p, type: 'revoked', effectiveAt: clock.iso(), detectedAt: clock.iso(), confidence: 'authoritative', affectedScope: 'binding', affectedBindingIds: [binding] });
  clock.t = Date.parse('2026-10-02T12:26:00.000Z');
  // A SECOND authoritative, explicitly-scoped change for the SAME binding claims a scope
  // UPGRADE -- operationally inconsistent with a binding that was just revoked (a revoked
  // binding should not legitimately receive further grants). Neither can be trusted over the
  // other from telemetry alone.
  change(evts, clock, ctx, { principalHash: p, type: 'scope_upgraded', effectiveAt: clock.iso(), detectedAt: clock.iso(), confidence: 'authoritative', affectedScope: 'binding', affectedBindingIds: [binding] });
  clock.t = Date.parse('2026-10-02T12:30:00.000Z');
  notify(evts, clock, ctx, { subId: '20012', principalHash: p, uriHash: hmacHash('resource:v12-10') });
  corpus.pushAll(file, evts);
  record({
    scenario_id: 'V12-10', file,
    purpose: 'NEW REGRESSION: two authoritative changes both explicitly name the SAME binding -- one revokes it, another (a scope upgrade) implies it remains active -- a data-quality conflict, not a timeline to order by picking whichever is "later". Must report insufficient_evidence for this binding rather than resolving the conflict by fiat.',
    expected_detection_track_1: false, expected_detection_track_2: false, expected_detection_track_3: false,
    expected_confidence: 'insufficient_evidence', false_positive_test: false, evasion_test: true,
    telemetry_limitation: 'Classification: NOT DETECTABLE as a clean confirm/clear -- NOT RESOLVABLE FROM TELEMETRY ALONE: two authoritative sources disagree about the same binding\'s current state. Resolving this requires deployment-side data-quality investigation (e.g. auditing the authorization server\'s own event log for that binding), not a query-level tiebreak rule.',
    notes: null
  });
}

function t3_v12_incompatibleHashEpoch() {
  const file = 'track3/v12_incompatible_hash_epoch.jsonl';
  const clock = new Clock('2026-10-02T12:40:00.000Z');
  const ctx = { protocolVersion: PROTOCOL_VERSION, transport: TRANSPORT };
  const evts = [];
  const p = hmacHash('principal:alice-v12-11');
  const binding = 'binding:v12-11';
  sub(evts, clock, ctx, { subId: '20013', principalHash: p, bindingId: binding, validUntil: '2026-10-02T14:00:00.000Z', keyId: 'block3-test-key-v1' });
  clock.t = Date.parse('2026-10-02T12:45:00.000Z');
  change(evts, clock, ctx, { principalHash: p, type: 'revoked', effectiveAt: clock.iso(), detectedAt: clock.iso(), confidence: 'authoritative', affectedScope: 'binding', affectedBindingIds: [binding] });
  clock.t = Date.parse('2026-10-02T12:50:00.000Z');
  // A mid-life key rotation: this notification's hashed fields were produced under a DIFFERENT
  // key epoch than the instance's own open event -- they are not safely comparable, per
  // telemetry/schema.md SS6.
  notify(evts, clock, ctx, { subId: '20013', principalHash: p, uriHash: hmacHash('resource:v12-11'), keyId: 'hypothetical-rotated-key-v2' });
  corpus.pushAll(file, evts);
  record({
    scenario_id: 'V12-11', file,
    purpose: 'NEW REGRESSION: the subscription\'s open event and its later notification carry DIFFERENT security.hash.key_id values (a key rotation occurred mid-lifetime). Their hashed fields are not safely comparable per telemetry/schema.md SS6. Must report insufficient_evidence (incompatible hash epoch), never silently proceed as if the values still corresponded, and never silently treat the mismatch as "no evidence, therefore clean".',
    expected_detection_track_1: false, expected_detection_track_2: false, expected_detection_track_3: false,
    expected_confidence: 'insufficient_evidence', false_positive_test: false, evasion_test: true,
    telemetry_limitation: 'Classification: NOT DETECTABLE as a clean confirm/clear -- NOT RESOLVABLE FROM TELEMETRY ALONE: a key rotation boundary was crossed within a single subscription instance\'s own lifetime. See telemetry/schema.md SS6 "controlled overlap" / "explicit epoch scoping" for the two supported deployment-side mitigations -- neither is implemented by this base query.',
    notes: null
  });
}

function t3_v12_directlyScopedNoRetainedOpen() {
  const file = 'track3/v12_directly_scoped_no_retained_open.jsonl';
  const clock = new Clock('2026-10-02T13:00:00.000Z');
  const ctx = { protocolVersion: PROTOCOL_VERSION, transport: TRANSPORT };
  const evts = [];
  const p = hmacHash('principal:alice-v12-12');
  const binding = 'binding:v12-12';
  // No mcp.subscription.open event at all (e.g. dropped by retention) -- but the change AND the
  // notification both carry direct, explicit binding evidence, so no retained open is needed.
  change(evts, clock, ctx, { principalHash: p, type: 'revoked', effectiveAt: clock.iso(), detectedAt: clock.iso(), confidence: 'authoritative', affectedScope: 'binding', affectedBindingIds: [binding] });
  clock.t = Date.parse('2026-10-02T13:10:00.000Z');
  notify(evts, clock, ctx, { subId: '20014', principalHash: p, uriHash: hmacHash('resource:v12-12'), bindingId: binding });
  corpus.pushAll(file, evts);
  record({
    scenario_id: 'V12-12', file,
    purpose: 'NEW REGRESSION -- corrected counterpart to V11-05\'s retained-as-ambiguous shape: no mcp.subscription.open event exists anywhere, but the notification directly carries mcp.authz.binding_id matching the change\'s affected_binding_ids explicitly. Must fire -- directly scoped invalidation needs no retained open event; the ambiguity in V11-05 came from having NEITHER a retained open NOR direct binding evidence, not from the missing open event alone.',
    expected_detection_track_1: false, expected_detection_track_2: false, expected_detection_track_3: true,
    expected_confidence: 'high', false_positive_test: false, evasion_test: false, telemetry_limitation: null,
    notes: 'Contrast directly with V11-05 (same "no retained open" shape, but zero scope evidence -- reports insufficient_evidence instead).'
  });
}

function t3_v12_correctedCrossSubscriptionCounterpart() {
  const file = 'track3/v12_corrected_cross_subscription_counterpart.jsonl';
  const clock = new Clock('2026-10-02T13:20:00.000Z');
  const ctx = { protocolVersion: PROTOCOL_VERSION, transport: TRANSPORT };
  const evts = [];
  const p = hmacHash('principal:alice-v12-13');
  const bindingA = 'binding:v12-13:A', bindingB = 'binding:v12-13:B';
  sub(evts, clock, ctx, { subId: '20015', principalHash: p, bindingId: bindingA, validUntil: '2026-10-02T15:00:00.000Z' });
  clock.t = Date.parse('2026-10-02T13:21:00.000Z');
  sub(evts, clock, ctx, { subId: '20016', principalHash: p, bindingId: bindingB, validUntil: '2026-10-02T15:00:00.000Z' });
  clock.t = Date.parse('2026-10-02T13:25:00.000Z');
  // Same two-concurrent-subscription SHAPE as V11-11, but this time the change explicitly names
  // exactly one binding -- proving the correction resolves cleanly once real scope evidence
  // exists, in direct contrast with V11-11's retained ambiguity.
  change(evts, clock, ctx, { principalHash: p, type: 'revoked', effectiveAt: clock.iso(), detectedAt: clock.iso(), confidence: 'authoritative', affectedScope: 'binding', affectedBindingIds: [bindingA] });
  clock.t = Date.parse('2026-10-02T13:30:00.000Z');
  notify(evts, clock, ctx, { subId: '20015', principalHash: p, uriHash: hmacHash('resource:v12-13-a') });
  notify(evts, clock, ctx, { subId: '20016', principalHash: p, uriHash: hmacHash('resource:v12-13-b') });
  corpus.pushAll(file, evts);
  record({
    scenario_id: 'V12-13', file,
    purpose: 'CORRECTED COUNTERPART TO V11-11: the identical two-concurrent-subscription-per-principal shape, but WITH explicit affected_binding_ids naming only one binding. Resolves cleanly: the named binding\'s subscription confirms drift, the other is definitively cleared -- proving the correction is real, not merely that ambiguous cases are now hidden. See docs/validation-report.md "Track 3 remediation pass, part 2".',
    expected_detection_track_1: false, expected_detection_track_2: false, expected_detection_track_3: true,
    expected_confidence: 'high', false_positive_test: false, evasion_test: false, telemetry_limitation: null,
    notes: 'Direct before/after pair with V11-11: identical shape, different (this time present) scope evidence, different (this time resolvable) outcome.'
  });
}

// ===========================================================================
// TRACK 3 -- V13 example-driven regression fixtures (see docs/validation-report.md "Track 3
// remediation pass, part 3"). Close the remaining gaps in the ten independently-specified
// examples that motivated this pass: delivery during a genuinely invalid interval that a later
// renewal must not erase (#4), an unrelated binding existing EARLIER (#5's other direction --
// V12-07 already covers "later"), a clean single-candidate "unknown scope" case decoupled from
// any other confounding factor (#6), a same-principal wire-id reopen (#9's other direction --
// V12-05 already covers cross-tenant reuse), and self-contradictory ("authoritative" but no
// effective_at) timing evidence (#10's timing-specific case).
// ===========================================================================

function t3_v13_confirmedDuringInvalidIntervalRenewalDoesNotErase() {
  const file = 'track3/v13_confirmed_during_invalid_interval.jsonl';
  const clock = new Clock('2026-10-03T09:00:00.000Z');
  const ctx = { protocolVersion: PROTOCOL_VERSION, transport: TRANSPORT };
  const evts = [];
  const p = hmacHash('principal:alice-v13-01');
  const binding = 'binding:v13-01', newBinding = 'binding:v13-01:renewed';
  sub(evts, clock, ctx, { subId: '30001', principalHash: p, bindingId: binding, validUntil: '2026-10-03T12:00:00.000Z' });
  clock.t = Date.parse('2026-10-03T09:05:00.000Z');
  change(evts, clock, ctx, { principalHash: p, type: 'revoked', effectiveAt: clock.iso(), detectedAt: clock.iso(), confidence: 'authoritative', affectedScope: 'binding', affectedBindingIds: [binding] });
  clock.t = Date.parse('2026-10-03T09:10:00.000Z'); // delivered WHILE genuinely invalid, before any replacement exists
  notify(evts, clock, ctx, { subId: '30001', principalHash: p, uriHash: hmacHash('resource:v13-01-a') });
  // A renewal/replacement occurs AFTER the fact: a later notification proves rebinding to a NEW,
  // valid binding. This must NOT retroactively erase the earlier notification's confirmed drift.
  clock.t = Date.parse('2026-10-03T09:20:00.000Z');
  notify(evts, clock, ctx, { subId: '30001', principalHash: p, uriHash: hmacHash('resource:v13-01-b'), bindingId: newBinding, validUntil: '2026-10-03T12:00:00.000Z' });
  corpus.pushAll(file, evts);
  record({
    scenario_id: 'V13-01', file,
    purpose: 'EXAMPLE #4: a notification is delivered during a genuinely invalid interval (after an explicit, binding-scoped revocation, before any replacement authorization exists) -- must confirm drift. A LATER renewal (proven rebinding to a new, valid binding for a subsequent notification) must not retroactively erase that earlier confirmed finding -- each notification is evaluated independently against the evidence that existed for it.',
    expected_detection_track_1: false, expected_detection_track_2: false, expected_detection_track_3: true,
    expected_confidence: 'high', false_positive_test: false, evasion_test: false, telemetry_limitation: null,
    notes: 'See tests/validation/track3_row_regression.test.js: the first notification must remain confirmed_drift regardless of the second, later, clean notification.'
  });
}

function t3_v13_unrelatedBindingEarlier() {
  const file = 'track3/v13_unrelated_binding_earlier.jsonl';
  const clock = new Clock('2026-10-03T09:30:00.000Z');
  const ctx = { protocolVersion: PROTOCOL_VERSION, transport: TRANSPORT };
  const evts = [];
  const p = hmacHash('principal:alice-v13-02');
  const oldUnrelated = 'binding:v13-02:old-unrelated', current = 'binding:v13-02:current';
  // An EARLIER, unrelated binding existed and was revoked well before the binding under test
  // even opens.
  sub(evts, clock, ctx, { subId: '30002', principalHash: p, bindingId: oldUnrelated, validUntil: '2026-10-03T09:35:00.000Z' });
  clock.t = Date.parse('2026-10-03T09:32:00.000Z');
  change(evts, clock, ctx, { principalHash: p, type: 'revoked', effectiveAt: clock.iso(), detectedAt: clock.iso(), confidence: 'authoritative', affectedScope: 'binding', affectedBindingIds: [oldUnrelated] });
  clock.t = Date.parse('2026-10-03T09:33:00.000Z');
  closeSub(evts, clock, ctx, { subId: '30002', principalHash: p, reason: 'client_closed' });
  // The subscription under test opens LATER, under a completely different, never-revoked binding.
  clock.t = Date.parse('2026-10-03T09:40:00.000Z');
  sub(evts, clock, ctx, { subId: '30003', principalHash: p, bindingId: current, validUntil: '2026-10-03T12:00:00.000Z' });
  clock.t = Date.parse('2026-10-03T09:45:00.000Z');
  notify(evts, clock, ctx, { subId: '30003', principalHash: p, uriHash: hmacHash('resource:v13-02') });
  corpus.pushAll(file, evts);
  record({
    scenario_id: 'V13-02', file,
    purpose: 'EXAMPLE #5 (earlier direction -- V12-07 covers the later direction): an unrelated binding for the SAME principal existed and was explicitly revoked BEFORE the binding under test even opened. Must not affect this notification -- the revocation explicitly names only the old, unrelated binding.',
    expected_detection_track_1: false, expected_detection_track_2: false, expected_detection_track_3: false,
    expected_confidence: 'not_applicable', false_positive_test: true, evasion_test: false, telemetry_limitation: null, notes: null
  });
}

function t3_v13_unknownScopeSingleCandidate() {
  const file = 'track3/v13_unknown_scope_single_candidate.jsonl';
  const clock = new Clock('2026-10-03T10:00:00.000Z');
  const ctx = { protocolVersion: PROTOCOL_VERSION, transport: TRANSPORT };
  const evts = [];
  const p = hmacHash('principal:alice-v13-03');
  // Deliberately NO bindingId on the open event, and NO affectedScope on the change -- this
  // principal has exactly ONE observable subscription in this fixture, which a sole-candidate
  // inference (now removed) would have used to justify a confirmed finding.
  sub(evts, clock, ctx, { subId: '30004', principalHash: p, validUntil: '2026-10-03T13:00:00.000Z' });
  clock.t = Date.parse('2026-10-03T10:05:00.000Z');
  change(evts, clock, ctx, { principalHash: p, type: 'revoked', effectiveAt: clock.iso(), detectedAt: clock.iso(), confidence: 'authoritative' });
  clock.t = Date.parse('2026-10-03T10:10:00.000Z');
  notify(evts, clock, ctx, { subId: '30004', principalHash: p, uriHash: hmacHash('resource:v13-03') });
  corpus.pushAll(file, evts);
  record({
    scenario_id: 'V13-03', file,
    purpose: 'EXAMPLE #6 (clean, single-purpose case): the revocation\'s scope is unknown (no affected_scope/affected_binding_ids), and exactly ONE subscription/binding is observable for this principal anywhere in the fixture. Must report insufficient_evidence, NOT confirmed_drift -- candidate count must never substitute for evidence, even when the count happens to be exactly one.',
    expected_detection_track_1: false, expected_detection_track_2: false, expected_detection_track_3: false,
    expected_confidence: 'insufficient_evidence', false_positive_test: false, evasion_test: true,
    telemetry_limitation: 'Classification: NOT DETECTABLE as a resolvable finding without mcp.authz.change.affected_scope/affected_binding_ids -- a "the only one we happen to have observed" inference is not evidence of what the authorization server actually intended to invalidate.',
    notes: 'Directly instantiates the rule removed in this pass: a prior revision resolved this exact shape to confirmed_drift via a sole-candidate fallback.'
  });
}

function t3_v13_requestIdReusedAfterReopen() {
  const file = 'track3/v13_request_id_reused_after_reopen.jsonl';
  const clock = new Clock('2026-10-03T10:20:00.000Z');
  const ctx = { protocolVersion: PROTOCOL_VERSION, transport: TRANSPORT };
  const evts = [];
  const p = hmacHash('principal:alice-v13-04');
  const oldBinding = 'binding:v13-04:old', newBinding = 'binding:v13-04:new';
  sub(evts, clock, ctx, { subId: '5', instanceId: 'inst-v13-04-old', principalHash: p, bindingId: oldBinding, validUntil: '2026-10-03T12:00:00.000Z' });
  clock.t = Date.parse('2026-10-03T10:25:00.000Z');
  change(evts, clock, ctx, { principalHash: p, type: 'revoked', effectiveAt: clock.iso(), detectedAt: clock.iso(), confidence: 'authoritative', affectedScope: 'binding', affectedBindingIds: [oldBinding] });
  clock.t = Date.parse('2026-10-03T10:26:00.000Z');
  closeSub(evts, clock, ctx, { subId: '5', instanceId: 'inst-v13-04-old', principalHash: p, reason: 'transport_drop' });
  // Client reopens, reusing the IDENTICAL wire subscription_id ("5") -- a brand-new instance and
  // a brand-new binding.
  clock.t = Date.parse('2026-10-03T10:30:00.000Z');
  sub(evts, clock, ctx, { subId: '5', instanceId: 'inst-v13-04-new', principalHash: p, bindingId: newBinding, validUntil: '2026-10-03T12:00:00.000Z' });
  clock.t = Date.parse('2026-10-03T10:35:00.000Z');
  notify(evts, clock, ctx, { subId: '5', instanceId: 'inst-v13-04-new', principalHash: p, uriHash: hmacHash('resource:v13-04') });
  corpus.pushAll(file, evts);
  record({
    scenario_id: 'V13-04', file,
    purpose: 'EXAMPLE #9 (same-principal reopen -- V12-05 covers the cross-tenant direction): the wire subscription_id ("5") is reused by the SAME principal after closing and reopening. The old instance was revoked and closed; the new instance (distinct instance_id, distinct binding) must not be affected by the old instance\'s close or revocation.',
    expected_detection_track_1: false, expected_detection_track_2: false, expected_detection_track_3: false,
    expected_confidence: 'not_applicable', false_positive_test: true, evasion_test: false, telemetry_limitation: null, notes: null
  });
}

function t3_v13_incompleteTimingEvidence() {
  const file = 'track3/v13_incomplete_timing_evidence.jsonl';
  const clock = new Clock('2026-10-03T10:40:00.000Z');
  const ctx = { protocolVersion: PROTOCOL_VERSION, transport: TRANSPORT };
  const evts = [];
  const p = hmacHash('principal:alice-v13-05');
  const binding = 'binding:v13-05';
  sub(evts, clock, ctx, { subId: '30005', principalHash: p, bindingId: binding, validUntil: '2026-10-03T13:00:00.000Z' });
  clock.t = Date.parse('2026-10-03T10:45:00.000Z');
  // Self-contradictory record: claims timing_confidence=authoritative (and the scope IS known)
  // but carries no effective_at at all.
  change(evts, clock, ctx, { principalHash: p, type: 'revoked', detectedAt: clock.iso(), confidence: 'authoritative', affectedScope: 'binding', affectedBindingIds: [binding] });
  clock.t = Date.parse('2026-10-03T10:50:00.000Z');
  notify(evts, clock, ctx, { subId: '30005', principalHash: p, uriHash: hmacHash('resource:v13-05') });
  corpus.pushAll(file, evts);
  record({
    scenario_id: 'V13-05', file,
    purpose: 'EXAMPLE #10 (timing-specific case): the revocation\'s SCOPE is unambiguous (affected_scope=binding, correctly naming this instance\'s binding), but its TIMING evidence is incomplete -- it claims timing_confidence=authoritative yet carries no effective_at at all, a self-contradictory record. Must report insufficient_evidence, never silently fall back to "does not apply" (which would be a false negative) or to detected_at (which would violate the locked timing-confidence model).',
    expected_detection_track_1: false, expected_detection_track_2: false, expected_detection_track_3: false,
    expected_confidence: 'insufficient_evidence', false_positive_test: false, evasion_test: true,
    telemetry_limitation: 'Classification: NOT DETECTABLE as a resolvable finding -- an authorization-server record that claims authoritative timing without providing effective_at is malformed at the source; no query-level fix compensates for it.',
    notes: null
  });
}

function t3_v13_allPrincipalBindingsPreciseInterval() {
  const file = 'track3/v13_all_principal_bindings_precise_interval.jsonl';
  const clock = new Clock('2026-10-03T11:00:00.000Z');
  const ctx = { protocolVersion: PROTOCOL_VERSION, transport: TRANSPORT };
  const evts = [];
  const p = hmacHash('principal:alice-v13-06');
  const oldBinding = 'binding:v13-06:old', newBinding = 'binding:v13-06:new';
  sub(evts, clock, ctx, { subId: '30008', principalHash: p, bindingId: oldBinding, validUntil: '2026-10-03T14:00:00.000Z' });
  clock.t = Date.parse('2026-10-03T11:05:00.000Z');
  // account-wide disablement -- explicitly claims to cover EVERY binding this principal holds.
  change(evts, clock, ctx, { principalHash: p, type: 'revoked', effectiveAt: clock.iso(), detectedAt: clock.iso(), confidence: 'authoritative', affectedScope: 'all_principal_bindings' });
  clock.t = Date.parse('2026-10-03T11:10:00.000Z'); // the OLD binding existed at effective_at -- must confirm
  notify(evts, clock, ctx, { subId: '30008', principalHash: p, uriHash: hmacHash('resource:v13-06-old') });
  // A brand-new binding is issued for the SAME principal AFTER the disablement event -- it did
  // not exist at effective_at, so the account-wide claim could not possibly have covered it.
  clock.t = Date.parse('2026-10-03T11:15:00.000Z');
  sub(evts, clock, ctx, { subId: '30009', principalHash: p, bindingId: newBinding, validUntil: '2026-10-03T14:00:00.000Z' });
  clock.t = Date.parse('2026-10-03T11:20:00.000Z');
  notify(evts, clock, ctx, { subId: '30009', principalHash: p, uriHash: hmacHash('resource:v13-06-new') });
  corpus.pushAll(file, evts);
  record({
    scenario_id: 'V13-06', file,
    purpose: 'PRECISE EFFECTIVE-TIME INTERVAL (replaces an "ever observed anywhere in the window" approximation): an affected_scope=all_principal_bindings revocation explicitly claims to cover every binding this principal holds. The OLD binding existed at effective_at and must confirm. A NEW binding issued AFTER effective_at did not exist yet at the moment of the change, so the account-wide claim could not have covered it -- it must NOT confirm, even though it shares the same principal and the same nominal "all bindings" change.',
    expected_detection_track_1: false, expected_detection_track_2: false, expected_detection_track_3: true,
    expected_confidence: 'high', false_positive_test: false, evasion_test: false, telemetry_limitation: null,
    notes: 'See tests/validation/track3_row_regression.test.js for the exact per-subscription split (old confirms, new does not).'
  });
}

// ===========================================================================
// ENRICHMENT -- V8
// ===========================================================================

function e_tinyMaliciousMismatch() {
  const file = 'enrichment/v8_tiny_malicious_mismatch.jsonl';
  const clock = new Clock('2026-10-01T14:00:00.000Z');
  const ctx = { protocolVersion: PROTOCOL_VERSION, transport: TRANSPORT };
  const evts = [];
  const taskA = hmacHash('task-v8-01-A'); const taskB = hmacHash('task-v8-01-B');
  const { overallResult } = requestValidationResponse(evts, clock, ctx, {
    reqId: '80', method: 'tasks/get', headerMethod: 'tasks/get', headerNameHash: taskA, bodyIdentityHash: taskB,
    responseOverrides: { 'event.outcome': 'failure', 'rpc.status_code': '-32020', 'error.type': 'HeaderMismatch', 'http.response.status_code': 400 }
  });
  corpus.pushAll(file, evts);
  record({
    scenario_id: 'V8-01', file, purpose: 'A minimal, low-volume routing conflict with essentially no enrichment telemetry (no trace_id, no output/token fields at all -- there is no task.state or completion here). Confirms enrichment absence never suppresses a genuine Track 1 verdict.',
    expected_detection_track_1: true, expected_detection_track_2: false, expected_detection_track_3: false,
    expected_confidence: 'high', false_positive_test: false, evasion_test: false, telemetry_limitation: null,
    notes: `overall=${overallResult}`
  });
}

function e_hugeLegitimateResult() {
  const file = 'enrichment/v8_huge_legitimate_result.jsonl';
  const clock = new Clock('2026-10-01T14:05:00.000Z');
  const ctx = { protocolVersion: PROTOCOL_VERSION, transport: TRANSPORT };
  const evts = [];
  const taskHash = hmacHash('task-v8-02-0001');
  const principalHash = hmacHash('principal:owner-v8-02');
  seedTaskState(evts, clock, taskHash, ctx);
  clock.advance(1000);
  requestValidationResponse(evts, clock, ctx, { reqId: '81', method: 'tasks/get', headerMethod: 'tasks/get', headerNameHash: taskHash, bodyIdentityHash: taskHash });
  authorizationEvent(evts, clock, ctx, { principalHash, taskHash, contextHash: principalHash, operation: 'get', decision: 'allow', reason: 'authorized_owner' });
  evts.push(envelope(clock.advance(1200), 'mcp.task.state', 'process', {
    ...ctx, fields: {
      'mcp.task.id_hash': taskHash, 'mcp.task.state': 'completed', 'mcp.task.previous_state': 'working',
      'mcp.output.schema_valid': true, 'mcp.output.bytes': 20971520, 'mcp.output.item_count': 200000
    }
  }));
  evts.push(envelope(clock.advance(5), 'mcp.response', 'network', { ...ctx, fields: { 'event.outcome': 'success', 'jsonrpc.request.id': '81', 'http.response.status_code': 200 } }));
  corpus.pushAll(file, evts);
  record({
    scenario_id: 'V8-02', file, purpose: '20 MiB / 200,000-item legitimate, fully authorized output. Stress variant of Block 3 N10 with a larger payload.',
    expected_detection_track_1: false, expected_detection_track_2: false, expected_detection_track_3: false,
    expected_confidence: 'not_applicable', false_positive_test: true, evasion_test: false, telemetry_limitation: null, notes: null
  });
}

function e_highTokenValidState() {
  const file = 'enrichment/v8_high_token_valid_state.jsonl';
  const clock = new Clock('2026-10-01T14:10:00.000Z');
  const ctx = { protocolVersion: PROTOCOL_VERSION, transport: TRANSPORT };
  const evts = [];
  const taskHash = hmacHash('task-v8-03-0001');
  const principalHash = hmacHash('principal:owner-v8-03');
  seedTaskState(evts, clock, taskHash, ctx);
  clock.advance(1000);
  requestValidationResponse(evts, clock, ctx, { reqId: '82', method: 'tasks/get', headerMethod: 'tasks/get', headerNameHash: taskHash, bodyIdentityHash: taskHash });
  authorizationEvent(evts, clock, ctx, { principalHash, taskHash, contextHash: principalHash, operation: 'get', decision: 'allow', reason: 'authorized_owner' });
  evts.push(envelope(clock.advance(1200), 'mcp.task.state', 'process', {
    ...ctx, fields: {
      'mcp.task.id_hash': taskHash, 'mcp.task.state': 'completed', 'mcp.task.previous_state': 'working',
      'mcp.output.schema_valid': true, 'gen_ai.usage.input_tokens': 95000, 'gen_ai.usage.output_tokens': 60000
    }
  }));
  evts.push(envelope(clock.advance(5), 'mcp.response', 'network', { ...ctx, fields: { 'event.outcome': 'success', 'jsonrpc.request.id': '82', 'http.response.status_code': 200 } }));
  corpus.pushAll(file, evts);
  record({
    scenario_id: 'V8-03', file, purpose: 'Very high token usage (155,000 combined) with fully valid protocol/authorization state. SYNTHETIC token values (no LLM invoked), consistent with Block 3 N11\'s documented convention.',
    expected_detection_track_1: false, expected_detection_track_2: false, expected_detection_track_3: false,
    expected_confidence: 'not_applicable', false_positive_test: true, evasion_test: false, telemetry_limitation: null, notes: 'Synthetic enrichment values, same convention as Block 3 N11.'
  });
}

function e_schemaInvalidBenignBug() {
  const file = 'enrichment/v8_schema_invalid_benign_bug.jsonl';
  const clock = new Clock('2026-10-01T14:15:00.000Z');
  const ctx = { protocolVersion: PROTOCOL_VERSION, transport: TRANSPORT };
  const evts = [];
  const taskHash = hmacHash('task-v8-04-0001');
  const principalHash = hmacHash('principal:owner-v8-04');
  seedTaskState(evts, clock, taskHash, ctx);
  clock.advance(1000);
  requestValidationResponse(evts, clock, ctx, { reqId: '83', method: 'tasks/get', headerMethod: 'tasks/get', headerNameHash: taskHash, bodyIdentityHash: taskHash });
  authorizationEvent(evts, clock, ctx, { principalHash, taskHash, contextHash: principalHash, operation: 'get', decision: 'allow', reason: 'authorized_owner' });
  evts.push(envelope(clock.advance(1200), 'mcp.task.state', 'process', {
    ...ctx, fields: { 'mcp.task.id_hash': taskHash, 'mcp.task.state': 'completed', 'mcp.task.previous_state': 'working', 'mcp.output.schema_valid': false, 'mcp.output.bytes': 512, 'mcp.output.item_count': 1 }
  }));
  evts.push(envelope(clock.advance(5), 'mcp.response', 'network', { ...ctx, fields: { 'event.outcome': 'success', 'jsonrpc.request.id': '83', 'http.response.status_code': 200 } }));
  corpus.pushAll(file, evts);
  record({
    scenario_id: 'V8-04', file, purpose: 'A tool returns output that fails its own declared outputSchema (mcp.output.schema_valid=false) -- an application bug -- while routing and authorization are both entirely valid. Schema invalidity alone must never generate a malicious verdict.',
    expected_detection_track_1: false, expected_detection_track_2: false, expected_detection_track_3: false,
    expected_confidence: 'not_applicable', false_positive_test: true, evasion_test: false, telemetry_limitation: null, notes: null
  });
}

function e_lowTokenViolation() {
  const file = 'enrichment/v8_low_token_violation.jsonl';
  const clock = new Clock('2026-10-01T14:20:00.000Z');
  const ctx = { protocolVersion: PROTOCOL_VERSION, transport: TRANSPORT };
  const evts = [];
  const taskHash = hmacHash('task-v8-05-0001');
  const ownerHash = hmacHash('principal:owner-v8-05');
  const attackerHash = hmacHash('principal:attacker-v8-05');
  seedTaskState(evts, clock, taskHash, ctx);
  clock.advance(1000);
  requestValidationResponse(evts, clock, ctx, { reqId: '84', method: 'tasks/get', headerMethod: 'tasks/get', headerNameHash: taskHash, bodyIdentityHash: taskHash });
  authorizationEvent(evts, clock, ctx, { principalHash: attackerHash, taskHash, contextHash: ownerHash, operation: 'get', decision: 'deny', reason: 'principal_mismatch' });
  evts.push(envelope(clock.advance(3), 'mcp.response', 'network', { ...ctx, fields: { 'event.outcome': 'failure', 'jsonrpc.request.id': '84', 'rpc.status_code': '-32602', 'http.response.status_code': 400 } }));
  corpus.pushAll(file, evts);
  record({
    scenario_id: 'V8-05', file, purpose: 'A genuine cross-principal violation with tiny/no output enrichment (the request is denied before any output is ever produced). Confirms Track 2 fires regardless of enrichment magnitude -- small or large, output size is irrelevant to the verdict.',
    expected_detection_track_1: false, expected_detection_track_2: true, expected_detection_track_3: false,
    expected_confidence: 'high', false_positive_test: false, evasion_test: false, telemetry_limitation: null, notes: null
  });
}

// ===========================================================================
// HASHING -- V7
// ===========================================================================

const ROTATED_TEST_KEY = crypto.createHash('sha256').update('block6-rotated-key-v2-DO-NOT-USE-IN-PROD').digest();
function hmacHashWithKey(raw, key) {
  return 'h_' + crypto.createHmac('sha256', key).update(String(raw).trim(), 'utf8').digest().subarray(0, 16).toString('hex');
}

function h_sameEpochEquality() {
  const file = 'hashing/v7_same_epoch_equality.jsonl';
  const clock = new Clock('2026-10-01T15:00:00.000Z');
  const ctx = { protocolVersion: PROTOCOL_VERSION, transport: TRANSPORT };
  const evts = [];
  const taskHash = hmacHash('task-v7-01-0001'); // same HASH_KEY_ID for both sides
  requestValidationResponse(evts, clock, ctx, { reqId: '90', method: 'tasks/get', headerMethod: 'tasks/get', headerNameHash: taskHash, bodyIdentityHash: taskHash });
  corpus.pushAll(file, evts);
  record({
    scenario_id: 'V7-01', file, purpose: 'Positive control: header hash and body hash for the same underlying taskId, computed under the SAME key_id, correctly compare equal (match).',
    expected_detection_track_1: false, expected_detection_track_2: false, expected_detection_track_3: false,
    expected_confidence: 'not_applicable', false_positive_test: true, evasion_test: false, telemetry_limitation: null, notes: `key_id=${HASH_KEY_ID}`
  });
}

function h_differentKeyIdNoSilentCorrelation() {
  const file = 'hashing/v7_different_key_id_no_correlation.jsonl';
  const clock = new Clock('2026-10-01T15:05:00.000Z');
  const ctx = { protocolVersion: PROTOCOL_VERSION, transport: TRANSPORT };
  const evts = [];
  const rawTask = 'task-v7-02-0001';
  const hashUnderV1 = hmacHash(rawTask); // key_id = block3-test-key-v1 (project standard)
  const hashUnderV2 = hmacHashWithKey(rawTask, ROTATED_TEST_KEY); // a DIFFERENT, hypothetical rotated key
  // Two events describing the SAME underlying task, hashed under two different key epochs.
  evts.push(envelope(clock.iso(), 'mcp.task.state', 'process', {
    ...ctx, fields: { 'mcp.task.id_hash': hashUnderV1, 'mcp.task.state': 'working', 'mcp.task.previous_state': null }
  }));
  evts.push(envelope(clock.advance(60000), 'mcp.task.state', 'process', {
    ...ctx, keyId: 'hypothetical-rotated-key-v2',
    fields: { 'mcp.task.id_hash': hashUnderV2, 'mcp.task.state': 'completed', 'mcp.task.previous_state': 'working' }
  }));
  corpus.pushAll(file, evts);
  record({
    scenario_id: 'V7-02', file,
    purpose: 'The SAME underlying taskId, hashed once under this project\'s standard key_id and once under a different, hypothetical rotated key_id, produces two DIFFERENT hash strings. A query that groups/correlates by mcp.task.id_hash alone (ignoring security.hash.key_id) would incorrectly treat these as two unrelated tasks.',
    expected_detection_track_1: false, expected_detection_track_2: false, expected_detection_track_3: false,
    expected_confidence: 'not_applicable', false_positive_test: false, evasion_test: false,
    telemetry_limitation: 'Confirms telemetry/schema.md SS6\'s key-rotation guidance is load-bearing: correlation across a key-epoch boundary silently fails unless security.hash.key_id is checked and a controlled-overlap or epoch-scoping strategy is used. Verified mechanically here: the two hash values are computed and asserted to differ in tests/validation.',
    notes: `hashUnderV1=${hashUnderV1} hashUnderV2=${hashUnderV2}`
  });
}

function h_keyRotationBreaksTrack2Correlation() {
  const file = 'hashing/v7_key_rotation_track2_correlation.jsonl';
  const clock = new Clock('2026-10-01T15:15:00.000Z');
  const ctx = { protocolVersion: PROTOCOL_VERSION, transport: TRANSPORT };
  const evts = [];
  const rawTask = 'task-v7-03-0001';
  const ownerHashV1 = hmacHash('principal:owner-v7-03');
  const attackerHashV2 = hmacHashWithKey('principal:attacker-v7-03', ROTATED_TEST_KEY);
  const taskHashV1 = hmacHash(rawTask);
  const taskHashV2 = hmacHashWithKey(rawTask, ROTATED_TEST_KEY);
  // Before rotation: owner accesses the task, hashed under key v1.
  authorizationEvent(evts, clock, ctx, { principalHash: ownerHashV1, taskHash: taskHashV1, contextHash: ownerHashV1, operation: 'get', decision: 'allow', reason: 'authorized_owner' });
  // Key rotation happens. After rotation: an attacker attempts the SAME underlying task,
  // now hashed under key v2 -- security.hash.key_id differs.
  evts.push(finalizeHashMeta({
    timestamp: clock.advance(3600000),
    'event.name': 'mcp.task.authorization', 'event.category': 'iam',
    'mcp.protocol.version': PROTOCOL_VERSION, 'mcp.transport': TRANSPORT,
    'event.outcome': 'failure', 'principal.id_hash': attackerHashV2, 'principal.authenticated': true,
    'mcp.task.id_hash': taskHashV2, 'mcp.task.authz_context_id_hash': hmacHashWithKey('principal:owner-v7-03', ROTATED_TEST_KEY),
    'mcp.task.operation': 'get', 'mcp.authz.decision': 'deny', 'mcp.authz.allowed': false, 'mcp.authz.reason': 'principal_mismatch'
  }, 'hypothetical-rotated-key-v2'));
  corpus.pushAll(file, evts);
  record({
    scenario_id: 'V7-03', file,
    purpose: 'DOCUMENTED OPERATIONAL RISK: the same underlying task is referenced before and after a key rotation. Both mcp.task.authorization events independently and correctly fire/don\'t-fire on their own (the second IS a real Track 2 violation, and fires correctly on its own record). What does NOT work across the rotation boundary is CROSS-TIME correlation by mcp.task.id_hash (e.g. "has this task ever been accessed by anyone other than its owner, across all time") -- the pre- and post-rotation hashes for the same task do not match, so such a historical query would miss the connection.',
    expected_detection_track_1: false, expected_detection_track_2: true, expected_detection_track_3: false,
    expected_confidence: 'high', false_positive_test: false, evasion_test: false,
    telemetry_limitation: 'This is the accepted, documented tradeoff from telemetry/schema.md SS6 ("Historical correlation across a key rotation boundary is not automatically valid") -- not a defect introduced in Block 6. The per-event Track 2 verdict is unaffected; only cross-epoch historical correlation is.',
    notes: 'The second (post-rotation) event alone is what the manifest\'s expected_detection_track_2=true refers to; per-event evaluation is required here, not per-file (see tests/validation).'
  });
}

// ===========================================================================
// Run all
// ===========================================================================
t1_versionIncompatibleResourcesRead();
t1_missingUnderRequiredVersion();
t1_collectorDerivedCorrect();
t1_proxyHeaderCasingNormalized();
t1_malformedRejectedBeforeRouting();
t1_unsupportedMethod();
t1_applicationErrorMatchingRouting();
t1_canonicalizationInstrumentationGap();
t1_canonicalizationCorrectControl();
t1t2_v2_perfectRoutingStolenHandle();

t2_delegatedAccessServicePrincipal();
t2_policyChangeExpandsAccess();
t2_genericDenialPolicy();
t2_nonexistentTask();
t2_authenticationFailure();
t2_missingAuthzContextButAllowed();
t2_staleOptionalTelemetry();
t2_v4_authzSystemWronglyAllows();
t2_v4_authorizationTelemetryDisabled();

t3_effectiveAtAfterNotification();
t3_gracePeriodPolicy();
t3_renewalMisclassifiedAsRevocation();
t3_streamClosesExactlyAtBoundary();
t3_notificationEqualsEffectiveAt();
t3_clockSkewFalseNegative();
t3_largeDetectedEffectiveGap();
t3_policyPermitsOpenStreams();
t3_v6_noInvalidityEvidenceAtAll();
t3_v6_subscriptionIdMissingOnNotification();

t3_v11_multipleChangesOutOfOrder();
t3_v11_sameSubIdDifferentPrincipals();
t3_v11_revocationAndExpiryBothApply();
t3_v11_expiryBeforeFutureRevocation();
t3_v11_revocationNoRetainedOpenEvent();
t3_v11_closeOnOtherSubscription();
t3_v11_closeExactlyAtNotification();
t3_v11_notificationEqualsValidUntil();
t3_v11_scopeUpgradeNoInvalidation();
t3_v11_multipleCloseEvents();
t3_v11_samePrincipalCrossSubscriptionRisk();

t3_v12_sameprincipalOnlyOneAlerts();
t3_v12_sharedGrantBothAlert();
t3_v12_unrelatedScopeRemoved();
t3_v12_requiredScopeRemoved();
t3_v12_sameWireIdAcrossTenants();
t3_v12_oldBindingExpiresAfterProvenReplacement();
t3_v12_newUnrelatedAuthDoesNotSuppressOldViolation();
t3_v12_outOfOrderArrivalTrustworthyTiming();
t3_v12_missingScopeEvidence();
t3_v12_conflictingEvidence();
t3_v12_incompatibleHashEpoch();
t3_v12_directlyScopedNoRetainedOpen();
t3_v12_correctedCrossSubscriptionCounterpart();

t3_v13_confirmedDuringInvalidIntervalRenewalDoesNotErase();
t3_v13_unrelatedBindingEarlier();
t3_v13_unknownScopeSingleCandidate();
t3_v13_requestIdReusedAfterReopen();
t3_v13_incompleteTimingEvidence();
t3_v13_allPrincipalBindingsPreciseInterval();

e_tinyMaliciousMismatch();
e_hugeLegitimateResult();
e_highTokenValidState();
e_schemaInvalidBenignBug();
e_lowTokenViolation();

h_sameEpochEquality();
h_differentKeyIdNoSilentCorrelation();
h_keyRotationBreaksTrack2Correlation();

corpus.writeOut();
const totalEvents = [...corpus.files.values()].reduce((n, evts) => n + evts.length, 0);
console.log(`Wrote ${corpus.files.size} JSONL files + manifest.jsonl (${corpus.manifest.length} scenarios, ${totalEvents} total events) to ${DATA_DIR}`);
