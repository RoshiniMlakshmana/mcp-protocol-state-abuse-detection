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
    ...ctx, fields: {
      'jsonrpc.request.id': opt.subId, 'mcp.subscription.id': opt.subId,
      'principal.id_hash': opt.principalHash, 'principal.authenticated': true,
      'mcp.authz.grant_snapshot_hash': hmacHash('grant:' + opt.subId),
      ...(opt.validUntil ? { 'mcp.authz.grant_expiry': opt.validUntil, 'mcp.authz.valid_until': opt.validUntil } : {})
    }
  }));
  evts.push(envelope(clock.advance(50), 'mcp.subscription.acknowledged', 'session', {
    ...ctx, fields: { 'event.outcome': 'success', 'mcp.subscription.id': opt.subId, 'principal.id_hash': opt.principalHash, 'mcp.subscription.state': 'acknowledged' }
  }));
}
function notify(evts, clock, ctx, opt) {
  evts.push(envelope(clock.iso(), 'mcp.subscription.notification', 'session', {
    ...ctx, fields: {
      'mcp.subscription.id': opt.subId === undefined ? undefined : opt.subId,
      'principal.id_hash': opt.principalHash, 'mcp.subscription.state': 'active',
      'mcp.subscription.notification_type': opt.type || 'notifications/resources/updated',
      ...(opt.uriHash ? { 'mcp.subscription.notification.resource_uri_hash': opt.uriHash } : {})
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
      'mcp.authz.change.timing_confidence': opt.confidence
    }
  }));
}
function closeSub(evts, clock, ctx, opt) {
  evts.push(envelope(clock.iso(), 'mcp.subscription.close', 'session', {
    ...ctx, fields: { 'event.outcome': 'success', 'mcp.subscription.id': opt.subId, 'principal.id_hash': opt.principalHash, 'mcp.subscription.state': opt.state || 'closed_graceful', 'mcp.subscription.close.reason': opt.reason }
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
    purpose: 'ACCEPTED, DOCUMENTED FALSE POSITIVE: a notification is delivered 3 minutes after a scope downgrade, within a hypothetical deployment-defined 5-minute grace period during which continuing to deliver non-sensitive list-changed notifications is an explicit, documented policy decision. The locked Block 2 schema has NO field encoding a grace-period duration, so the current rule logic (correctly, given available telemetry) still flags this.',
    expected_detection_track_1: false, expected_detection_track_2: false, expected_detection_track_3: true,
    expected_confidence: 'high', false_positive_test: true, evasion_test: false,
    telemetry_limitation: 'No mcp.*.grace_period field exists in the locked telemetry contract (Block 2). Adding one would be a schema change, out of scope for a rule-tuning pass. Tuning recommendation (deployment-side, not a rule change): apply a per-deployment grace-period CONSTANT in the query (boundary + grace_period) rather than inventing a new field. See docs/false-positive-analysis.md.',
    notes: 'Deliberately left unfixed -- see docs/validation-report.md "false positives discovered, not fixed".'
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
  sub(evts, clock, ctx, { subId: '5007', principalHash: p, validUntil: '2026-10-01T16:00:00.000Z' });
  clock.t = Date.parse('2026-10-01T12:25:00.000Z');
  notify(evts, clock, ctx, { subId: '5007', principalHash: p, uriHash: hmacHash('resource:v5-07') });
  // effective_at is only 5 minutes after open, but detected_at is a full 2 HOURS later --
  // authoritative timing must still be trusted regardless of how large this gap is.
  change(evts, clock, ctx, {
    principalHash: p, type: 'revoked', effectiveAt: '2026-10-01T12:22:00.000Z',
    detectedAt: '2026-10-01T14:20:00.000Z', confidence: 'authoritative'
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
  sub(evts, clock, ctx, { subId: '5009', principalHash: p, validUntil: '2026-10-01T14:00:00.000Z' });
  clock.t = Date.parse('2026-10-01T12:35:00.000Z');
  const effAt = clock.iso();
  change(evts, clock, ctx, { principalHash: p, type: 'revoked', effectiveAt: effAt, detectedAt: effAt, confidence: 'authoritative' });
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
    purpose: 'EVASION / TELEMETRY GAP -- PARTIALLY DETECTABLE. A notification event is missing mcp.subscription.id (malformed/incomplete instrumentation). The KQL/SPL correlation still successfully joins the revocation to the PRINCIPAL (via principal.id_hash), so the drift is still detectable via the revocation-leg join alone in this project\'s actual implementation -- but any logic that required mcp.subscription.id on the notification leg specifically (e.g. the close-suppression anti-join) would silently fail to exclude a legitimately-closed different subscription for the same principal.',
    expected_detection_track_1: false, expected_detection_track_2: false, expected_detection_track_3: true,
    expected_confidence: 'high', false_positive_test: false, evasion_test: true,
    telemetry_limitation: 'PARTIALLY DETECTABLE: the primary-principal join still works, but the close-suppression check (which currently keys on mcp.subscription.id) cannot be trusted for this record -- see tests/validation and docs/validation-report.md for what still fires here and why the close-anti-join is a residual risk in this exact shape.',
    notes: null
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
  sub(evts, clock, ctx, { subId: '10001', principalHash: p, validUntil: '2026-10-01T20:00:00.000Z' });
  clock.t = Date.parse('2026-10-01T17:05:00.000Z');
  // Change A is EMITTED FIRST in the file but carries a LATER (further future) effective_at.
  change(evts, clock, ctx, { principalHash: p, type: 'revoked', effectiveAt: '2026-10-01T18:00:00.000Z', detectedAt: clock.iso(), confidence: 'authoritative' });
  clock.t = Date.parse('2026-10-01T17:10:00.000Z');
  // Change B is EMITTED SECOND in the file but carries an EARLIER effective_at than change A.
  change(evts, clock, ctx, { principalHash: p, type: 'revoked', effectiveAt: '2026-10-01T17:07:00.000Z', detectedAt: clock.iso(), confidence: 'authoritative' });
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
  // mcp.subscription.id is only a per-connection JSON-RPC request id (Block 1 SS7) -- it is not
  // guaranteed globally unique, so two different principals' independent connections can
  // legitimately reuse the same subscription_id string.
  sub(evts, clock, ctx, { subId: '10002', principalHash: pA, validUntil: '2026-10-01T20:00:00.000Z' });
  clock.t = Date.parse('2026-10-01T17:40:00.000Z');
  sub(evts, clock, ctx, { subId: '10002', principalHash: pB, validUntil: '2026-10-01T20:00:00.000Z' });
  clock.t = Date.parse('2026-10-01T17:45:00.000Z');
  change(evts, clock, ctx, { principalHash: pA, type: 'revoked', effectiveAt: clock.iso(), detectedAt: clock.iso(), confidence: 'authoritative' }); // Alice ONLY
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
  sub(evts, clock, ctx, { subId: '10003', principalHash: p, validUntil: '2026-10-01T18:10:00.000Z' });
  clock.t = Date.parse('2026-10-01T18:05:00.000Z');
  change(evts, clock, ctx, { principalHash: p, type: 'revoked', effectiveAt: '2026-10-01T18:03:00.000Z', detectedAt: clock.iso(), confidence: 'authoritative' });
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
  sub(evts, clock, ctx, { subId: '10004', principalHash: p, validUntil: '2026-10-01T18:35:00.000Z' }); // expires EARLY
  clock.t = Date.parse('2026-10-01T18:36:00.000Z'); // after expiry, before any revocation exists
  notify(evts, clock, ctx, { subId: '10004', principalHash: p, uriHash: hmacHash('resource:v11-04-a') });
  clock.t = Date.parse('2026-10-01T18:40:00.000Z');
  change(evts, clock, ctx, { principalHash: p, type: 'revoked', effectiveAt: '2026-10-01T18:45:00.000Z', detectedAt: clock.iso(), confidence: 'authoritative' }); // FUTURE relative to N1
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
    purpose: 'REGRESSION (this pass): the revocation-leg join (principal_hash only) must not require an mcp.subscription.open event to exist at all -- this fixture has NONE. The real KQL/SPL revocation leg never references the Notifications-vs-Opens relationship, only Notifications-vs-AuthoritativeChanges by principal, so this must still fire. The previous oracle bailed out entirely to not_applicable whenever no open event existed, which was stricter than the real query and would have produced a false negative here.',
    expected_detection_track_1: false, expected_detection_track_2: false, expected_detection_track_3: true,
    expected_confidence: 'high', false_positive_test: false, evasion_test: false,
    telemetry_limitation: null,
    notes: null
  });
}

function t3_v11_closeOnOtherSubscription() {
  const file = 'track3/v11_close_on_other_subscription.jsonl';
  const clock = new Clock('2026-10-01T19:15:00.000Z');
  const ctx = { protocolVersion: PROTOCOL_VERSION, transport: TRANSPORT };
  const evts = [];
  const p = hmacHash('principal:alice-v11-06');
  sub(evts, clock, ctx, { subId: '10006', principalHash: p, validUntil: '2026-10-01T21:00:00.000Z' }); // subscription A -- stays open
  clock.t = Date.parse('2026-10-01T19:16:00.000Z');
  sub(evts, clock, ctx, { subId: '10007', principalHash: p, validUntil: '2026-10-01T21:00:00.000Z' }); // subscription B -- same principal, different id
  clock.t = Date.parse('2026-10-01T19:20:00.000Z');
  change(evts, clock, ctx, { principalHash: p, type: 'revoked', effectiveAt: clock.iso(), detectedAt: clock.iso(), confidence: 'authoritative' });
  clock.t = Date.parse('2026-10-01T19:22:00.000Z');
  closeSub(evts, clock, ctx, { subId: '10007', principalHash: p, reason: 'client_disconnect' }); // closes B, NOT A
  clock.t = Date.parse('2026-10-01T19:25:00.000Z');
  notify(evts, clock, ctx, { subId: '10006', principalHash: p, uriHash: hmacHash('resource:v11-06') }); // A's notification continues
  corpus.pushAll(file, evts);
  record({
    scenario_id: 'V11-06', file,
    purpose: 'REGRESSION (this pass): the same principal holds two subscriptions; one (B) is closed, the other (A) is not. A\'s post-revocation notification must still fire -- B\'s close must not suppress it. Confirms close-suppression is correctly scoped by subscription_id (not just principal_hash) in the direction opposite to the V11-02/close-suppression fix above.',
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
  sub(evts, clock, ctx, { subId: '10011', principalHash: p, validUntil: '2026-10-01T23:00:00.000Z' });
  clock.t = Date.parse('2026-10-01T20:25:00.000Z');
  change(evts, clock, ctx, { principalHash: p, type: 'revoked', effectiveAt: clock.iso(), detectedAt: clock.iso(), confidence: 'authoritative' });
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
    purpose: 'KNOWN, DOCUMENTED, UNRESOLVED RISK (explicitly NOT fixed in this pass -- see docs/validation-report.md "remaining risks" and the comments in detections/kql/mcp_subscription_authorization_drift.kql / detections/spl/...spl / tests/attack/track3util.js): a principal holds two concurrent subscriptions. A revocation event (principal-scoped, no subscription id available at all) is emitted. Subscription B\'s notification, though still legitimately valid in this fixture\'s hypothetical ground truth, MECHANICALLY fires because the revocation-leg join can only scope by principal_hash -- there is no subscription-id field on authorization_change events to narrow it further. This is reported as an unresolved scope boundary, not silently fixed by inventing a field or a grace period.',
    expected_detection_track_1: false, expected_detection_track_2: false, expected_detection_track_3: true,
    expected_confidence: 'high', false_positive_test: false, evasion_test: true,
    telemetry_limitation: 'Classification: DETECTABLE only in the narrow, mechanical sense that the rule fires on subscription B\'s notification -- whether that fire is a TRUE or FALSE positive is UNRESOLVED given current telemetry (unlike a clean NOT DETECTABLE or PARTIALLY DETECTABLE case). mcp.subscription.authorization_change carries no subscription id, so a principal with multiple concurrent subscriptions cannot be disambiguated at the revocation-leg join. Tightening the join to also require subscription_id would eliminate this risk but would reintroduce the V6-02 blind spot (a notification missing its own subscription_id would no longer correlate to a revocation at all). Not classified as false_positive_test because, absent ground truth in real deployments, whether this is actually benign is unknowable from telemetry alone -- unlike V5-02/V5-09, this is not a provably-benign accepted tradeoff.',
    notes: 'This is the "same-principal cross-subscription correlation risk" explicitly called out in the Track 3 remediation instructions; kept unresolved by design.'
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
