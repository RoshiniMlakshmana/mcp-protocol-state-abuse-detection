'use strict';
/**
 * Block 4 controlled-attack corpus generator.
 *
 * Reuses tools/harness/lib/hash.js and tools/harness/lib/protocol.js UNCHANGED from Block 3
 * (no modification to locked Block 3 code) so attack and normal fixtures are directly
 * comparable: same hashing scheme, same real (recomputed, not hand-labeled) Track 1 validation
 * logic, same event envelope shape.
 *
 * Everything here is local, synthetic, deterministic test data. No external systems, no real
 * credentials, no third-party infrastructure is touched or referenced.
 *
 * Determinism: fixed logical clock per scenario, fixed identifiers, fixed HMAC key (same test
 * key as Block 3). Re-running reproduces the corpus byte-for-byte.
 */
const fs = require('fs');
const path = require('path');
const { hmacHash, HASH_KEY_ID, HASH_ALGORITHM } = require('./lib/hash');
const { validateField, validateName, rollup, taskOperationFor } = require('./lib/protocol');

const DATA_DIR = path.join(__dirname, '..', '..', 'data', 'attack');
const PROTOCOL_VERSION = '2026-07-28';
const TRANSPORT = 'streamable-http';

class Clock {
  constructor(startIso) { this.t = Date.parse(startIso); }
  iso() { return new Date(this.t).toISOString(); }
  advance(ms) { this.t += ms; return this.iso(); }
}

function finalizeHashMeta(evt) {
  const hasHash = Object.keys(evt).some(
    (k) => k.endsWith('_hash') && evt[k] !== null && evt[k] !== undefined
  );
  if (hasHash) {
    evt['security.hash.key_id'] = HASH_KEY_ID;
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
  });
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
    const manifestBody = this.manifest.map((r) => JSON.stringify(r)).join('\n') + '\n';
    fs.mkdirSync(DATA_DIR, { recursive: true });
    fs.writeFileSync(path.join(DATA_DIR, 'manifest.jsonl'), manifestBody, 'utf8');
  }
}

const corpus = new Corpus();

function seedTaskState(evts, clock, taskHash, ctx) {
  evts.push(envelope(clock.iso(), 'mcp.task.state', 'process', {
    ...ctx, fields: { 'mcp.task.id_hash': taskHash, 'mcp.task.state': 'working', 'mcp.task.previous_state': null }
  }));
}

function requestTriplet(evts, clock, ctx, { reqId, method, headerMethod, headerNameHash, bodyIdentityHash }) {
  evts.push(envelope(clock.iso(), 'mcp.request.received', 'network', {
    ...ctx, fields: {
      'rpc.system.name': 'jsonrpc', 'rpc.method': method, 'mcp.body.method': method,
      'jsonrpc.request.id': reqId,
      'mcp.header.method': headerMethod,
      'mcp.header.name_hash': headerNameHash, 'mcp.body.identity_hash': bodyIdentityHash,
      'http.request.method': 'POST'
    }
  }));
  const methodResult = validateField(
    ctx.protocolVersion || PROTOCOL_VERSION,
    { present: headerMethod !== null && headerMethod !== undefined, value: headerMethod },
    method
  );
  const nameResult = validateName(
    ctx.protocolVersion || PROTOCOL_VERSION,
    { present: headerNameHash !== null && headerNameHash !== undefined, value: headerNameHash },
    bodyIdentityHash,
    method
  );
  const overallResult = rollup(methodResult, nameResult);
  return { methodResult, nameResult, overallResult };
}

function pushValidation(evts, clock, ctx, { reqId, method, headerMethod, headerNameHash, bodyIdentityHash, methodResult, nameResult, overallResult, reason }) {
  evts.push(envelope(clock.advance(3), 'mcp.request.validation', 'network', {
    ...ctx, fields: {
      'event.outcome': overallResult === 'valid' ? 'success' : 'failure',
      'jsonrpc.request.id': reqId, 'mcp.body.method': method, 'mcp.header.method': headerMethod,
      'mcp.header.name_hash': headerNameHash, 'mcp.body.identity_hash': bodyIdentityHash,
      'mcp.validation.method.result': methodResult, 'mcp.validation.name.result': nameResult,
      'mcp.validation.result': overallResult, 'mcp.validation.source': 'server_native',
      ...(reason ? { 'mcp.validation.reason': reason } : {})
    }
  }));
}

function pushHeaderMismatchResponse(evts, clock, ctx, reqId) {
  evts.push(envelope(clock.advance(4), 'mcp.response', 'network', {
    ...ctx, fields: {
      'event.outcome': 'failure', 'jsonrpc.request.id': reqId,
      'rpc.status_code': '-32020', 'error.type': 'HeaderMismatch', 'http.response.status_code': 400
    }
  }));
}

function pushOkResponse(evts, clock, ctx, reqId) {
  evts.push(envelope(clock.advance(5), 'mcp.response', 'network', {
    ...ctx, fields: { 'event.outcome': 'success', 'jsonrpc.request.id': reqId, 'http.response.status_code': 200 }
  }));
}

function pushDeniedResponse(evts, clock, ctx, reqId) {
  evts.push(envelope(clock.advance(3), 'mcp.response', 'network', {
    ...ctx, fields: {
      'event.outcome': 'failure', 'jsonrpc.request.id': reqId,
      'rpc.status_code': '-32602', 'http.response.status_code': 400
    }
  }));
}

// ===========================================================================
// TRACK 1 -- Task Routing Desynchronization (A1-A5) + control (A6)
// ===========================================================================

function routingMismatchScenario({
  scenarioId, file, method, description, violated, isolation,
  taskAraw, taskBraw, headerMethodOverride, bodyMethodOverride, reasonText, startIso
}) {
  const clock = new Clock(startIso);
  const ctx = { protocolVersion: PROTOCOL_VERSION, transport: TRANSPORT };
  const evts = [];
  const taskAHash = hmacHash(taskAraw);
  const taskBHash = hmacHash(taskBraw);

  seedTaskState(evts, clock, taskAHash, ctx);
  if (taskBHash !== taskAHash) { clock.advance(10); seedTaskState(evts, clock, taskBHash, ctx); }

  const reqId = '1';
  const headerMethod = headerMethodOverride !== undefined ? headerMethodOverride : method;
  const bodyMethod = bodyMethodOverride !== undefined ? bodyMethodOverride : method;
  clock.advance(500);
  const { methodResult, nameResult, overallResult } = requestTriplet(evts, clock, ctx, {
    reqId, method: bodyMethod, headerMethod, headerNameHash: taskAHash, bodyIdentityHash: taskBHash
  });
  pushValidation(evts, clock, ctx, {
    reqId, method: bodyMethod, headerMethod, headerNameHash: taskAHash, bodyIdentityHash: taskBHash,
    methodResult, nameResult, overallResult, reason: reasonText
  });
  // Per Block 1/2 (docs/threat-model.md SS9, telemetry/correlation.md): a HeaderMismatch
  // rejection happens at validation, BEFORE any authorization check runs. No
  // mcp.task.authorization event is emitted here -- this is what keeps Track 2 = false.
  pushHeaderMismatchResponse(evts, clock, ctx, reqId);

  corpus.pushAll(file, evts);
  corpus.record({
    scenario_id: scenarioId, file, description, provenance: 'project_reference_harness',
    expected_security_outcome: 'malicious',
    expected_detection_track_1: true, expected_detection_track_2: false, expected_detection_track_3: false,
    expected_confidence: 'high',
    violated_invariant: violated,
    required_evidence: [
      'mcp.header.method', 'mcp.body.method', 'mcp.header.name_hash', 'mcp.body.identity_hash',
      'mcp.validation.method.result', 'mcp.validation.name.result', 'mcp.validation.result',
      'mcp.validation.source', 'rpc.status_code', 'http.response.status_code'
    ],
    cross_track_isolation: isolation, experimental: false,
    event_count: evts.length,
    notes: 'No mcp.task.authorization event is emitted: the request is rejected at routing validation before any authorization check runs, which is why Track 2 stays false here even though the request targeted a task.'
  });
}

function scenarioA1() {
  routingMismatchScenario({
    scenarioId: 'A1', file: 'track1/task_get_identity_mismatch.jsonl', method: 'tasks/get',
    description: 'Mcp-Name header identifies Task-A while the JSON-RPC body params.taskId identifies Task-B, on tasks/get. Method itself matches.',
    violated: 'Routing header task identity must equal request body task identity (docs/state-invariants.md row 2).',
    isolation: 'track1_only',
    taskAraw: 'task-a1-TaskA', taskBraw: 'task-a1-TaskB', startIso: '2026-09-05T14:00:00.000Z',
    reasonText: 'Mcp-Name header identifies Task-A but params.taskId in the body identifies Task-B.'
  });
}
function scenarioA2() {
  routingMismatchScenario({
    scenarioId: 'A2', file: 'track1/task_update_identity_mismatch.jsonl', method: 'tasks/update',
    description: 'Mcp-Name header identifies Task-A while the JSON-RPC body params.taskId identifies Task-B, on tasks/update.',
    violated: 'Routing header task identity must equal request body task identity (docs/state-invariants.md row 2).',
    isolation: 'track1_only',
    taskAraw: 'task-a2-TaskA', taskBraw: 'task-a2-TaskB', startIso: '2026-09-05T14:05:00.000Z',
    reasonText: 'Mcp-Name header identifies Task-A but params.taskId in the body identifies Task-B.'
  });
}
function scenarioA3() {
  routingMismatchScenario({
    scenarioId: 'A3', file: 'track1/task_cancel_identity_mismatch.jsonl', method: 'tasks/cancel',
    description: 'Mcp-Name header identifies Task-A while the JSON-RPC body params.taskId identifies Task-B, on tasks/cancel.',
    violated: 'Routing header task identity must equal request body task identity (docs/state-invariants.md row 2).',
    isolation: 'track1_only',
    taskAraw: 'task-a3-TaskA', taskBraw: 'task-a3-TaskB', startIso: '2026-09-05T14:10:00.000Z',
    reasonText: 'Mcp-Name header identifies Task-A but params.taskId in the body identifies Task-B.'
  });
}
function scenarioA4() {
  routingMismatchScenario({
    scenarioId: 'A4', file: 'track1/method_mismatch.jsonl', method: 'tasks/cancel',
    description: 'Mcp-Method header says tasks/get while the JSON-RPC body method is tasks/cancel; the referenced task identity itself matches on both sides.',
    violated: 'Routing header method must equal request body method (docs/state-invariants.md row 1).',
    isolation: 'track1_only',
    taskAraw: 'task-a4-TaskC', taskBraw: 'task-a4-TaskC', // SAME task both sides -- only method disagrees
    headerMethodOverride: 'tasks/get', bodyMethodOverride: 'tasks/cancel',
    startIso: '2026-09-05T14:15:00.000Z',
    reasonText: 'Mcp-Method header (tasks/get) disagrees with the JSON-RPC body method (tasks/cancel); task identity matches.'
  });
}
function scenarioA5() {
  routingMismatchScenario({
    scenarioId: 'A5', file: 'track1/dual_mismatch.jsonl', method: 'tasks/cancel',
    description: 'Both Mcp-Method and Mcp-Name disagree with the JSON-RPC body simultaneously.',
    violated: 'Routing header method AND routing header task identity must each independently equal the request body (rows 1 and 2).',
    isolation: 'track1_only',
    taskAraw: 'task-a5-TaskA', taskBraw: 'task-a5-TaskB',
    headerMethodOverride: 'tasks/get', bodyMethodOverride: 'tasks/cancel',
    startIso: '2026-09-05T14:20:00.000Z',
    reasonText: 'Both mismatches present: Mcp-Method header (tasks/get) disagrees with body method (tasks/cancel), AND Mcp-Name header identifies Task-A while body params.taskId identifies Task-B. mcp.validation.method.result and mcp.validation.name.result each independently record "conflict", preserving both findings rather than collapsing them into one flag.'
  });
}

function scenarioA6() {
  // Control: header genuinely not required because the negotiated protocol version predates
  // SEP-2243. This must NOT be classified the same as A1-A5's conflicting-value mismatches.
  const file = 'controls/missing_header_compatibility.jsonl';
  const clock = new Clock('2026-09-05T14:30:00.000Z');
  const legacyVersion = '2025-03-26';
  const toolNameHash = hmacHash('tool:legacy_tool_a6');
  const ctx = { protocolVersion: legacyVersion, transport: TRANSPORT };
  const evts = [];
  const reqId = '2';
  const method = 'tools/call';

  evts.push(envelope(clock.iso(), 'mcp.request.received', 'network', {
    ...ctx, fields: {
      'rpc.system.name': 'jsonrpc', 'rpc.method': method, 'mcp.body.method': method,
      'jsonrpc.request.id': reqId, 'mcp.header.method': null, 'mcp.header.name_hash': null,
      'mcp.body.identity_hash': toolNameHash, 'http.request.method': 'POST'
    }
  }));
  const methodResult = validateField(legacyVersion, { present: false }, method);
  const nameResult = validateName(legacyVersion, { present: false }, toolNameHash, method);
  pushValidation(evts, clock, ctx, {
    reqId, method, headerMethod: null, headerNameHash: null, bodyIdentityHash: toolNameHash,
    methodResult, nameResult, overallResult: rollup(methodResult, nameResult),
    reason: 'Negotiated protocol version 2025-03-26 predates Mcp-Method/Mcp-Name (SEP-2243, introduced 2026-07-28). Header absence here is compatibility, not a routing violation. Contrast with A1-A5, where headers ARE present but conflict under 2026-07-28.'
  });
  pushOkResponse(evts, clock, ctx, reqId);

  corpus.pushAll(file, evts);
  corpus.record({
    scenario_id: 'A6', file,
    description: 'A legacy client negotiates protocol version 2025-03-26, which predates the Mcp-Method/Mcp-Name header requirement. This is a diagnostic/compatibility fixture, not an attack.',
    provenance: 'project_reference_harness',
    expected_security_outcome: 'benign_compatibility',
    expected_detection_track_1: false, expected_detection_track_2: false, expected_detection_track_3: false,
    expected_confidence: 'not_applicable',
    violated_invariant: 'None. Per docs/state-invariants.md row 3, a header absent under a protocol version that never defined it is compatibility, not a violation. NOTE: a header missing under a version that DOES require it (2026-07-28) is a real Track 1 violation under the locked model -- that distinct case is exercised by A1-A5\'s use of "conflict", not by this fixture.',
    required_evidence: ['mcp.protocol.version', 'mcp.validation.method.result=version_incompatible', 'mcp.validation.name.result=version_incompatible', 'mcp.validation.result=valid'],
    cross_track_isolation: null, experimental: false,
    event_count: evts.length,
    notes: 'Exists specifically to prove false-positive separation: any later detection logic keying on "header absent/conflicting" must not fire on this fixture the way it fires on A1-A5.'
  });
}

// ===========================================================================
// TRACK 2 -- Cross-Principal Task Authorization Violation (A7-A10)
// ===========================================================================

function unauthorizedScenario({ scenarioId, file, method, description, isolation, ownerRaw, attackerRaw, taskRaw, startIso, reqId }) {
  const clock = new Clock(startIso);
  const ctx = { protocolVersion: PROTOCOL_VERSION, transport: TRANSPORT };
  const evts = [];
  const taskHash = hmacHash(taskRaw);
  const ownerHash = hmacHash(ownerRaw);
  const attackerHash = hmacHash(attackerRaw);

  seedTaskState(evts, clock, taskHash, ctx);
  clock.advance(2000);
  const { methodResult, nameResult, overallResult } = requestTriplet(evts, clock, ctx, {
    reqId, method, headerMethod: method, headerNameHash: taskHash, bodyIdentityHash: taskHash
  });
  pushValidation(evts, clock, ctx, {
    reqId, method, headerMethod: method, headerNameHash: taskHash, bodyIdentityHash: taskHash,
    methodResult, nameResult, overallResult
  });
  // Routing is perfectly valid -- the ONLY problem is authorization. This is the exact
  // condition A10's docstring calls out: Track 1 alone is insufficient here.
  evts.push(envelope(clock.advance(4), 'mcp.task.authorization', 'iam', {
    ...ctx, fields: {
      'event.outcome': 'failure', 'principal.id_hash': attackerHash, 'principal.authenticated': true,
      'mcp.task.id_hash': taskHash, 'mcp.task.authz_context_id_hash': ownerHash,
      'mcp.task.operation': taskOperationFor(method), 'mcp.authz.decision': 'deny', 'mcp.authz.allowed': false,
      'mcp.authz.reason': 'principal_mismatch'
    }
  }));
  pushDeniedResponse(evts, clock, ctx, reqId);

  corpus.pushAll(file, evts);
  corpus.record({
    scenario_id: scenarioId, file, description, provenance: 'project_reference_harness',
    expected_security_outcome: 'malicious',
    expected_detection_track_1: false, expected_detection_track_2: true, expected_detection_track_3: false,
    expected_confidence: 'high',
    violated_invariant: 'Caller must be authorized for the referenced task/operation (docs/state-invariants.md row 4).',
    required_evidence: [
      'principal.id_hash', 'mcp.task.id_hash', 'mcp.task.authz_context_id_hash',
      'mcp.task.operation', 'mcp.authz.decision', 'mcp.authz.reason'
    ],
    cross_track_isolation: isolation, experimental: false,
    event_count: evts.length,
    notes: 'Header and body task identity match perfectly (Track 1 clean); the response error code (-32602) is wire-identical to an ordinary not-found error. The violation is provable ONLY from mcp.authz.decision/reason, per Block 1 SS10 -- this scenario exists specifically to prevent inferring Track 2 from the JSON-RPC error code alone.'
  });
}

function scenarioA7() {
  unauthorizedScenario({
    scenarioId: 'A7', file: 'track2/unauthorized_get.jsonl', method: 'tasks/get',
    description: 'Task-123 is authorized for Alice. Bob, a different authenticated principal, attempts tasks/get against it with perfectly matching routing.',
    isolation: 'track2_only',
    ownerRaw: 'principal:alice-a7', attackerRaw: 'principal:bob-a7', taskRaw: 'task-a7-0123',
    startIso: '2026-09-05T15:00:00.000Z', reqId: '701'
  });
}
function scenarioA8() {
  unauthorizedScenario({
    scenarioId: 'A8', file: 'track2/unauthorized_update.jsonl', method: 'tasks/update',
    description: 'Task-123 is authorized for Alice. Bob attempts tasks/update against it with perfectly matching routing.',
    isolation: 'track2_only',
    ownerRaw: 'principal:alice-a8', attackerRaw: 'principal:bob-a8', taskRaw: 'task-a8-0123',
    startIso: '2026-09-05T15:05:00.000Z', reqId: '801'
  });
}
function scenarioA9() {
  unauthorizedScenario({
    scenarioId: 'A9', file: 'track2/unauthorized_cancel.jsonl', method: 'tasks/cancel',
    description: 'Task-123 is authorized for Alice. Bob attempts tasks/cancel against it with perfectly matching routing.',
    isolation: 'track2_only',
    ownerRaw: 'principal:alice-a9', attackerRaw: 'principal:bob-a9', taskRaw: 'task-a9-0123',
    startIso: '2026-09-05T15:10:00.000Z', reqId: '901'
  });
}
function scenarioA10() {
  unauthorizedScenario({
    scenarioId: 'A10', file: 'track2/stolen_valid_handle.jsonl', method: 'tasks/get',
    description: 'Mallory, an external attacker, has obtained Task-123\'s real, correctly-formatted taskId (e.g. via leakage) and issues a syntactically perfect tasks/get for it. Every protocol field is valid; the only violation is authorization state. This is why Track 1 alone can never catch this class of abuse.',
    isolation: 'track2_only',
    ownerRaw: 'principal:alice-a10', attackerRaw: 'principal:mallory-a10', taskRaw: 'task-a10-0123',
    startIso: '2026-09-05T15:15:00.000Z', reqId: '1001'
  });
}

function scenarioA11() {
  // Reuse the Block 3 legitimate shared-access control rather than fabricating new semantics
  // -- the harness already represents this cleanly (Block 3 N6), so duplicating it here would
  // be "generic suspicious/positive traffic" for no reason. Point at it directly.
  corpus.record({
    scenario_id: 'A11',
    file: '../normal/authorized_shared_access.jsonl',
    description: 'Legitimate shared-access control: Task-123 is explicitly authorized for both Alice (owner) and Bob (explicit grant); Bob calls tasks/get. Reused directly from the Block 3 normal corpus (scenario N6) rather than duplicated here, since Block 3 already represents this cleanly and duplicating it would add no new evidence.',
    provenance: 'project_reference_harness',
    expected_security_outcome: 'benign',
    expected_detection_track_1: false, expected_detection_track_2: false, expected_detection_track_3: false,
    expected_confidence: 'not_applicable',
    violated_invariant: 'None -- both principals carry a distinct, legitimate mcp.authz.reason (authorized_owner / authorized_grant); this is the positive control Track 2 must not misfire on.',
    required_evidence: ['principal.id_hash (x2, distinct)', 'mcp.task.id_hash (same)', 'mcp.authz.decision=allow (both)', 'mcp.authz.reason (authorized_owner vs authorized_grant)'],
    cross_track_isolation: null, experimental: false,
    event_count: 9,
    notes: 'See data/normal/README.md scenario N6 for the full generation detail. Listed here so the Block 4 manifest and test suite can validate cross-block consistency directly.'
  });
}

// ===========================================================================
// TRACK 3 -- Long-Lived Subscription Authorization Drift (A12-A14) + controls (A15-A16)
// + optional experimental scenario
// ===========================================================================

function scenarioA12() {
  const file = 'track3/revocation_drift.jsonl';
  const clock = new Clock('2026-09-05T10:01:00.000Z'); // "10:01 subscriptions/listen opened"
  const principalHash = hmacHash('principal:alice-a12');
  const subId = '1201';
  const uriHash = hmacHash('resource:file:///a12/report.csv');
  const ctx = { protocolVersion: PROTOCOL_VERSION, transport: TRANSPORT };
  const evts = [];

  evts.push(envelope(clock.iso(), 'mcp.subscription.open', 'session', {
    ...ctx, fields: {
      'jsonrpc.request.id': subId, 'mcp.subscription.id': subId,
      'principal.id_hash': principalHash, 'principal.authenticated': true,
      'mcp.authz.grant_snapshot_hash': hmacHash('grant:alice-a12:v1'),
      'mcp.authz.grant_expiry': '2026-09-05T12:00:00.000Z', 'mcp.authz.valid_until': '2026-09-05T12:00:00.000Z',
      'mcp.subscription.filter_types': { resourcesListChanged: false, toolsListChanged: false }
    }
  }));
  clock.t = Date.parse('2026-09-05T10:02:00.000Z'); // "10:02 acknowledged / active"
  evts.push(envelope(clock.iso(), 'mcp.subscription.acknowledged', 'session', {
    ...ctx, fields: {
      'event.outcome': 'success', 'mcp.subscription.id': subId, 'principal.id_hash': principalHash,
      'mcp.subscription.state': 'acknowledged'
    }
  }));
  clock.t = Date.parse('2026-09-05T10:10:00.000Z'); // "10:10 authorization revoked / effective_at"
  evts.push(envelope(clock.iso(), 'mcp.subscription.authorization_change', 'iam', {
    ...ctx, fields: {
      'principal.id_hash': principalHash, 'mcp.authz.change.type': 'revoked',
      'mcp.authz.change.source': 'authorization_server_event',
      'mcp.authz.change.effective_at': clock.iso(), 'mcp.authz.change.detected_at': clock.iso(),
      'mcp.authz.change.timing_confidence': 'authoritative'
    }
  }));
  clock.t = Date.parse('2026-09-05T10:11:00.000Z'); // "10:11 notification delivered" -- THE VIOLATION
  evts.push(envelope(clock.iso(), 'mcp.subscription.notification', 'session', {
    ...ctx, fields: {
      'mcp.subscription.id': subId, 'principal.id_hash': principalHash, 'mcp.subscription.state': 'active',
      'mcp.subscription.notification_type': 'notifications/resources/updated',
      'mcp.subscription.notification.resource_uri_hash': uriHash
    }
  }));
  clock.t = Date.parse('2026-09-05T10:20:00.000Z'); // stream eventually drops, well after the violation
  evts.push(envelope(clock.iso(), 'mcp.subscription.close', 'session', {
    ...ctx, fields: {
      'event.outcome': 'success', 'mcp.subscription.id': subId, 'principal.id_hash': principalHash,
      'mcp.subscription.state': 'closed_abrupt', 'mcp.subscription.close.reason': 'transport_drop'
    }
  }));

  corpus.pushAll(file, evts);
  corpus.record({
    scenario_id: 'A12', file,
    description: 'Authorization is revoked (effective_at=10:10, authoritative) while a subscription opened at 10:01 remains active; a notification is delivered at 10:11, one minute after revocation, with no closure in between.',
    provenance: 'project_reference_harness',
    expected_security_outcome: 'malicious',
    expected_detection_track_1: false, expected_detection_track_2: false, expected_detection_track_3: true,
    expected_confidence: 'high',
    violated_invariant: 'Active subscription must remain consistent with current authorization state (docs/state-invariants.md row 10): a notification was delivered after the authoritative effective_at with no intervening close.',
    required_evidence: ['mcp.subscription.id', 'principal.id_hash', 'mcp.authz.change.effective_at', 'mcp.authz.change.timing_confidence=authoritative', 'mcp.subscription.notification (timestamp > effective_at)', 'absence of mcp.subscription.close before the notification'],
    cross_track_isolation: 'track3_only', experimental: false,
    event_count: evts.length,
    notes: 'Per Block 1 SS11, the notification\'s content is a change/activity signal (notifications/resources/updated carries only a URI), not assumed to be protected resource contents itself -- the violation is continued event visibility after authorization ceased to be valid, not a claim about payload content.'
  });
}

function scenarioA13() {
  const file = 'track3/token_expiry_drift.jsonl';
  const clock = new Clock('2026-09-05T09:00:00.000Z');
  const principalHash = hmacHash('principal:alice-a13');
  const subId = '1301';
  const uriHash = hmacHash('resource:file:///a13/notes.md');
  const ctx = { protocolVersion: PROTOCOL_VERSION, transport: TRANSPORT };
  const evts = [];
  const validUntil = '2026-09-05T09:30:00.000Z';

  evts.push(envelope(clock.iso(), 'mcp.subscription.open', 'session', {
    ...ctx, fields: {
      'jsonrpc.request.id': subId, 'mcp.subscription.id': subId,
      'principal.id_hash': principalHash, 'principal.authenticated': true,
      'mcp.authz.grant_snapshot_hash': hmacHash('grant:alice-a13:v1'),
      'mcp.authz.grant_expiry': validUntil, 'mcp.authz.valid_until': validUntil,
      'mcp.subscription.filter_types': { resourcesListChanged: false, toolsListChanged: false }
    }
  }));
  evts.push(envelope(clock.advance(50), 'mcp.subscription.acknowledged', 'session', {
    ...ctx, fields: { 'event.outcome': 'success', 'mcp.subscription.id': subId, 'principal.id_hash': principalHash, 'mcp.subscription.state': 'acknowledged' }
  }));
  // No explicit push revocation at all -- token simply expires silently at validUntil (09:30).
  clock.t = Date.parse('2026-09-05T09:45:00.000Z'); // T+15min past valid_until, no revocation event exists
  evts.push(envelope(clock.iso(), 'mcp.subscription.notification', 'session', {
    ...ctx, fields: {
      'mcp.subscription.id': subId, 'principal.id_hash': principalHash, 'mcp.subscription.state': 'active',
      'mcp.subscription.notification_type': 'notifications/resources/updated',
      'mcp.subscription.notification.resource_uri_hash': uriHash
    }
  }));
  clock.t = Date.parse('2026-09-05T09:50:00.000Z');
  evts.push(envelope(clock.iso(), 'mcp.subscription.close', 'session', {
    ...ctx, fields: { 'event.outcome': 'success', 'mcp.subscription.id': subId, 'principal.id_hash': principalHash, 'mcp.subscription.state': 'closed_abrupt', 'mcp.subscription.close.reason': 'transport_drop' }
  }));

  corpus.pushAll(file, evts);
  corpus.record({
    scenario_id: 'A13', file,
    description: 'Subscription opened with mcp.authz.valid_until=09:30. No push revocation ever occurs. A notification is delivered at 09:45, 15 minutes past the known expiry, with the stream still active.',
    provenance: 'project_reference_harness',
    expected_security_outcome: 'malicious',
    expected_detection_track_1: false, expected_detection_track_2: false, expected_detection_track_3: true,
    expected_confidence: 'high',
    violated_invariant: 'Active subscription must remain consistent with current authorization state (row 10); revocation propagation delay is bounded and expected only up to a documented grace period (row 11) -- 15 minutes past a known, computable expiry with no push feed at all exceeds any reasonable such bound.',
    required_evidence: ['mcp.authz.valid_until', 'mcp.subscription.notification (timestamp > valid_until)', 'absence of mcp.subscription.authorization_change (silent expiry -- proves detection must not depend on a push feed)', 'absence of a close before the notification'],
    cross_track_isolation: 'track3_only', experimental: false,
    event_count: evts.length,
    notes: 'Demonstrates Track 3 detection must work from mcp.authz.valid_until alone when no authorization_change event exists at all -- most real OAuth deployments have no push-based revocation feed (telemetry/schema.md SS5 "fields that cannot realistically be collected").'
  });
}

function scenarioA14() {
  const file = 'track3/delayed_revocation_observation.jsonl';
  const clock = new Clock('2026-09-05T10:00:00.000Z');
  const principalHash = hmacHash('principal:alice-a14');
  const subId = '1401';
  const uriHash = hmacHash('resource:file:///a14/report.csv');
  const ctx = { protocolVersion: PROTOCOL_VERSION, transport: TRANSPORT };
  const evts = [];

  evts.push(envelope(clock.iso(), 'mcp.subscription.open', 'session', {
    ...ctx, fields: {
      'jsonrpc.request.id': subId, 'mcp.subscription.id': subId,
      'principal.id_hash': principalHash, 'principal.authenticated': true,
      'mcp.authz.grant_snapshot_hash': hmacHash('grant:alice-a14:v1'),
      'mcp.authz.grant_expiry': '2026-09-05T11:00:00.000Z', 'mcp.authz.valid_until': '2026-09-05T11:00:00.000Z',
      'mcp.subscription.filter_types': { resourcesListChanged: false, toolsListChanged: false }
    }
  }));
  evts.push(envelope(clock.advance(50), 'mcp.subscription.acknowledged', 'session', {
    ...ctx, fields: { 'event.outcome': 'success', 'mcp.subscription.id': subId, 'principal.id_hash': principalHash, 'mcp.subscription.state': 'acknowledged' }
  }));
  // Notification at 10:12 arrives in the raw event stream BEFORE the authorization_change
  // event is even recorded (that only happens once detected_at=10:14 arrives) -- but the
  // change event's own effective_at (10:10) retroactively proves 10:12 was already a violation.
  clock.t = Date.parse('2026-09-05T10:12:00.000Z');
  evts.push(envelope(clock.iso(), 'mcp.subscription.notification', 'session', {
    ...ctx, fields: {
      'mcp.subscription.id': subId, 'principal.id_hash': principalHash, 'mcp.subscription.state': 'active',
      'mcp.subscription.notification_type': 'notifications/resources/updated',
      'mcp.subscription.notification.resource_uri_hash': uriHash
    }
  }));
  clock.t = Date.parse('2026-09-05T10:14:00.000Z');
  evts.push(envelope(clock.iso(), 'mcp.subscription.authorization_change', 'iam', {
    ...ctx, fields: {
      'principal.id_hash': principalHash, 'mcp.authz.change.type': 'revoked',
      'mcp.authz.change.source': 'authorization_server_event',
      'mcp.authz.change.effective_at': '2026-09-05T10:10:00.000Z',
      'mcp.authz.change.detected_at': '2026-09-05T10:14:00.000Z',
      'mcp.authz.change.timing_confidence': 'authoritative'
    }
  }));
  clock.t = Date.parse('2026-09-05T10:20:00.000Z');
  evts.push(envelope(clock.iso(), 'mcp.subscription.close', 'session', {
    ...ctx, fields: { 'event.outcome': 'success', 'mcp.subscription.id': subId, 'principal.id_hash': principalHash, 'mcp.subscription.state': 'closed_abrupt', 'mcp.subscription.close.reason': 'transport_drop' }
  }));

  corpus.pushAll(file, evts);
  corpus.record({
    scenario_id: 'A14', file,
    description: 'effective_at=10:10, detected_at=10:14, notification=10:12. The notification arrives (and is logged) BEFORE the authorization_change event is even recorded, but the change event\'s authoritative effective_at retroactively proves the notification was already a violation.',
    provenance: 'project_reference_harness',
    expected_security_outcome: 'malicious',
    expected_detection_track_1: false, expected_detection_track_2: false, expected_detection_track_3: true,
    expected_confidence: 'high',
    violated_invariant: 'Row 10, using the authoritative effective_at per row 11\'s preference order (telemetry/correlation.md): notification (10:12) > effective_at (10:10), regardless of when detected_at (10:14) arrived.',
    required_evidence: ['mcp.authz.change.effective_at=10:10', 'mcp.authz.change.timing_confidence=authoritative', 'mcp.subscription.notification.timestamp=10:12', 'mcp.authz.change.detected_at=10:14 (shown to demonstrate a detected_at-only check would have WRONGLY missed this, since 10:12 < 10:14)'],
    cross_track_isolation: 'track3_only', experimental: false,
    event_count: evts.length,
    notes: 'This is the exact scenario Block 2 separated effective_at from detected_at to handle correctly (telemetry/schema.md patch history). Compare directly with A15, which has the same notification/detected_at shape but NO authoritative effective_at at all.'
  });
}

function scenarioA15() {
  const file = 'controls/detected_only_timing.jsonl';
  const clock = new Clock('2026-09-05T10:00:00.000Z');
  const principalHash = hmacHash('principal:alice-a15');
  const subId = '1501';
  const uriHash = hmacHash('resource:file:///a15/report.csv');
  const ctx = { protocolVersion: PROTOCOL_VERSION, transport: TRANSPORT };
  const evts = [];

  evts.push(envelope(clock.iso(), 'mcp.subscription.open', 'session', {
    ...ctx, fields: {
      'jsonrpc.request.id': subId, 'mcp.subscription.id': subId,
      'principal.id_hash': principalHash, 'principal.authenticated': true,
      'mcp.authz.grant_snapshot_hash': hmacHash('grant:alice-a15:v1'),
      'mcp.authz.grant_expiry': '2026-09-05T11:00:00.000Z', 'mcp.authz.valid_until': '2026-09-05T11:00:00.000Z',
      'mcp.subscription.filter_types': { resourcesListChanged: false, toolsListChanged: false }
    }
  }));
  evts.push(envelope(clock.advance(50), 'mcp.subscription.acknowledged', 'session', {
    ...ctx, fields: { 'event.outcome': 'success', 'mcp.subscription.id': subId, 'principal.id_hash': principalHash, 'mcp.subscription.state': 'acknowledged' }
  }));
  clock.t = Date.parse('2026-09-05T10:12:00.000Z'); // notification -- BEFORE detected_at, no effective_at exists anywhere
  evts.push(envelope(clock.iso(), 'mcp.subscription.notification', 'session', {
    ...ctx, fields: {
      'mcp.subscription.id': subId, 'principal.id_hash': principalHash, 'mcp.subscription.state': 'active',
      'mcp.subscription.notification_type': 'notifications/resources/updated',
      'mcp.subscription.notification.resource_uri_hash': uriHash
    }
  }));
  clock.t = Date.parse('2026-09-05T10:14:00.000Z');
  evts.push(envelope(clock.iso(), 'mcp.subscription.authorization_change', 'iam', {
    ...ctx, fields: {
      'principal.id_hash': principalHash, 'mcp.authz.change.type': 'revoked',
      'mcp.authz.change.source': 'policy_engine',
      'mcp.authz.change.detected_at': '2026-09-05T10:14:00.000Z',
      'mcp.authz.change.timing_confidence': 'detected_only'
      // deliberately no mcp.authz.change.effective_at -- none is trustworthy/available
    }
  }));
  clock.t = Date.parse('2026-09-05T10:25:00.000Z');
  evts.push(envelope(clock.iso(), 'mcp.subscription.close', 'session', {
    ...ctx, fields: { 'event.outcome': 'success', 'mcp.subscription.id': subId, 'principal.id_hash': principalHash, 'mcp.subscription.state': 'closed_graceful', 'mcp.subscription.close.reason': 'client_closed' }
  }));

  corpus.pushAll(file, evts);
  corpus.record({
    scenario_id: 'A15', file,
    description: 'No trustworthy effective_at is available (timing_confidence=detected_only). detected_at=10:14, notification=10:12. The notification precedes detected_at, so a naive observer might suspect drift, but the true revocation moment is unknown and could be anywhere before 10:14.',
    provenance: 'project_reference_harness',
    expected_security_outcome: 'ambiguous_insufficient_confidence',
    expected_detection_track_1: false, expected_detection_track_2: false, expected_detection_track_3: false,
    expected_confidence: 'low',
    violated_invariant: 'None confirmed. Per docs/state-invariants.md row 11 and telemetry/correlation.md\'s Track 3 preference order, with no authoritative effective_at the only usable boundary is detected_at; since the notification (10:12) is BEFORE detected_at (10:14), the correlation boundary check does not trigger. This is a deliberate negative/ambiguous fixture, not a confirmed violation.',
    required_evidence: ['mcp.authz.change.timing_confidence=detected_only', 'mcp.authz.change.detected_at', 'mcp.subscription.notification.timestamp (which precedes detected_at)', 'absence of mcp.authz.change.effective_at'],
    cross_track_isolation: null, experimental: false,
    event_count: evts.length,
    notes: 'Directly comparable to A14: identical notification/detected_at shape, but A14 additionally has an authoritative effective_at that A15 lacks -- that is the ONLY difference, and it is what flips the correct verdict from true (A14) to false/indeterminate (A15).'
  });
}

function scenarioA16() {
  const file = 'controls/correct_stream_termination.jsonl';
  const clock = new Clock('2026-09-05T13:00:00.000Z');
  const principalHash = hmacHash('principal:alice-a16');
  const subId = '1601';
  const uriHash = hmacHash('resource:file:///a16/report.csv');
  const ctx = { protocolVersion: PROTOCOL_VERSION, transport: TRANSPORT };
  const evts = [];

  evts.push(envelope(clock.iso(), 'mcp.subscription.open', 'session', {
    ...ctx, fields: {
      'jsonrpc.request.id': subId, 'mcp.subscription.id': subId,
      'principal.id_hash': principalHash, 'principal.authenticated': true,
      'mcp.authz.grant_snapshot_hash': hmacHash('grant:alice-a16:v1'),
      'mcp.authz.grant_expiry': '2026-09-05T14:00:00.000Z', 'mcp.authz.valid_until': '2026-09-05T14:00:00.000Z',
      'mcp.subscription.filter_types': { resourcesListChanged: false, toolsListChanged: false }
    }
  }));
  evts.push(envelope(clock.advance(50), 'mcp.subscription.acknowledged', 'session', {
    ...ctx, fields: { 'event.outcome': 'success', 'mcp.subscription.id': subId, 'principal.id_hash': principalHash, 'mcp.subscription.state': 'acknowledged' }
  }));
  clock.t = Date.parse('2026-09-05T13:05:00.000Z'); // before revocation: fine
  evts.push(envelope(clock.iso(), 'mcp.subscription.notification', 'session', {
    ...ctx, fields: {
      'mcp.subscription.id': subId, 'principal.id_hash': principalHash, 'mcp.subscription.state': 'active',
      'mcp.subscription.notification_type': 'notifications/resources/updated',
      'mcp.subscription.notification.resource_uri_hash': uriHash
    }
  }));
  clock.t = Date.parse('2026-09-05T13:10:00.000Z');
  const revokedAt = clock.iso();
  evts.push(envelope(revokedAt, 'mcp.subscription.authorization_change', 'iam', {
    ...ctx, fields: {
      'principal.id_hash': principalHash, 'mcp.authz.change.type': 'revoked',
      'mcp.authz.change.source': 'authorization_server_event',
      'mcp.authz.change.effective_at': revokedAt, 'mcp.authz.change.detected_at': revokedAt,
      'mcp.authz.change.timing_confidence': 'authoritative'
    }
  }));
  evts.push(envelope(clock.advance(500), 'mcp.subscription.close', 'session', {
    ...ctx, fields: {
      'event.outcome': 'success', 'mcp.subscription.id': subId, 'principal.id_hash': principalHash,
      'mcp.subscription.state': 'closed_graceful', 'mcp.subscription.close.reason': 'server_forced_authz'
    }
  }));
  // No further notification after the close.

  corpus.pushAll(file, evts);
  corpus.record({
    scenario_id: 'A16', file,
    description: 'Authorization is revoked at 13:10; the application closes the stream (server_forced_authz) 500ms later, with no further notification emitted afterward.',
    provenance: 'project_reference_harness',
    expected_security_outcome: 'benign',
    expected_detection_track_1: false, expected_detection_track_2: false, expected_detection_track_3: false,
    expected_confidence: 'not_applicable',
    violated_invariant: 'None -- row 10 is preserved: no notification exists after effective_at because the stream was closed first. This is an attack-adjacent CONTROL case: same revocation shape as A12/A14, opposite (correct) application response.',
    required_evidence: ['mcp.authz.change.effective_at', 'mcp.subscription.close.timestamp <= any candidate post-revocation notification (there are none)', 'mcp.subscription.close.reason=server_forced_authz'],
    cross_track_isolation: null, experimental: false,
    event_count: evts.length,
    notes: 'Kept in the Block 4 corpus (not Block 3) specifically for direct, same-timeline-shape comparison against A12/A14 -- the only difference is the presence and promptness of the close.'
  });
}

function scenarioAExp1() {
  // OPTIONAL experimental scenario. Explicitly labeled; not required for Track 3 (which
  // already has A12-A14 as its true-positive proof). Not presented as SDK-verified behavior --
  // see docs/sdk-discrepancy.md: no current official SDK (v1 or v2) implements a live
  // notifications/tasks runtime.
  const file = 'track3/experimental_task_notification_inline_result.jsonl';
  const clock = new Clock('2026-09-05T16:00:00.000Z');
  const principalHash = hmacHash('principal:alice-aexp1');
  const subId = '1701';
  const taskHash = hmacHash('task-aexp1-0001');
  const ctx = { protocolVersion: PROTOCOL_VERSION, transport: TRANSPORT };
  const evts = [];

  evts.push(envelope(clock.iso(), 'mcp.subscription.open', 'session', {
    ...ctx, fields: {
      'jsonrpc.request.id': subId, 'mcp.subscription.id': subId,
      'principal.id_hash': principalHash, 'principal.authenticated': true,
      'mcp.authz.grant_snapshot_hash': hmacHash('grant:alice-aexp1:v1'),
      'mcp.authz.valid_until': '2026-09-05T17:00:00.000Z'
    }
  }));
  evts.push(envelope(clock.advance(50), 'mcp.subscription.acknowledged', 'session', {
    ...ctx, fields: { 'event.outcome': 'success', 'mcp.subscription.id': subId, 'principal.id_hash': principalHash, 'mcp.subscription.state': 'acknowledged' }
  }));
  clock.t = Date.parse('2026-09-05T16:10:00.000Z');
  const revokedAt = clock.iso();
  evts.push(envelope(revokedAt, 'mcp.subscription.authorization_change', 'iam', {
    ...ctx, fields: {
      'principal.id_hash': principalHash, 'mcp.authz.change.type': 'revoked',
      'mcp.authz.change.source': 'authorization_server_event',
      'mcp.authz.change.effective_at': revokedAt, 'mcp.authz.change.detected_at': revokedAt,
      'mcp.authz.change.timing_confidence': 'authoritative'
    }
  }));
  clock.t = Date.parse('2026-09-05T16:11:00.000Z');
  evts.push(envelope(clock.iso(), 'mcp.subscription.notification', 'session', {
    ...ctx, fields: {
      'mcp.subscription.id': subId, 'principal.id_hash': principalHash, 'mcp.subscription.state': 'active',
      'mcp.subscription.notification_type': 'notifications/tasks',
      'mcp.subscription.notification.contains_inline_result': true
    }
  }));
  evts.push(envelope(clock.advance(500), 'mcp.subscription.close', 'session', {
    ...ctx, fields: { 'event.outcome': 'success', 'mcp.subscription.id': subId, 'principal.id_hash': principalHash, 'mcp.subscription.state': 'closed_abrupt', 'mcp.subscription.close.reason': 'transport_drop' }
  }));

  corpus.pushAll(file, evts);
  corpus.record({
    scenario_id: 'A-EXP1', file,
    description: 'EXPERIMENTAL: a notifications/tasks notification carrying an inlined terminal task result is delivered after authoritative revocation.',
    provenance: 'project_reference_harness',
    expected_security_outcome: 'malicious_experimental',
    expected_detection_track_1: false, expected_detection_track_2: false, expected_detection_track_3: true,
    expected_confidence: 'high',
    violated_invariant: 'Same row-10 drift condition as A12, PLUS the separately-flagged, experimentally-unvalidated hypothesis from docs/threat-model.md SS11/SS17 (row 11a) that notifications/tasks can inline actual result content rather than mere change metadata.',
    required_evidence: ['mcp.subscription.notification_type=notifications/tasks', 'mcp.subscription.notification.contains_inline_result=true', 'mcp.authz.change.effective_at', 'notification.timestamp > effective_at'],
    cross_track_isolation: null, experimental: true,
    event_count: evts.length,
    notes: 'This is generated ONLY by the project reference harness. Per docs/sdk-discrepancy.md, no current official SDK (v1 or v2) implements a live notifications/tasks runtime -- v2\'s task-status notification type is explicitly marked "@deprecated ... no SDK runtime" in its own shipped source, and does not even use SEP-2663\'s current method name. Do not treat this scenario as evidence of established real-world SDK behavior. Not required for Track 3, which already has A12-A14 as non-experimental true positives.'
  });
}

// ===========================================================================
// COMBINED scenario -- proves the two tracks are independent/additive, not exclusive
// ===========================================================================

function scenarioA17Combined() {
  const file = 'combined/mismatch_and_unauthorized.jsonl';
  const clock = new Clock('2026-09-05T17:00:00.000Z');
  const ctx = { protocolVersion: PROTOCOL_VERSION, transport: TRANSPORT };
  const evts = [];
  const attackerHash = hmacHash('principal:mallory-a17');
  const ownerHash = hmacHash('principal:alice-a17');
  const taskXHash = hmacHash('task-a17-TaskX');
  const taskYHash = hmacHash('task-a17-TaskY');

  seedTaskState(evts, clock, taskXHash, ctx);
  clock.advance(10); seedTaskState(evts, clock, taskYHash, ctx);

  // Step 1: routing-mismatched attempt against Task-X (rejected -- Track 1 evidence).
  clock.advance(1000);
  const reqId1 = '1701';
  {
    const method = 'tasks/get';
    const { methodResult, nameResult, overallResult } = requestTriplet(evts, clock, ctx, {
      reqId: reqId1, method, headerMethod: method, headerNameHash: taskXHash, bodyIdentityHash: taskYHash
    });
    pushValidation(evts, clock, ctx, {
      reqId: reqId1, method, headerMethod: method, headerNameHash: taskXHash, bodyIdentityHash: taskYHash,
      methodResult, nameResult, overallResult,
      reason: 'Mcp-Name identifies Task-X but params.taskId identifies Task-Y -- same attacker\'s first, unsuccessful probing attempt.'
    });
    pushHeaderMismatchResponse(evts, clock, ctx, reqId1);
  }

  // Step 2: properly-routed follow-up attempt against Task-Y, which the attacker does not own
  // (denied -- Track 2 evidence). Same attacker principal, same session narrative.
  clock.advance(5000);
  const reqId2 = '1702';
  {
    const method = 'tasks/get';
    const { methodResult, nameResult, overallResult } = requestTriplet(evts, clock, ctx, {
      reqId: reqId2, method, headerMethod: method, headerNameHash: taskYHash, bodyIdentityHash: taskYHash
    });
    pushValidation(evts, clock, ctx, {
      reqId: reqId2, method, headerMethod: method, headerNameHash: taskYHash, bodyIdentityHash: taskYHash,
      methodResult, nameResult, overallResult
    });
    evts.push(envelope(clock.advance(4), 'mcp.task.authorization', 'iam', {
      ...ctx, fields: {
        'event.outcome': 'failure', 'principal.id_hash': attackerHash, 'principal.authenticated': true,
        'mcp.task.id_hash': taskYHash, 'mcp.task.authz_context_id_hash': ownerHash,
        'mcp.task.operation': 'get', 'mcp.authz.decision': 'deny', 'mcp.authz.allowed': false,
        'mcp.authz.reason': 'principal_mismatch'
      }
    }));
    pushDeniedResponse(evts, clock, ctx, reqId2);
  }

  corpus.pushAll(file, evts);
  corpus.record({
    scenario_id: 'A17', file,
    description: 'Combined scenario: the same attacker (Mallory) first attempts a routing-mismatched tasks/get (Task-X header vs Task-Y body, rejected), then a properly-routed tasks/get against Task-Y, which she does not own (denied). Proves Track 1 and Track 2 fire independently within one attacker session rather than being mutually exclusive.',
    provenance: 'project_reference_harness',
    expected_security_outcome: 'malicious',
    expected_detection_track_1: true, expected_detection_track_2: true, expected_detection_track_3: false,
    expected_confidence: 'high',
    violated_invariant: 'Both docs/state-invariants.md row 2 (routing identity) and row 4 (task authorization), on two separate requests within the same fixture.',
    required_evidence: [
      'request 1701: mcp.validation.name.result=conflict (Track 1)',
      'request 1702: mcp.authz.decision=deny, mcp.authz.reason=principal_mismatch (Track 2)'
    ],
    cross_track_isolation: 'combined', experimental: false,
    event_count: evts.length,
    notes: 'Not a single event triggering two tracks at once -- per Block 1/2, a HeaderMismatch-rejected request never reaches authorization, so the two findings necessarily come from two distinct requests. This scenario demonstrates additive detection across a session, not simultaneous triggering within one message.'
  });
}

// ===========================================================================
// Run all scenarios
// ===========================================================================
scenarioA1(); scenarioA2(); scenarioA3(); scenarioA4(); scenarioA5(); scenarioA6();
scenarioA7(); scenarioA8(); scenarioA9(); scenarioA10(); scenarioA11();
scenarioA12(); scenarioA13(); scenarioA14(); scenarioA15(); scenarioA16(); scenarioAExp1();
scenarioA17Combined();

corpus.writeOut();

const totalEvents = [...corpus.files.values()].reduce((n, evts) => n + evts.length, 0);
console.log(`Wrote ${corpus.files.size} JSONL files + manifest.jsonl (${corpus.manifest.length} scenarios, ${totalEvents} total events) to ${DATA_DIR}`);
