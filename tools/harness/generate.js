'use strict';
/**
 * Block 3 normal-corpus generator.
 *
 * This is a project-built, spec-conformant reference harness -- NOT an official MCP SDK.
 * See docs/sdk-discrepancy.md for the full, verified picture: the official TypeScript SDK's
 * stable v2 line (@modelcontextprotocol/client + @modelcontextprotocol/server, 2.0.0) DOES
 * implement 2026-07-28 core -- including Mcp-Method/Mcp-Name header validation and
 * subscriptions/listen -- but the SEP-2663 Tasks extension is not part of what v2 implements
 * yet (its task types are still the pre-SEP-2663 2025-11-25 shape, and its task-status
 * notification type is explicitly marked "@deprecated ... no SDK runtime" in the shipped
 * source). Since 11 of 13 scenarios here are task-centric, this harness is used for all of
 * them for consistency and determinism -- see docs/sdk-discrepancy.md for why the one
 * non-task scenario (N8) was not split out to real v2-SDK capture.
 * Every event shape below is built directly from the primary-source wire mechanics cited in
 * docs/threat-model.md and telemetry/schema.md.
 *
 * Every event is produced by real code paths (protocol.js's validation functions actually
 * compute results from raw inputs; state transitions are tracked, not hand-typed per event)
 * so this is "harness-generated," not "hand-labeled fixtures dressed up as telemetry."
 *
 * Determinism: a fixed logical clock and fixed identifiers are used throughout -- no
 * wall-clock time, no Math.random() -- so re-running this script byte-for-byte reproduces
 * the corpus.
 */
const fs = require('fs');
const path = require('path');
const { hmacHash, HASH_KEY_ID, HASH_ALGORITHM } = require('./lib/hash');
const { validateField, validateName, rollup, taskOperationFor } = require('./lib/protocol');

const DATA_DIR = path.join(__dirname, '..', '..', 'data', 'normal');
const PROTOCOL_VERSION = '2026-07-28';
const TRANSPORT = 'streamable-http';

// ---------------------------------------------------------------------------
// Deterministic logical clock (ms since a fixed epoch). No wall-clock reads.
// ---------------------------------------------------------------------------
class Clock {
  constructor(startIso) { this.t = Date.parse(startIso); }
  iso() { return new Date(this.t).toISOString(); }
  advance(ms) { this.t += ms; return this.iso(); }
}

// ---------------------------------------------------------------------------
// Event helpers
// ---------------------------------------------------------------------------
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
    ...(extra.traceId ? { trace_id: extra.traceId } : {}),
    ...(extra.spanId ? { span_id: extra.spanId } : {}),
    ...extra.fields
  });
}

// ---------------------------------------------------------------------------
// A "corpus" collects events per output file and manifest rows for ground truth.
// ---------------------------------------------------------------------------
class Corpus {
  constructor() {
    this.files = new Map(); // filename -> [events]
    this.manifest = [];
  }
  push(filename, evt) {
    if (!this.files.has(filename)) this.files.set(filename, []);
    this.files.get(filename).push(evt);
  }
  pushAll(filename, evts) { evts.forEach((e) => this.push(filename, e)); }
  record(manifestRow) { this.manifest.push(manifestRow); }
  writeOut() {
    fs.mkdirSync(DATA_DIR, { recursive: true });
    for (const [filename, evts] of this.files) {
      const body = evts.map((e) => JSON.stringify(e)).join('\n') + '\n';
      fs.writeFileSync(path.join(DATA_DIR, filename), body, 'utf8');
    }
    const manifestBody = this.manifest.map((r) => JSON.stringify(r)).join('\n') + '\n';
    fs.writeFileSync(path.join(DATA_DIR, 'manifest.jsonl'), manifestBody, 'utf8');
  }
  count(filename) { return (this.files.get(filename) || []).length; }
}

const corpus = new Corpus();

// A tiny in-memory task/subscription registry so state transitions are tracked, not
// hand-typed independently per event (real state-machine behavior, not label copy-paste).
function makeTaskTracker() {
  const state = new Map(); // taskId -> current status
  return {
    seed(taskId, status) { state.set(taskId, null); return this.transition(taskId, status); },
    transition(taskId, next) {
      const prev = state.has(taskId) ? state.get(taskId) : null;
      state.set(taskId, next);
      return prev;
    }
  };
}

// ===========================================================================
// N1 -- Normal tasks/get
// ===========================================================================
function scenarioN1() {
  const file = 'tasks_get.jsonl';
  const clock = new Clock('2026-09-01T09:00:00.000Z');
  const taskRaw = 'task-n1-0001';
  const taskHash = hmacHash(taskRaw);
  const principalHash = hmacHash('principal:alice-n1');
  const tracker = makeTaskTracker();

  const ctx = { protocolVersion: PROTOCOL_VERSION, transport: TRANSPORT };
  const evts = [];

  // Task already exists in 'working' state (created by an earlier, unlogged tools/call in
  // this fixture's narrative -- the seed transition itself is recorded as the first event).
  const prev0 = tracker.seed(taskRaw, 'working');
  evts.push(envelope(clock.iso(), 'mcp.task.state', 'process', {
    ...ctx, fields: { 'mcp.task.id_hash': taskHash, 'mcp.task.state': 'working', 'mcp.task.previous_state': prev0 }
  }));

  clock.advance(500);
  const reqId = '101';
  const method = 'tasks/get';
  evts.push(envelope(clock.iso(), 'mcp.request.received', 'network', {
    ...ctx,
    traceId: '4bf92f3577b34da6a3ce929d0e0e4736',
    fields: {
      'rpc.system.name': 'jsonrpc', 'rpc.method': method, 'mcp.body.method': method,
      'jsonrpc.request.id': reqId,
      'mcp.header.method': method,
      'mcp.header.name_hash': taskHash, 'mcp.body.identity_hash': taskHash,
      'http.request.method': 'POST'
    }
  }));

  const methodResult = validateField(PROTOCOL_VERSION, { present: true, value: method }, method);
  const nameResult = validateName(PROTOCOL_VERSION, { present: true, value: taskHash }, taskHash, method);
  evts.push(envelope(clock.advance(4), 'mcp.request.validation', 'network', {
    ...ctx,
    fields: {
      'event.outcome': 'success', 'jsonrpc.request.id': reqId,
      'mcp.body.method': method, 'mcp.header.method': method,
      'mcp.header.name_hash': taskHash, 'mcp.body.identity_hash': taskHash,
      'mcp.validation.method.result': methodResult, 'mcp.validation.name.result': nameResult,
      'mcp.validation.result': rollup(methodResult, nameResult),
      'mcp.validation.source': 'server_native'
    }
  }));

  evts.push(envelope(clock.advance(6), 'mcp.task.authorization', 'iam', {
    ...ctx,
    fields: {
      'event.outcome': 'success',
      'principal.id_hash': principalHash, 'principal.authenticated': true, 'principal.auth_method': 'oauth2_bearer',
      'mcp.task.id_hash': taskHash, 'mcp.task.authz_context_id_hash': principalHash,
      'mcp.task.operation': taskOperationFor(method),
      'mcp.authz.decision': 'allow', 'mcp.authz.allowed': true, 'mcp.authz.reason': 'authorized_owner'
    }
  }));

  evts.push(envelope(clock.advance(10), 'mcp.response', 'network', {
    ...ctx, fields: { 'event.outcome': 'success', 'jsonrpc.request.id': reqId, 'http.response.status_code': 200 }
  }));

  corpus.pushAll(file, evts);
  corpus.record({
    scenario_id: 'N1', file, provenance: 'project_reference_harness',
    expected_security_outcome: 'benign',
    expected_detection_track_1: false, expected_detection_track_2: false, expected_detection_track_3: false,
    event_count: evts.length,
    notes: 'Single authorized tasks/get poll against an already-working task; header/body identity match throughout.'
  });
}

// ===========================================================================
// N2 -- Normal tasks/update
// ===========================================================================
function scenarioN2() {
  const file = 'tasks_update.jsonl';
  const clock = new Clock('2026-09-01T09:05:00.000Z');
  const taskRaw = 'task-n2-0001';
  const taskHash = hmacHash(taskRaw);
  const principalHash = hmacHash('principal:alice-n2');
  const tracker = makeTaskTracker();
  const ctx = { protocolVersion: PROTOCOL_VERSION, transport: TRANSPORT };
  const evts = [];

  let prev = tracker.seed(taskRaw, 'working');
  evts.push(envelope(clock.iso(), 'mcp.task.state', 'process', {
    ...ctx, fields: { 'mcp.task.id_hash': taskHash, 'mcp.task.state': 'working', 'mcp.task.previous_state': prev }
  }));

  prev = tracker.transition(taskRaw, 'input_required');
  evts.push(envelope(clock.advance(2000), 'mcp.task.state', 'process', {
    ...ctx, fields: { 'mcp.task.id_hash': taskHash, 'mcp.task.state': 'input_required', 'mcp.task.previous_state': prev }
  }));

  const reqId = '202';
  const method = 'tasks/update';
  clock.advance(1500);
  evts.push(envelope(clock.iso(), 'mcp.request.received', 'network', {
    ...ctx, fields: {
      'rpc.system.name': 'jsonrpc', 'rpc.method': method, 'mcp.body.method': method,
      'jsonrpc.request.id': reqId, 'mcp.header.method': method,
      'mcp.header.name_hash': taskHash, 'mcp.body.identity_hash': taskHash, 'http.request.method': 'POST'
    }
  }));
  const methodResult = validateField(PROTOCOL_VERSION, { present: true, value: method }, method);
  const nameResult = validateName(PROTOCOL_VERSION, { present: true, value: taskHash }, taskHash, method);
  evts.push(envelope(clock.advance(3), 'mcp.request.validation', 'network', {
    ...ctx, fields: {
      'event.outcome': 'success', 'jsonrpc.request.id': reqId, 'mcp.body.method': method, 'mcp.header.method': method,
      'mcp.header.name_hash': taskHash, 'mcp.body.identity_hash': taskHash,
      'mcp.validation.method.result': methodResult, 'mcp.validation.name.result': nameResult,
      'mcp.validation.result': rollup(methodResult, nameResult), 'mcp.validation.source': 'server_native'
    }
  }));
  evts.push(envelope(clock.advance(5), 'mcp.task.authorization', 'iam', {
    ...ctx, fields: {
      'event.outcome': 'success', 'principal.id_hash': principalHash, 'principal.authenticated': true,
      'mcp.task.id_hash': taskHash, 'mcp.task.authz_context_id_hash': principalHash,
      'mcp.task.operation': taskOperationFor(method),
      'mcp.authz.decision': 'allow', 'mcp.authz.allowed': true, 'mcp.authz.reason': 'authorized_owner'
    }
  }));

  // Per SEP-2663, tasks/update's ack is eventually consistent with observable status --
  // the state transition is recorded slightly after the ack, which is normal, not drift.
  evts.push(envelope(clock.advance(8), 'mcp.response', 'network', {
    ...ctx, fields: { 'event.outcome': 'success', 'jsonrpc.request.id': reqId, 'http.response.status_code': 200 }
  }));
  prev = tracker.transition(taskRaw, 'working');
  evts.push(envelope(clock.advance(40), 'mcp.task.state', 'process', {
    ...ctx, fields: { 'mcp.task.id_hash': taskHash, 'mcp.task.state': 'working', 'mcp.task.previous_state': prev }
  }));

  corpus.pushAll(file, evts);
  corpus.record({
    scenario_id: 'N2', file, provenance: 'project_reference_harness',
    expected_security_outcome: 'benign',
    expected_detection_track_1: false, expected_detection_track_2: false, expected_detection_track_3: false,
    event_count: evts.length,
    notes: 'Owner supplies tasks/update while task is input_required; task returns to working. Ack precedes observable state change (spec-permitted eventual consistency), not a violation.'
  });
}

// ===========================================================================
// N3 -- Normal tasks/cancel
// ===========================================================================
function scenarioN3() {
  const file = 'tasks_cancel.jsonl';
  const clock = new Clock('2026-09-01T09:10:00.000Z');
  const taskRaw = 'task-n3-0001';
  const taskHash = hmacHash(taskRaw);
  const principalHash = hmacHash('principal:alice-n3');
  const tracker = makeTaskTracker();
  const ctx = { protocolVersion: PROTOCOL_VERSION, transport: TRANSPORT };
  const evts = [];

  let prev = tracker.seed(taskRaw, 'working');
  evts.push(envelope(clock.iso(), 'mcp.task.state', 'process', {
    ...ctx, fields: { 'mcp.task.id_hash': taskHash, 'mcp.task.state': 'working', 'mcp.task.previous_state': prev }
  }));

  const reqId = '303';
  const method = 'tasks/cancel';
  clock.advance(5000);
  evts.push(envelope(clock.iso(), 'mcp.request.received', 'network', {
    ...ctx, fields: {
      'rpc.system.name': 'jsonrpc', 'rpc.method': method, 'mcp.body.method': method,
      'jsonrpc.request.id': reqId, 'mcp.header.method': method,
      'mcp.header.name_hash': taskHash, 'mcp.body.identity_hash': taskHash, 'http.request.method': 'POST'
    }
  }));
  const methodResult = validateField(PROTOCOL_VERSION, { present: true, value: method }, method);
  const nameResult = validateName(PROTOCOL_VERSION, { present: true, value: taskHash }, taskHash, method);
  evts.push(envelope(clock.advance(2), 'mcp.request.validation', 'network', {
    ...ctx, fields: {
      'event.outcome': 'success', 'jsonrpc.request.id': reqId, 'mcp.body.method': method, 'mcp.header.method': method,
      'mcp.header.name_hash': taskHash, 'mcp.body.identity_hash': taskHash,
      'mcp.validation.method.result': methodResult, 'mcp.validation.name.result': nameResult,
      'mcp.validation.result': rollup(methodResult, nameResult), 'mcp.validation.source': 'server_native'
    }
  }));
  evts.push(envelope(clock.advance(4), 'mcp.task.authorization', 'iam', {
    ...ctx, fields: {
      'event.outcome': 'success', 'principal.id_hash': principalHash, 'principal.authenticated': true,
      'mcp.task.id_hash': taskHash, 'mcp.task.authz_context_id_hash': principalHash,
      'mcp.task.operation': taskOperationFor(method),
      'mcp.authz.decision': 'allow', 'mcp.authz.allowed': true, 'mcp.authz.reason': 'authorized_owner'
    }
  }));
  prev = tracker.transition(taskRaw, 'cancelled');
  evts.push(envelope(clock.advance(3), 'mcp.task.state', 'process', {
    ...ctx, fields: { 'mcp.task.id_hash': taskHash, 'mcp.task.state': 'cancelled', 'mcp.task.previous_state': prev }
  }));
  evts.push(envelope(clock.advance(5), 'mcp.response', 'network', {
    ...ctx, fields: { 'event.outcome': 'success', 'jsonrpc.request.id': reqId, 'http.response.status_code': 200 }
  }));

  corpus.pushAll(file, evts);
  corpus.record({
    scenario_id: 'N3', file, provenance: 'project_reference_harness',
    expected_security_outcome: 'benign',
    expected_detection_track_1: false, expected_detection_track_2: false, expected_detection_track_3: false,
    event_count: evts.length,
    notes: 'Owner cancels their own working task; routing identity matches; resulting terminal state is cancelled.'
  });
}

// ===========================================================================
// N4 -- Legitimate task polling (short interval, moderate interval, longer-running task)
// ===========================================================================
function scenarioN4() {
  const file = 'polling.jsonl';
  const clock = new Clock('2026-09-01T09:20:00.000Z');
  const taskRaw = 'task-n4-0001';
  const taskHash = hmacHash(taskRaw);
  const principalHash = hmacHash('principal:alice-n4');
  const tracker = makeTaskTracker();
  const ctx = { protocolVersion: PROTOCOL_VERSION, transport: TRANSPORT };
  const evts = [];
  let idCounter = 400;

  let prev = tracker.seed(taskRaw, 'working');
  evts.push(envelope(clock.iso(), 'mcp.task.state', 'process', {
    ...ctx, fields: { 'mcp.task.id_hash': taskHash, 'mcp.task.state': 'working', 'mcp.task.previous_state': prev }
  }));

  function poll(status) {
    const reqId = String(idCounter++);
    const method = 'tasks/get';
    evts.push(envelope(clock.iso(), 'mcp.request.received', 'network', {
      ...ctx, fields: {
        'rpc.system.name': 'jsonrpc', 'rpc.method': method, 'mcp.body.method': method,
        'jsonrpc.request.id': reqId, 'mcp.header.method': method,
        'mcp.header.name_hash': taskHash, 'mcp.body.identity_hash': taskHash, 'http.request.method': 'POST'
      }
    }));
    const methodResult = validateField(PROTOCOL_VERSION, { present: true, value: method }, method);
    const nameResult = validateName(PROTOCOL_VERSION, { present: true, value: taskHash }, taskHash, method);
    evts.push(envelope(clock.advance(2), 'mcp.request.validation', 'network', {
      ...ctx, fields: {
        'event.outcome': 'success', 'jsonrpc.request.id': reqId, 'mcp.body.method': method, 'mcp.header.method': method,
        'mcp.header.name_hash': taskHash, 'mcp.body.identity_hash': taskHash,
        'mcp.validation.method.result': methodResult, 'mcp.validation.name.result': nameResult,
        'mcp.validation.result': rollup(methodResult, nameResult), 'mcp.validation.source': 'server_native'
      }
    }));
    evts.push(envelope(clock.advance(3), 'mcp.task.authorization', 'iam', {
      ...ctx, fields: {
        'event.outcome': 'success', 'principal.id_hash': principalHash, 'principal.authenticated': true,
        'mcp.task.id_hash': taskHash, 'mcp.task.authz_context_id_hash': principalHash,
        'mcp.task.operation': 'get', 'mcp.authz.decision': 'allow', 'mcp.authz.allowed': true,
        'mcp.authz.reason': 'authorized_owner'
      }
    }));
    evts.push(envelope(clock.advance(5), 'mcp.response', 'network', {
      ...ctx, fields: { 'event.outcome': 'success', 'jsonrpc.request.id': reqId, 'http.response.status_code': 200 }
    }));
    return status;
  }

  // Short polling interval: three polls, 2s apart, task still working.
  clock.advance(2000); poll('working');
  clock.advance(2000); poll('working');
  clock.advance(2000); poll('working');

  // Moderate polling frequency: two polls, 30s apart.
  clock.advance(30000); poll('working');
  clock.advance(30000); poll('working');

  // Longer-running task: final poll five minutes later observes completion.
  clock.advance(300000);
  poll('working');
  prev = tracker.transition(taskRaw, 'completed');
  evts.push(envelope(clock.advance(50), 'mcp.task.state', 'process', {
    ...ctx, fields: {
      'mcp.task.id_hash': taskHash, 'mcp.task.state': 'completed', 'mcp.task.previous_state': prev,
      'mcp.output.schema_valid': true, 'mcp.output.bytes': 2048, 'mcp.output.item_count': 3
    }
  }));

  corpus.pushAll(file, evts);
  corpus.record({
    scenario_id: 'N4', file, provenance: 'project_reference_harness',
    expected_security_outcome: 'benign',
    expected_detection_track_1: false, expected_detection_track_2: false, expected_detection_track_3: false,
    event_count: evts.length,
    notes: 'Six tasks/get polls (2s, 2s, 2s, 30s, 30s, 300s spacing) against one authorized, long-running task. Establishes that repeated polling volume/frequency alone is not suspicious.'
  });
}

// ===========================================================================
// N5 -- Valid task lifecycle transitions across four distinct tasks
// ===========================================================================
function scenarioN5() {
  const file = 'lifecycle.jsonl';
  const clock = new Clock('2026-09-01T09:40:00.000Z');
  const ctx = { protocolVersion: PROTOCOL_VERSION, transport: TRANSPORT };
  const evts = [];

  function chain(taskRaw, transitions) {
    const taskHash = hmacHash(taskRaw);
    const tracker = makeTaskTracker();
    let prev = tracker.seed(taskRaw, transitions[0]);
    evts.push(envelope(clock.advance(1000), 'mcp.task.state', 'process', {
      ...ctx, fields: { 'mcp.task.id_hash': taskHash, 'mcp.task.state': transitions[0], 'mcp.task.previous_state': prev }
    }));
    for (let i = 1; i < transitions.length; i++) {
      prev = tracker.transition(taskRaw, transitions[i]);
      evts.push(envelope(clock.advance(1000), 'mcp.task.state', 'process', {
        ...ctx, fields: { 'mcp.task.id_hash': taskHash, 'mcp.task.state': transitions[i], 'mcp.task.previous_state': prev }
      }));
    }
  }

  // working -> completed
  chain('task-n5-a', ['working', 'completed']);
  // working -> input_required -> working -> completed
  chain('task-n5-b', ['working', 'input_required', 'working', 'completed']);
  // working -> failed
  chain('task-n5-c', ['working', 'failed']);
  // working -> cancelled
  chain('task-n5-d', ['working', 'cancelled']);

  corpus.pushAll(file, evts);
  corpus.record({
    scenario_id: 'N5', file, provenance: 'project_reference_harness',
    expected_security_outcome: 'benign',
    expected_detection_track_1: false, expected_detection_track_2: false, expected_detection_track_3: false,
    event_count: evts.length,
    notes: 'Four independent tasks demonstrating every SEP-2663 TaskStatus transition path this harness supports: working->completed, working->input_required->working->completed, working->failed, working->cancelled. No transition outside the exact enum in Block 1 is used.'
  });
}

// ===========================================================================
// N6 -- Legitimate cross-principal / shared access (explicit multi-principal grant)
// ===========================================================================
function scenarioN6() {
  const file = 'authorized_shared_access.jsonl';
  const clock = new Clock('2026-09-01T10:00:00.000Z');
  const taskRaw = 'task-n6-0001';
  const taskHash = hmacHash(taskRaw);
  const aliceHash = hmacHash('principal:alice-n6');
  const bobHash = hmacHash('principal:bob-n6');
  const tracker = makeTaskTracker();
  const ctx = { protocolVersion: PROTOCOL_VERSION, transport: TRANSPORT };
  const evts = [];

  let prev = tracker.seed(taskRaw, 'working');
  evts.push(envelope(clock.iso(), 'mcp.task.state', 'process', {
    ...ctx, fields: { 'mcp.task.id_hash': taskHash, 'mcp.task.state': 'working', 'mcp.task.previous_state': prev }
  }));

  function get(principalHash, reason, reqId) {
    const method = 'tasks/get';
    clock.advance(1000);
    evts.push(envelope(clock.iso(), 'mcp.request.received', 'network', {
      ...ctx, fields: {
        'rpc.system.name': 'jsonrpc', 'rpc.method': method, 'mcp.body.method': method,
        'jsonrpc.request.id': reqId, 'mcp.header.method': method,
        'mcp.header.name_hash': taskHash, 'mcp.body.identity_hash': taskHash, 'http.request.method': 'POST'
      }
    }));
    const methodResult = validateField(PROTOCOL_VERSION, { present: true, value: method }, method);
    const nameResult = validateName(PROTOCOL_VERSION, { present: true, value: taskHash }, taskHash, method);
    evts.push(envelope(clock.advance(2), 'mcp.request.validation', 'network', {
      ...ctx, fields: {
        'event.outcome': 'success', 'jsonrpc.request.id': reqId, 'mcp.body.method': method, 'mcp.header.method': method,
        'mcp.header.name_hash': taskHash, 'mcp.body.identity_hash': taskHash,
        'mcp.validation.method.result': methodResult, 'mcp.validation.name.result': nameResult,
        'mcp.validation.result': rollup(methodResult, nameResult), 'mcp.validation.source': 'server_native'
      }
    }));
    evts.push(envelope(clock.advance(4), 'mcp.task.authorization', 'iam', {
      ...ctx, fields: {
        'event.outcome': 'success', 'principal.id_hash': principalHash, 'principal.authenticated': true,
        'mcp.task.id_hash': taskHash, 'mcp.task.authz_context_id_hash': aliceHash,
        'mcp.task.operation': 'get', 'mcp.authz.decision': 'allow', 'mcp.authz.allowed': true,
        'mcp.authz.reason': reason
      }
    }));
    evts.push(envelope(clock.advance(5), 'mcp.response', 'network', {
      ...ctx, fields: { 'event.outcome': 'success', 'jsonrpc.request.id': reqId, 'http.response.status_code': 200 }
    }));
  }

  get(aliceHash, 'authorized_owner', '601');
  get(bobHash, 'authorized_grant', '602');

  corpus.pushAll(file, evts);
  corpus.record({
    scenario_id: 'N6', file, provenance: 'project_reference_harness',
    expected_security_outcome: 'benign',
    expected_detection_track_1: false, expected_detection_track_2: false, expected_detection_track_3: false,
    event_count: evts.length,
    notes: 'Task-123-equivalent owned by Alice; Bob is explicitly granted access by the (simulated) server application layer. Both tasks/get calls are allowed; Bob\'s carries mcp.authz.reason=authorized_grant, distinguishing legitimate sharing from principal_mismatch. MCP itself defines no sharing mechanism (Block 1 SS5) -- this models an application-layer grant on top of it.'
  });
}

// ===========================================================================
// N7 -- Authorization denial unrelated to cross-principal abuse (3 sub-cases)
// ===========================================================================
function scenarioN7() {
  const file = 'benign_denials.jsonl';
  const clock = new Clock('2026-09-01T10:20:00.000Z');
  const ctx = { protocolVersion: PROTOCOL_VERSION, transport: TRANSPORT };
  const evts = [];

  function denial({ taskRaw, principalRaw, ownerRaw, reqId, reason, contextHashPresent }) {
    const taskHash = hmacHash(taskRaw);
    const principalHash = hmacHash(principalRaw);
    const ownerHash = ownerRaw ? hmacHash(ownerRaw) : null;
    const method = 'tasks/cancel';
    clock.advance(1000);
    evts.push(envelope(clock.iso(), 'mcp.request.received', 'network', {
      ...ctx, fields: {
        'rpc.system.name': 'jsonrpc', 'rpc.method': method, 'mcp.body.method': method,
        'jsonrpc.request.id': reqId, 'mcp.header.method': method,
        'mcp.header.name_hash': taskHash, 'mcp.body.identity_hash': taskHash, 'http.request.method': 'POST'
      }
    }));
    const methodResult = validateField(PROTOCOL_VERSION, { present: true, value: method }, method);
    const nameResult = validateName(PROTOCOL_VERSION, { present: true, value: taskHash }, taskHash, method);
    evts.push(envelope(clock.advance(2), 'mcp.request.validation', 'network', {
      ...ctx, fields: {
        'event.outcome': 'success', 'jsonrpc.request.id': reqId, 'mcp.body.method': method, 'mcp.header.method': method,
        'mcp.header.name_hash': taskHash, 'mcp.body.identity_hash': taskHash,
        'mcp.validation.method.result': methodResult, 'mcp.validation.name.result': nameResult,
        'mcp.validation.result': rollup(methodResult, nameResult), 'mcp.validation.source': 'server_native'
      }
    }));
    evts.push(envelope(clock.advance(4), 'mcp.task.authorization', 'iam', {
      ...ctx, fields: {
        'event.outcome': 'failure', 'principal.id_hash': principalHash, 'principal.authenticated': true,
        'mcp.task.id_hash': taskHash,
        'mcp.task.authz_context_id_hash': contextHashPresent ? ownerHash : null,
        'mcp.task.operation': 'cancel', 'mcp.authz.decision': 'deny', 'mcp.authz.allowed': false,
        'mcp.authz.reason': reason
      }
    }));
    evts.push(envelope(clock.advance(3), 'mcp.response', 'network', {
      ...ctx, fields: {
        'event.outcome': 'failure', 'jsonrpc.request.id': reqId,
        'rpc.status_code': '-32602', 'http.response.status_code': 400
      }
    }));
  }

  // (a) The task's own owner is denied by a business/org policy, not by another principal.
  denial({
    taskRaw: 'task-n7-a', principalRaw: 'principal:carol-n7', ownerRaw: 'principal:carol-n7',
    reqId: '701', reason: 'policy_denied', contextHashPresent: true
  });
  // (b) The task's own owner is denied for lacking a scope required for this specific operation.
  denial({
    taskRaw: 'task-n7-b', principalRaw: 'principal:carol-n7', ownerRaw: 'principal:carol-n7',
    reqId: '702', reason: 'insufficient_scope', contextHashPresent: true
  });
  // (c) taskId does not correspond to any known task at all -- no owner to speak of.
  denial({
    taskRaw: 'task-n7-c-nonexistent', principalRaw: 'principal:erin-n7', ownerRaw: null,
    reqId: '703', reason: 'context_unbound', contextHashPresent: false
  });

  corpus.pushAll(file, evts);
  corpus.record({
    scenario_id: 'N7', file, provenance: 'project_reference_harness',
    expected_security_outcome: 'benign',
    expected_detection_track_1: false, expected_detection_track_2: false, expected_detection_track_3: false,
    event_count: evts.length,
    notes: 'Three denials that must NOT be classified as Track 2 attacks: (a) owner denied by policy, (b) owner denied for insufficient scope, (c) nonexistent taskId (no owner exists to be wronged). All surface the ambiguous wire-level -32602, demonstrating why Track 2 must read mcp.authz.decision/reason rather than the response code.'
  });
}

// ===========================================================================
// N8 -- Normal subscriptions/listen
// ===========================================================================
function scenarioN8() {
  const file = 'subscriptions.jsonl';
  const clock = new Clock('2026-09-01T11:00:00.000Z');
  const principalHash = hmacHash('principal:alice-n8');
  const subId = '801';
  const uriHash = hmacHash('resource:file:///project/config.json');
  const ctx = { protocolVersion: PROTOCOL_VERSION, transport: TRANSPORT };
  const evts = [];

  evts.push(envelope(clock.iso(), 'mcp.subscription.open', 'session', {
    ...ctx, fields: {
      'jsonrpc.request.id': subId, 'mcp.subscription.id': subId,
      'principal.id_hash': principalHash, 'principal.authenticated': true,
      'mcp.authz.grant_snapshot_hash': hmacHash('grant:alice-n8:v1'),
      'mcp.authz.grant_expiry': '2026-09-01T12:00:00.000Z',
      'mcp.authz.valid_until': '2026-09-01T12:00:00.000Z',
      'mcp.subscription.filter_types': { resourcesListChanged: false, toolsListChanged: false }
    }
  }));
  evts.push(envelope(clock.advance(50), 'mcp.subscription.acknowledged', 'session', {
    ...ctx, fields: {
      'event.outcome': 'success', 'mcp.subscription.id': subId, 'principal.id_hash': principalHash,
      'mcp.subscription.state': 'acknowledged', 'mcp.subscription.filter_hash': [uriHash]
    }
  }));
  evts.push(envelope(clock.advance(15000), 'mcp.subscription.notification', 'session', {
    ...ctx, fields: {
      'mcp.subscription.id': subId, 'principal.id_hash': principalHash,
      'mcp.subscription.state': 'active', 'mcp.subscription.notification_type': 'notifications/resources/updated',
      'mcp.subscription.notification.resource_uri_hash': uriHash
    }
  }));
  evts.push(envelope(clock.advance(20000), 'mcp.subscription.notification', 'session', {
    ...ctx, fields: {
      'mcp.subscription.id': subId, 'principal.id_hash': principalHash,
      'mcp.subscription.state': 'active', 'mcp.subscription.notification_type': 'notifications/resources/updated',
      'mcp.subscription.notification.resource_uri_hash': uriHash
    }
  }));
  evts.push(envelope(clock.advance(600000), 'mcp.subscription.close', 'session', {
    ...ctx, fields: {
      'event.outcome': 'success', 'mcp.subscription.id': subId, 'principal.id_hash': principalHash,
      'mcp.subscription.state': 'closed_graceful', 'mcp.subscription.close.reason': 'client_closed'
    }
  }));

  corpus.pushAll(file, evts);
  corpus.record({
    scenario_id: 'N8', file, provenance: 'project_reference_harness',
    expected_security_outcome: 'benign',
    expected_detection_track_1: false, expected_detection_track_2: false, expected_detection_track_3: false,
    event_count: evts.length,
    notes: 'Full open -> acknowledged -> two notifications -> client-initiated graceful close, all before the grant expiry. mcp.subscription.id (=801) is the JSON-RPC id of the listen request, per Block 1/2.'
  });
}

// ===========================================================================
// N9 -- Authorization revocation followed by CORRECT stream termination
// ===========================================================================
function scenarioN9() {
  const file = 'authorization_expiry_clean_close.jsonl';
  const clock = new Clock('2026-09-01T11:30:00.000Z');
  const principalHash = hmacHash('principal:alice-n9');
  const subId = '901';
  const uriHash = hmacHash('resource:file:///project/notes.md');
  const ctx = { protocolVersion: PROTOCOL_VERSION, transport: TRANSPORT };
  const evts = [];

  evts.push(envelope(clock.iso(), 'mcp.subscription.open', 'session', {
    ...ctx, fields: {
      'jsonrpc.request.id': subId, 'mcp.subscription.id': subId,
      'principal.id_hash': principalHash, 'principal.authenticated': true,
      'mcp.authz.grant_snapshot_hash': hmacHash('grant:alice-n9:v1'),
      'mcp.authz.grant_expiry': '2026-09-01T13:30:00.000Z',
      'mcp.authz.valid_until': '2026-09-01T13:30:00.000Z',
      'mcp.subscription.filter_types': { resourcesListChanged: false, toolsListChanged: false }
    }
  }));
  evts.push(envelope(clock.advance(50), 'mcp.subscription.acknowledged', 'session', {
    ...ctx, fields: {
      'event.outcome': 'success', 'mcp.subscription.id': subId, 'principal.id_hash': principalHash,
      'mcp.subscription.state': 'acknowledged'
    }
  }));
  evts.push(envelope(clock.advance(60000), 'mcp.subscription.notification', 'session', {
    ...ctx, fields: {
      'mcp.subscription.id': subId, 'principal.id_hash': principalHash, 'mcp.subscription.state': 'active',
      'mcp.subscription.notification_type': 'notifications/resources/updated',
      'mcp.subscription.notification.resource_uri_hash': uriHash
    }
  })); // before revocation: fine

  const revokedAt = clock.advance(30000);
  evts.push(envelope(revokedAt, 'mcp.subscription.authorization_change', 'iam', {
    ...ctx, fields: {
      'principal.id_hash': principalHash, 'mcp.authz.change.type': 'revoked',
      'mcp.authz.change.source': 'authorization_server_event',
      'mcp.authz.change.effective_at': revokedAt, 'mcp.authz.change.detected_at': revokedAt,
      'mcp.authz.change.timing_confidence': 'authoritative'
    }
  }));

  // Correct application behavior: close the stream promptly, before any further notification.
  evts.push(envelope(clock.advance(500), 'mcp.subscription.close', 'session', {
    ...ctx, fields: {
      'event.outcome': 'success', 'mcp.subscription.id': subId, 'principal.id_hash': principalHash,
      'mcp.subscription.state': 'closed_graceful', 'mcp.subscription.close.reason': 'server_forced_authz'
    }
  }));

  corpus.pushAll(file, evts);
  corpus.record({
    scenario_id: 'N9', file, provenance: 'project_reference_harness',
    expected_security_outcome: 'benign',
    expected_detection_track_1: false, expected_detection_track_2: false, expected_detection_track_3: false,
    event_count: evts.length,
    notes: 'Subscription is revoked while active; the application closes the stream (close.reason=server_forced_authz) 500ms later with NO further notification emitted after mcp.authz.change.effective_at. This is the correct behavior Track 3 must NOT flag -- contrast with a future Block 4 fixture that omits the close and keeps notifying.'
  });
}

// ===========================================================================
// N10 -- Legitimate large payload
// ===========================================================================
function scenarioN10() {
  const file = 'large_output.jsonl';
  const clock = new Clock('2026-09-01T12:00:00.000Z');
  const taskRaw = 'task-n10-0001';
  const taskHash = hmacHash(taskRaw);
  const principalHash = hmacHash('principal:frank-n10');
  const tracker = makeTaskTracker();
  const ctx = { protocolVersion: PROTOCOL_VERSION, transport: TRANSPORT };
  const evts = [];

  let prev = tracker.seed(taskRaw, 'working');
  evts.push(envelope(clock.iso(), 'mcp.task.state', 'process', {
    ...ctx, fields: { 'mcp.task.id_hash': taskHash, 'mcp.task.state': 'working', 'mcp.task.previous_state': prev }
  }));

  const reqId = '1001';
  const method = 'tasks/get';
  clock.advance(1000);
  evts.push(envelope(clock.iso(), 'mcp.request.received', 'network', {
    ...ctx, fields: {
      'rpc.system.name': 'jsonrpc', 'rpc.method': method, 'mcp.body.method': method,
      'jsonrpc.request.id': reqId, 'mcp.header.method': method,
      'mcp.header.name_hash': taskHash, 'mcp.body.identity_hash': taskHash, 'http.request.method': 'POST'
    }
  }));
  const methodResult = validateField(PROTOCOL_VERSION, { present: true, value: method }, method);
  const nameResult = validateName(PROTOCOL_VERSION, { present: true, value: taskHash }, taskHash, method);
  evts.push(envelope(clock.advance(2), 'mcp.request.validation', 'network', {
    ...ctx, fields: {
      'event.outcome': 'success', 'jsonrpc.request.id': reqId, 'mcp.body.method': method, 'mcp.header.method': method,
      'mcp.header.name_hash': taskHash, 'mcp.body.identity_hash': taskHash,
      'mcp.validation.method.result': methodResult, 'mcp.validation.name.result': nameResult,
      'mcp.validation.result': rollup(methodResult, nameResult), 'mcp.validation.source': 'server_native'
    }
  }));
  evts.push(envelope(clock.advance(4), 'mcp.task.authorization', 'iam', {
    ...ctx, fields: {
      'event.outcome': 'success', 'principal.id_hash': principalHash, 'principal.authenticated': true,
      'mcp.task.id_hash': taskHash, 'mcp.task.authz_context_id_hash': principalHash,
      'mcp.task.operation': 'get', 'mcp.authz.decision': 'allow', 'mcp.authz.allowed': true,
      'mcp.authz.reason': 'authorized_owner'
    }
  }));
  prev = tracker.transition(taskRaw, 'completed');
  evts.push(envelope(clock.advance(1200), 'mcp.task.state', 'process', {
    ...ctx, fields: {
      'mcp.task.id_hash': taskHash, 'mcp.task.state': 'completed', 'mcp.task.previous_state': prev,
      'mcp.output.schema_valid': true, 'mcp.output.bytes': 5242880, 'mcp.output.item_count': 50000
    }
  }));
  evts.push(envelope(clock.advance(5), 'mcp.response', 'network', {
    ...ctx, fields: { 'event.outcome': 'success', 'jsonrpc.request.id': reqId, 'http.response.status_code': 200 }
  }));

  corpus.pushAll(file, evts);
  corpus.record({
    scenario_id: 'N10', file, provenance: 'project_reference_harness',
    expected_security_outcome: 'benign',
    expected_detection_track_1: false, expected_detection_track_2: false, expected_detection_track_3: false,
    event_count: evts.length,
    notes: '5 MiB / 50,000-item completed output from an authorized owner. Schema-valid, protocol-valid, authorization-valid; size alone must not trigger any track.'
  });
}

// ===========================================================================
// N11 -- Legitimate high-token LLM-shaped output (SYNTHETIC enrichment values)
// ===========================================================================
function scenarioN11() {
  const file = 'high_token_output.jsonl';
  const clock = new Clock('2026-09-01T12:15:00.000Z');
  const taskRaw = 'task-n11-0001';
  const taskHash = hmacHash(taskRaw);
  const principalHash = hmacHash('principal:grace-n11');
  const tracker = makeTaskTracker();
  const ctx = { protocolVersion: PROTOCOL_VERSION, transport: TRANSPORT };
  const evts = [];

  let prev = tracker.seed(taskRaw, 'working');
  evts.push(envelope(clock.iso(), 'mcp.task.state', 'process', {
    ...ctx, fields: { 'mcp.task.id_hash': taskHash, 'mcp.task.state': 'working', 'mcp.task.previous_state': prev }
  }));

  const reqId = '1101';
  const method = 'tasks/get';
  clock.advance(1000);
  evts.push(envelope(clock.iso(), 'mcp.request.received', 'network', {
    ...ctx, fields: {
      'rpc.system.name': 'jsonrpc', 'rpc.method': method, 'mcp.body.method': method,
      'jsonrpc.request.id': reqId, 'mcp.header.method': method,
      'mcp.header.name_hash': taskHash, 'mcp.body.identity_hash': taskHash, 'http.request.method': 'POST'
    }
  }));
  const methodResult = validateField(PROTOCOL_VERSION, { present: true, value: method }, method);
  const nameResult = validateName(PROTOCOL_VERSION, { present: true, value: taskHash }, taskHash, method);
  evts.push(envelope(clock.advance(2), 'mcp.request.validation', 'network', {
    ...ctx, fields: {
      'event.outcome': 'success', 'jsonrpc.request.id': reqId, 'mcp.body.method': method, 'mcp.header.method': method,
      'mcp.header.name_hash': taskHash, 'mcp.body.identity_hash': taskHash,
      'mcp.validation.method.result': methodResult, 'mcp.validation.name.result': nameResult,
      'mcp.validation.result': rollup(methodResult, nameResult), 'mcp.validation.source': 'server_native'
    }
  }));
  evts.push(envelope(clock.advance(4), 'mcp.task.authorization', 'iam', {
    ...ctx, fields: {
      'event.outcome': 'success', 'principal.id_hash': principalHash, 'principal.authenticated': true,
      'mcp.task.id_hash': taskHash, 'mcp.task.authz_context_id_hash': principalHash,
      'mcp.task.operation': 'get', 'mcp.authz.decision': 'allow', 'mcp.authz.allowed': true,
      'mcp.authz.reason': 'authorized_owner'
    }
  }));
  prev = tracker.transition(taskRaw, 'completed');
  // NOTE: gen_ai.usage.* values below are SYNTHETIC illustrative numbers -- no LLM was
  // invoked by this harness (Block 3 explicitly forbids adding an LLM solely for this
  // scenario). See data/normal/README.md "Synthetic fixtures" section.
  evts.push(envelope(clock.advance(1200), 'mcp.task.state', 'process', {
    ...ctx, fields: {
      'mcp.task.id_hash': taskHash, 'mcp.task.state': 'completed', 'mcp.task.previous_state': prev,
      'mcp.output.schema_valid': true, 'mcp.output.bytes': 61440, 'mcp.output.item_count': 1,
      'gen_ai.usage.input_tokens': 18000, 'gen_ai.usage.output_tokens': 12000
    }
  }));
  evts.push(envelope(clock.advance(5), 'mcp.response', 'network', {
    ...ctx, fields: { 'event.outcome': 'success', 'jsonrpc.request.id': reqId, 'http.response.status_code': 200 }
  }));

  corpus.pushAll(file, evts);
  corpus.record({
    scenario_id: 'N11', file, provenance: 'synthetic_enrichment',
    expected_security_outcome: 'benign_synthetic_enrichment',
    expected_detection_track_1: false, expected_detection_track_2: false, expected_detection_track_3: false,
    event_count: evts.length,
    notes: 'SYNTHETIC: gen_ai.usage.input_tokens/output_tokens (18000/12000) are illustrative fabricated values, not produced by a live LLM call -- this harness intentionally does not embed an LLM per the Block 3 instruction. High token count is recorded purely as enrichment and must not be treated as malicious.'
  });
}

// ===========================================================================
// N12 -- Missing optional telemetry (reduced visibility, still benign)
// ===========================================================================
function scenarioN12() {
  const file = 'missing_optional_telemetry.jsonl';
  const clock = new Clock('2026-09-01T12:30:00.000Z');
  const taskRaw = 'task-n12-0001';
  const taskHash = hmacHash(taskRaw);
  const principalHash = hmacHash('principal:henry-n12');
  const tracker = makeTaskTracker();
  const ctx = { protocolVersion: PROTOCOL_VERSION, transport: TRANSPORT }; // note: no traceId/spanId passed anywhere below
  const evts = [];

  let prev = tracker.seed(taskRaw, 'working');
  evts.push(envelope(clock.iso(), 'mcp.task.state', 'process', {
    ...ctx, fields: { 'mcp.task.id_hash': taskHash, 'mcp.task.state': 'working', 'mcp.task.previous_state': prev }
  }));

  const reqId = '1201';
  const method = 'tasks/get';
  clock.advance(1000);
  evts.push(envelope(clock.iso(), 'mcp.request.received', 'network', {
    ...ctx, fields: {
      'rpc.system.name': 'jsonrpc', 'rpc.method': method, 'mcp.body.method': method,
      'jsonrpc.request.id': reqId, 'mcp.header.method': method,
      'mcp.header.name_hash': taskHash, 'mcp.body.identity_hash': taskHash, 'http.request.method': 'POST'
      // no trace_id / span_id
    }
  }));
  const methodResult = validateField(PROTOCOL_VERSION, { present: true, value: method }, method);
  const nameResult = validateName(PROTOCOL_VERSION, { present: true, value: taskHash }, taskHash, method);
  evts.push(envelope(clock.advance(2), 'mcp.request.validation', 'network', {
    ...ctx, fields: {
      'event.outcome': 'success', 'jsonrpc.request.id': reqId, 'mcp.body.method': method, 'mcp.header.method': method,
      'mcp.header.name_hash': taskHash, 'mcp.body.identity_hash': taskHash,
      'mcp.validation.method.result': methodResult, 'mcp.validation.name.result': nameResult,
      'mcp.validation.result': rollup(methodResult, nameResult), 'mcp.validation.source': 'server_native'
    }
  }));
  // Server can determine allow/deny but cannot expose *why* via a context binding --
  // mcp.task.authz_context_id_hash is null. Per the Block 2 patch, this null MUST NOT be
  // treated as suspicious; the allow decision + authorized_owner reason still stand alone.
  evts.push(envelope(clock.advance(4), 'mcp.task.authorization', 'iam', {
    ...ctx, fields: {
      'event.outcome': 'success', 'principal.id_hash': principalHash, 'principal.authenticated': true,
      'mcp.task.id_hash': taskHash, 'mcp.task.authz_context_id_hash': null,
      'mcp.task.operation': 'get', 'mcp.authz.decision': 'allow', 'mcp.authz.allowed': true,
      'mcp.authz.reason': 'authorized_owner'
    }
  }));
  prev = tracker.transition(taskRaw, 'completed');
  // No mcp.output.* and no gen_ai.usage.* fields at all -- output/token telemetry absent.
  evts.push(envelope(clock.advance(1200), 'mcp.task.state', 'process', {
    ...ctx, fields: { 'mcp.task.id_hash': taskHash, 'mcp.task.state': 'completed', 'mcp.task.previous_state': prev }
  }));
  evts.push(envelope(clock.advance(5), 'mcp.response', 'network', {
    ...ctx, fields: { 'event.outcome': 'success', 'jsonrpc.request.id': reqId, 'http.response.status_code': 200 }
  }));

  corpus.pushAll(file, evts);
  corpus.record({
    scenario_id: 'N12', file, provenance: 'project_reference_harness',
    expected_security_outcome: 'benign_reduced_visibility',
    expected_detection_track_1: false, expected_detection_track_2: false, expected_detection_track_3: false,
    event_count: evts.length,
    notes: 'No trace_id/span_id anywhere; mcp.task.authz_context_id_hash=null despite a definite allow decision; no mcp.output.* or gen_ai.usage.* on task completion. Demonstrates that simultaneous absence of several optional fields reduces visibility only, never implies malice (Block 2 patch, N12 requirement).'
  });
}

// ===========================================================================
// N13 -- Missing/compatibility routing header case (legacy protocol version)
// ===========================================================================
function scenarioN13() {
  const file = 'compatibility_cases.jsonl';
  const clock = new Clock('2026-09-01T12:45:00.000Z');
  const legacyVersion = '2025-03-26'; // predates SEP-2243 (Mcp-Method/Mcp-Name did not exist yet)
  const toolNameHash = hmacHash('tool:legacy_tool');
  const principalHash = hmacHash('principal:legacy-client-n13');
  const ctx = { protocolVersion: legacyVersion, transport: TRANSPORT };
  const evts = [];

  const reqId = '1301';
  const method = 'tools/call';
  evts.push(envelope(clock.iso(), 'mcp.request.received', 'network', {
    ...ctx, fields: {
      'rpc.system.name': 'jsonrpc', 'rpc.method': method, 'mcp.body.method': method,
      'jsonrpc.request.id': reqId,
      'mcp.header.method': null, 'mcp.header.name_hash': null, 'mcp.body.identity_hash': toolNameHash,
      'http.request.method': 'POST'
    }
  }));
  const methodResult = validateField(legacyVersion, { present: false }, method);
  const nameResult = validateName(legacyVersion, { present: false }, toolNameHash, method);
  evts.push(envelope(clock.advance(3), 'mcp.request.validation', 'network', {
    ...ctx, fields: {
      'event.outcome': 'success', 'jsonrpc.request.id': reqId, 'mcp.body.method': method, 'mcp.header.method': null,
      'mcp.header.name_hash': null, 'mcp.body.identity_hash': toolNameHash,
      'mcp.validation.method.result': methodResult, 'mcp.validation.name.result': nameResult,
      'mcp.validation.result': rollup(methodResult, nameResult), 'mcp.validation.source': 'server_native',
      'mcp.validation.reason': 'Negotiated protocol version 2025-03-26 predates Mcp-Method/Mcp-Name (SEP-2243, introduced 2026-07-28); header absence is compatibility, not a routing violation.'
    }
  }));
  evts.push(envelope(clock.advance(20), 'mcp.response', 'network', {
    ...ctx, fields: { 'event.outcome': 'success', 'jsonrpc.request.id': reqId, 'http.response.status_code': 200 }
  }));

  corpus.pushAll(file, evts);
  corpus.record({
    scenario_id: 'N13', file, provenance: 'project_reference_harness',
    expected_security_outcome: 'benign_compatibility',
    expected_detection_track_1: false, expected_detection_track_2: false, expected_detection_track_3: false,
    event_count: evts.length,
    notes: 'Legacy client negotiated protocol version 2025-03-26, which predates the Mcp-Method/Mcp-Name header requirement entirely. Both validation results are version_incompatible (not "missing"), rolling up to mcp.validation.result=valid. Labeled compatibility/benign per Block 3 -- this is NOT the "malformed value under a version that requires the header" case, which is reserved for Block 4.'
  });
}

// ===========================================================================
// Run all scenarios
// ===========================================================================
scenarioN1();
scenarioN2();
scenarioN3();
scenarioN4();
scenarioN5();
scenarioN6();
scenarioN7();
scenarioN8();
scenarioN9();
scenarioN10();
scenarioN11();
scenarioN12();
scenarioN13();

corpus.writeOut();

const totalEvents = [...corpus.files.values()].reduce((n, evts) => n + evts.length, 0);
console.log(`Wrote ${corpus.files.size} JSONL files + manifest.jsonl (${corpus.manifest.length} scenarios, ${totalEvents} total events) to ${DATA_DIR}`);
