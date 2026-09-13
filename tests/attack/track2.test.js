'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const { readAllScenarios } = require('./helpers');
const { validateField, validateName, rollup } = require('../../tools/harness/lib/protocol');

function recomputeValidation(evt) {
  const pv = evt['mcp.protocol.version'];
  const method = evt['mcp.body.method'];
  const hMethod = evt['mcp.header.method'];
  const hName = evt['mcp.header.name_hash'];
  const bIdentity = evt['mcp.body.identity_hash'];
  const methodResult = validateField(pv, { present: hMethod !== null && hMethod !== undefined, value: hMethod }, method);
  const nameResult = validateName(pv, { present: hName !== null && hName !== undefined, value: hName }, bIdentity, method);
  return rollup(methodResult, nameResult);
}

/** Independent re-implementation of the Block 2 (patched) Track 2 rule: a violation requires
 *  server-side authorization evidence (decision=deny with a violation-shaped reason), never an
 *  inference from a null context hash or from the response code alone. */
function isTrack2Violation(authzEvt) {
  if (!authzEvt) return false;
  // Specifically the cross-principal shape -- a deny for policy/scope/nonexistent-task reasons
  // is a benign denial (Block 3 N7), not the violation Track 2 exists to catch.
  return authzEvt['mcp.authz.decision'] === 'deny' && authzEvt['mcp.authz.reason'] === 'principal_mismatch';
}

for (const id of ['A7', 'A8', 'A9', 'A10']) {
  test(`Track 2 (${id}): matching protocol fields do not suppress the authorization violation`, () => {
    const { byScenario } = readAllScenarios();
    const s = byScenario.get(id);
    const v = s.events.find((e) => e['event.name'] === 'mcp.request.validation');
    assert.equal(recomputeValidation(v), 'valid', `${id}: routing must independently recompute as valid`);
    const authz = s.events.find((e) => e['event.name'] === 'mcp.task.authorization');
    assert.ok(authz, `${id} must carry a mcp.task.authorization event`);
    assert.equal(isTrack2Violation(authz), true, `${id}: recomputed rule must call this a violation`);
    assert.equal(s.manifest.expected_detection_track_1, false);
    assert.equal(s.manifest.expected_detection_track_2, true);
    assert.equal(s.manifest.expected_detection_track_3, false);
  });
}

test('Track 2 (A7 vs A11): denied authorization fires; the response error code alone would have been ambiguous', () => {
  const { byScenario } = readAllScenarios();
  const a7 = byScenario.get('A7');
  const resp = a7.events.find((e) => e['event.name'] === 'mcp.response');
  assert.equal(resp['rpc.status_code'], '-32602', 'A7 must surface the same wire code an ordinary not-found error would');
  const authz = a7.events.find((e) => e['event.name'] === 'mcp.task.authorization');
  assert.equal(isTrack2Violation(authz), true, 'the finding must come from mcp.authz.*, not from rpc.status_code');
});

test('Track 2 (rule-level): missing auth-context telemetry alone does not fire', () => {
  // Constructed directly (not read from a label) to test the RULE, independent of any file:
  // per the Block 2 patch, a null context hash must never by itself indicate a violation.
  const allowedWithNullContext = {
    'mcp.authz.decision': 'allow', 'mcp.authz.reason': 'authorized_owner', 'mcp.task.authz_context_id_hash': null
  };
  const deniedWithNullContext = {
    'mcp.authz.decision': 'deny', 'mcp.authz.reason': 'context_unbound', 'mcp.task.authz_context_id_hash': null
  };
  assert.equal(isTrack2Violation(allowedWithNullContext), false, 'allow + null context must not be flagged');
  // context_unbound (nonexistent task) is explicitly NOT the cross-principal shape either.
  assert.equal(isTrack2Violation(deniedWithNullContext), false, 'deny for a nonexistent task (context_unbound) is not a cross-principal violation');
});

test('Track 2 (A11, reused Block 3 N6): legitimate shared access does not fire', () => {
  const { byScenario } = readAllScenarios();
  const a11 = byScenario.get('A11');
  assert.ok(a11, 'A11 must be present in the attack manifest even though it reuses a Block 3 file');
  const authzEvents = a11.events.filter((e) => e['event.name'] === 'mcp.task.authorization');
  assert.equal(authzEvents.length, 2, 'A11 must show two principals against the same task');
  for (const e of authzEvents) {
    assert.equal(isTrack2Violation(e), false, 'both allowed accesses in A11 must not be flagged as violations');
  }
  const reasons = new Set(authzEvents.map((e) => e['mcp.authz.reason']));
  assert.ok(reasons.has('authorized_owner') && reasons.has('authorized_grant'));
  assert.equal(a11.manifest.expected_detection_track_2, false);
});

test('Track 2 (A17 combined): the unauthorized leg fires independently of the routing leg', () => {
  const { byScenario } = readAllScenarios();
  const a17 = byScenario.get('A17');
  const authz = a17.events.find((e) => e['event.name'] === 'mcp.task.authorization');
  assert.equal(isTrack2Violation(authz), true);
  assert.equal(a17.manifest.expected_detection_track_2, true);
  assert.equal(a17.manifest.expected_detection_track_1, true);
});
