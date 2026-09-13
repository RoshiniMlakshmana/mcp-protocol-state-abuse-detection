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
  return { methodResult, nameResult, overall: rollup(methodResult, nameResult) };
}

for (const [scenarioId, expectFire] of [['A1', true], ['A2', true], ['A3', true]]) {
  test(`Track 1 (${scenarioId}): task-identity mismatch (Mcp-Name vs params.taskId) independently recomputes to conflict and fires`, () => {
    const { byScenario } = readAllScenarios();
    const s = byScenario.get(scenarioId);
    assert.ok(s, `${scenarioId} must exist`);
    const v = s.events.find((e) => e['event.name'] === 'mcp.request.validation');
    const recomputed = recomputeValidation(v);
    assert.equal(recomputed.methodResult, 'match', `${scenarioId}: method should match`);
    assert.equal(recomputed.nameResult, 'conflict', `${scenarioId}: name should independently recompute to conflict`);
    assert.equal(recomputed.overall, 'invalid');
    assert.equal(v['mcp.validation.name.result'], recomputed.nameResult, `${scenarioId}: recorded result must match recomputation`);
    assert.equal(s.manifest.expected_detection_track_1, expectFire);
    assert.equal(s.manifest.expected_detection_track_2, false);
    assert.equal(s.manifest.expected_detection_track_3, false);
    // No mcp.task.authorization event: rejected at validation, never reaches authz.
    assert.equal(s.events.some((e) => e['event.name'] === 'mcp.task.authorization'), false);
  });
}

test('Track 1 (A4): header/body method mismatch independently recomputes to conflict, task identity matches', () => {
  const { byScenario } = readAllScenarios();
  const s = byScenario.get('A4');
  const v = s.events.find((e) => e['event.name'] === 'mcp.request.validation');
  const recomputed = recomputeValidation(v);
  assert.equal(recomputed.methodResult, 'conflict');
  assert.equal(recomputed.nameResult, 'match');
  assert.equal(recomputed.overall, 'invalid');
  assert.equal(v['mcp.header.name_hash'], v['mcp.body.identity_hash'], 'A4: task identity must genuinely match on both sides');
  assert.equal(s.manifest.expected_detection_track_1, true);
});

test('Track 1 (A5): dual mismatch independently recomputes both fields to conflict, preserving both findings', () => {
  const { byScenario } = readAllScenarios();
  const s = byScenario.get('A5');
  const v = s.events.find((e) => e['event.name'] === 'mcp.request.validation');
  const recomputed = recomputeValidation(v);
  assert.equal(recomputed.methodResult, 'conflict');
  assert.equal(recomputed.nameResult, 'conflict');
  assert.notEqual(v['mcp.header.name_hash'], v['mcp.body.identity_hash']);
  assert.notEqual(v['mcp.header.method'], v['mcp.body.method']);
  assert.equal(s.manifest.expected_detection_track_1, true);
});

test('Track 1 (A6 control): version-incompatible header absence recomputes to version_incompatible, not "missing", and does not fire', () => {
  const { byScenario } = readAllScenarios();
  const s = byScenario.get('A6');
  const v = s.events.find((e) => e['event.name'] === 'mcp.request.validation');
  const recomputed = recomputeValidation(v);
  assert.equal(recomputed.methodResult, 'version_incompatible');
  assert.equal(recomputed.nameResult, 'version_incompatible');
  assert.equal(recomputed.overall, 'valid');
  assert.equal(s.manifest.expected_detection_track_1, false);
  assert.notEqual(v['mcp.validation.method.result'], 'missing', 'A6 must not be conflated with a real "missing under a required version" case');
});

test('Track 1: matching routing (A7-A10 requests) does not fire, verified by recomputation', () => {
  const { byScenario } = readAllScenarios();
  for (const id of ['A7', 'A8', 'A9', 'A10']) {
    const s = byScenario.get(id);
    const v = s.events.find((e) => e['event.name'] === 'mcp.request.validation');
    const recomputed = recomputeValidation(v);
    assert.equal(recomputed.overall, 'valid', `${id}: routing must be clean so the finding is provably Track 2, not Track 1`);
    assert.equal(s.manifest.expected_detection_track_1, false);
  }
});

test('Track 1 (A6 vs A1) false-positive separation: missing/compatibility is distinguishable from conflicting values', () => {
  const { byScenario } = readAllScenarios();
  const a1 = byScenario.get('A1').events.find((e) => e['event.name'] === 'mcp.request.validation');
  const a6 = byScenario.get('A6').events.find((e) => e['event.name'] === 'mcp.request.validation');
  assert.notEqual(a1['mcp.validation.name.result'], a6['mcp.validation.name.result']);
  assert.equal(a1['mcp.validation.result'], 'invalid');
  assert.equal(a6['mcp.validation.result'], 'valid');
});
