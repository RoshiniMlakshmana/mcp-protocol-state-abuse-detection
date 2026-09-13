'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const { readAllScenarioEvents } = require('./helpers');
const { validateField, validateName, rollup } = require('../../tools/harness/lib/protocol');

// Track 1 invariant (docs/state-invariants.md rows 1-3): header method/identity must agree
// with the body, and "missing under a compatible version" must never be conflated with
// "conflicting under a version that requires the header."

test('Track 1: every mcp.request.validation result is independently recomputable from its own recorded raw fields', () => {
  const { allEvents } = readAllScenarioEvents();
  const validations = allEvents.filter((e) => e['event.name'] === 'mcp.request.validation');
  assert.ok(validations.length > 0, 'corpus must contain at least one mcp.request.validation event');

  for (const evt of validations) {
    const pv = evt['mcp.protocol.version'];
    const method = evt['mcp.body.method'];
    const headerMethod = evt['mcp.header.method'];
    const header = { present: headerMethod !== null && headerMethod !== undefined, value: headerMethod };
    const recomputedMethodResult = validateField(pv, header, method);
    assert.equal(
      recomputedMethodResult, evt['mcp.validation.method.result'],
      `method validation mismatch for jsonrpc.request.id=${evt['jsonrpc.request.id']}`
    );

    const headerName = evt['mcp.header.name_hash'];
    const bodyIdentity = evt['mcp.body.identity_hash'];
    const nameHeader = { present: headerName !== null && headerName !== undefined, value: headerName };
    const recomputedNameResult = validateName(pv, nameHeader, bodyIdentity, method);
    assert.equal(
      recomputedNameResult, evt['mcp.validation.name.result'],
      `name validation mismatch for jsonrpc.request.id=${evt['jsonrpc.request.id']}`
    );

    assert.equal(
      rollup(recomputedMethodResult, recomputedNameResult), evt['mcp.validation.result'],
      `rollup mismatch for jsonrpc.request.id=${evt['jsonrpc.request.id']}`
    );
  }
});

test('Track 1: no normal-corpus request has a real conflict/malformed routing mismatch', () => {
  const { allEvents } = readAllScenarioEvents();
  const validations = allEvents.filter((e) => e['event.name'] === 'mcp.request.validation');
  for (const evt of validations) {
    assert.notEqual(evt['mcp.validation.method.result'], 'conflict');
    assert.notEqual(evt['mcp.validation.method.result'], 'malformed');
    assert.notEqual(evt['mcp.validation.name.result'], 'conflict');
    assert.notEqual(evt['mcp.validation.name.result'], 'malformed');
  }
});

test('Track 1: "missing" (compatibility) is distinguished from "conflict" -- version_incompatible cases roll up to valid', () => {
  const { byScenario } = readAllScenarioEvents();
  const n13 = byScenario.get('N13');
  assert.ok(n13, 'scenario N13 (compatibility) must exist');
  const validation = n13.events.find((e) => e['event.name'] === 'mcp.request.validation');
  assert.equal(validation['mcp.validation.method.result'], 'version_incompatible');
  assert.equal(validation['mcp.validation.name.result'], 'version_incompatible');
  assert.equal(validation['mcp.validation.result'], 'valid');
  assert.equal(n13.manifest.expected_detection_track_1, false);
});

test('Track 1: every hash-bearing event carries security.hash.key_id and security.hash.algorithm', () => {
  const { allEvents } = readAllScenarioEvents();
  for (const evt of allEvents) {
    const hasHash = Object.keys(evt).some((k) => k.endsWith('_hash') && evt[k] !== null);
    if (hasHash) {
      assert.ok(evt['security.hash.key_id'], `missing security.hash.key_id on ${evt['event.name']}`);
      assert.ok(evt['security.hash.algorithm'], `missing security.hash.algorithm on ${evt['event.name']}`);
    }
  }
});
