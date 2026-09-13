'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const { readAllScenarioEvents } = require('./helpers');

const VALID_REASONS = new Set([
  'authorized_owner', 'authorized_grant', 'principal_mismatch',
  'insufficient_scope', 'context_unbound', 'policy_denied', 'unknown'
]);

// Track 2 invariant (docs/state-invariants.md row 4-5; telemetry/correlation.md Track 2
// section, as patched): authorization decisions must come from mcp.authz.decision/reason,
// and a null mcp.task.authz_context_id_hash must never, by itself, indicate a violation.

test('Track 2: every mcp.task.authorization event carries a decision, boolean mirror, and a recognized reason', () => {
  const { allEvents } = readAllScenarioEvents();
  const authz = allEvents.filter((e) => e['event.name'] === 'mcp.task.authorization');
  assert.ok(authz.length > 0);
  for (const evt of authz) {
    assert.ok(['allow', 'deny'].includes(evt['mcp.authz.decision']));
    assert.equal(evt['mcp.authz.allowed'], evt['mcp.authz.decision'] === 'allow');
    assert.ok(VALID_REASONS.has(evt['mcp.authz.reason']), `unrecognized reason: ${evt['mcp.authz.reason']}`);
  }
});

test('Track 2: no normal-corpus event allows access while its own reason says it should not', () => {
  const { allEvents } = readAllScenarioEvents();
  const authz = allEvents.filter((e) => e['event.name'] === 'mcp.task.authorization');
  for (const evt of authz) {
    // A decision of "allow" combined with a violation-shaped reason would itself BE the
    // Track 2 finding this corpus must not contain.
    if (evt['mcp.authz.decision'] === 'allow') {
      assert.ok(
        ['authorized_owner', 'authorized_grant'].includes(evt['mcp.authz.reason']),
        `allow decision with non-legitimate reason ${evt['mcp.authz.reason']}`
      );
    }
  }
});

test('Track 2: legitimate shared access (N6) uses distinct principals with distinguishing reasons, both allowed', () => {
  const { byScenario } = readAllScenarioEvents();
  const n6 = byScenario.get('N6');
  assert.ok(n6);
  const authz = n6.events.filter((e) => e['event.name'] === 'mcp.task.authorization');
  assert.equal(authz.length, 2);
  const principals = new Set(authz.map((e) => e['principal.id_hash']));
  assert.equal(principals.size, 2, 'N6 must involve two distinct principals');
  assert.ok(authz.every((e) => e['mcp.authz.decision'] === 'allow'));
  const reasons = new Set(authz.map((e) => e['mcp.authz.reason']));
  assert.ok(reasons.has('authorized_owner'));
  assert.ok(reasons.has('authorized_grant'));
});

test('Track 2: absence of authorization-context telemetry alone does not fail the test / does not force a deny', () => {
  const { allEvents } = readAllScenarioEvents();
  const nullContext = allEvents.filter(
    (e) => e['event.name'] === 'mcp.task.authorization' && e['mcp.task.authz_context_id_hash'] === null
  );
  assert.ok(nullContext.length > 0, 'corpus should include at least one null-context case (N12, N7c)');
  for (const evt of nullContext) {
    // The test only requires that decision/reason are still present and self-consistent --
    // it must NOT assert deny, and must NOT assert the record is invalid, purely because
    // the context hash is null.
    assert.ok(['allow', 'deny'].includes(evt['mcp.authz.decision']));
    assert.ok(VALID_REASONS.has(evt['mcp.authz.reason']));
  }
});

test('Track 2: benign denials (N7) are not shaped like cross-principal violations', () => {
  const { byScenario } = readAllScenarioEvents();
  const n7 = byScenario.get('N7');
  assert.ok(n7);
  const authz = n7.events.filter((e) => e['event.name'] === 'mcp.task.authorization');
  assert.equal(authz.length, 3);
  for (const evt of authz) {
    assert.equal(evt['mcp.authz.decision'], 'deny');
    assert.notEqual(evt['mcp.authz.reason'], 'principal_mismatch');
  }
  assert.equal(n7.manifest.expected_detection_track_2, false);
});
