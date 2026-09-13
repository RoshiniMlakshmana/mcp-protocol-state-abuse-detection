'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const { loadUnifiedCorpus } = require('./corpus');
const { track1PrimaryFires, track1DiagnosticFires, track2Fires, track3PrimaryFires, track3SigmaCorrelationFires } = require('./oracle');
const { evaluate, formatReport } = require('./metrics');

const rows = loadUnifiedCorpus();

test('Corpus sanity: 31 scenarios loaded (13 Block 3 + 18 Block 4), 200 total events (106 + 94)', () => {
  assert.equal(rows.length, 31);
  const block3 = rows.filter((r) => r.source === 'block3_normal');
  const block4 = rows.filter((r) => r.source === 'block4_attack');
  assert.equal(block3.length, 13);
  assert.equal(block4.length, 18);
  const block3Events = block3.reduce((n, r) => n + r.events.length, 0);
  // A11 (block4) reuses the same file as N6 (block3) -- its events are counted once in each
  // manifest's own total by design (they are two independent ground-truth assertions over the
  // same underlying data), so the raw event sum below double-counts N6's 9 events once.
  const block4Events = block4.reduce((n, r) => n + r.events.length, 0);
  assert.equal(block3Events, 106, 'Block 3 corpus must still be exactly 106 events (locked)');
  assert.equal(block4Events, 94, 'Block 4 corpus must still be exactly 94 events (locked, including the reused A11 pointer)');
});

test('Detection 1 (primary, high-confidence): matches required behavior exactly', () => {
  const result = evaluate(rows, track1PrimaryFires, 'expected1');
  console.log('\n' + formatReport('Track 1 PRIMARY (conflict only)', result));
  assert.equal(result.fn, 0, 'no required Track 1 positive may be missed');
  assert.equal(result.fp, 0, 'no normal/control scenario may be misclassified as Track 1');
  // Explicit required-behavior spot checks (not just aggregate counts):
  for (const id of ['A1', 'A2', 'A3', 'A4', 'A5', 'A17']) {
    assert.equal(track1PrimaryFires(rows.find((r) => r.scenario_id === id).events), true, `${id} must alert`);
  }
  for (const id of ['A6', 'A11']) {
    assert.equal(track1PrimaryFires(rows.find((r) => r.scenario_id === id).events), false, `${id} must not alert on Track 1`);
  }
  for (const row of rows.filter((r) => r.source === 'block3_normal')) {
    assert.equal(track1PrimaryFires(row.events), false, `normal scenario ${row.scenario_id} must not alert on Track 1`);
  }
});

test('Detection 1 (diagnostic): correctly separated from the primary rule', () => {
  // No manifest field represents "expected diagnostic hit" (it is intentionally a separate,
  // lower rule with no dedicated ground truth of its own), so no confusion-matrix report is
  // printed here -- only the two behavioral guarantees that actually matter are asserted.
  // A6 is version_incompatible, NOT "missing" -- the diagnostic rule must not fire on it either.
  assert.equal(track1DiagnosticFires(rows.find((r) => r.scenario_id === 'A6').events), false);
  // Nothing in the current corpus exercises a genuine "missing" (as opposed to
  // version_incompatible) case, so the diagnostic rule legitimately fires on zero scenarios
  // here -- this is a documented corpus limitation, not a rule defect (see detections/README.md).
  const anyDiagnosticHits = rows.filter((r) => track1DiagnosticFires(r.events));
  assert.equal(anyDiagnosticHits.length, 0, 'no current fixture exercises a genuine "missing" routing header case');
});

test('Detection 2: matches required behavior exactly', () => {
  const result = evaluate(rows, track2Fires, 'expected2');
  console.log('\n' + formatReport('Track 2', result));
  assert.equal(result.fn, 0);
  assert.equal(result.fp, 0);
  for (const id of ['A7', 'A8', 'A9', 'A10', 'A17']) {
    assert.equal(track2Fires(rows.find((r) => r.scenario_id === id).events), true, `${id} must alert`);
  }
  for (const id of ['A11']) {
    assert.equal(track2Fires(rows.find((r) => r.scenario_id === id).events), false, `${id} (reused N6) must not alert`);
  }
  const n6 = rows.find((r) => r.scenario_id === 'N6' && r.source === 'block3_normal');
  assert.equal(track2Fires(n6.events), false, 'N6 must not alert directly either');
  const n7 = rows.find((r) => r.scenario_id === 'N7');
  assert.equal(track2Fires(n7.events), false, 'N7 (benign denials unrelated to cross-principal misuse) must not alert');
});

test('Detection 3 (primary, KQL/SPL-faithful): matches required behavior exactly', () => {
  const result = evaluate(rows, track3PrimaryFires, 'expected3');
  console.log('\n' + formatReport('Track 3 PRIMARY (KQL/SPL, all non-experimental scenarios)', result));
  const nonExperimental = rows.filter((r) => !r.experimental);
  const resultCore = evaluate(nonExperimental, track3PrimaryFires, 'expected3');
  console.log(formatReport('Track 3 PRIMARY (excluding experimental A-EXP1)', resultCore));
  assert.equal(resultCore.fn, 0);
  assert.equal(resultCore.fp, 0);
  for (const id of ['A12', 'A13', 'A14']) {
    assert.equal(track3PrimaryFires(rows.find((r) => r.scenario_id === id).events), true, `${id} must alert (high confidence)`);
  }
  for (const id of ['A15', 'A16']) {
    assert.equal(track3PrimaryFires(rows.find((r) => r.scenario_id === id).events), false, `${id} must not produce a high-confidence alert`);
  }
  for (const row of rows.filter((r) => r.source === 'block3_normal')) {
    assert.equal(track3PrimaryFires(row.events), false, `normal scenario ${row.scenario_id} must not alert on Track 3`);
  }
  // A-EXP1 is expected3=true and mechanically follows the same authoritative-revocation path
  // as A12, so the KQL/SPL logic correctly fires on it too -- reported separately, not folded
  // into the "official" required-behavior assertions above, since it is explicitly experimental.
  assert.equal(track3PrimaryFires(rows.find((r) => r.scenario_id === 'A-EXP1').events), true);
});

test('Sigma correlation (documented limitation): reproduces exactly the false negatives described in mcp_subscription_drift_correlation.yml', () => {
  assert.equal(track3SigmaCorrelationFires(rows.find((r) => r.scenario_id === 'A12').events), true, 'A12: Sigma correlation DOES correctly match (in-order case)');
  assert.equal(track3SigmaCorrelationFires(rows.find((r) => r.scenario_id === 'A13').events), false, 'A13: Sigma correlation cannot match -- no authorization_change event exists at all');
  assert.equal(track3SigmaCorrelationFires(rows.find((r) => r.scenario_id === 'A14').events), false, 'A14: Sigma correlation misses this -- notification is logged before the change event');
  assert.equal(track3SigmaCorrelationFires(rows.find((r) => r.scenario_id === 'A15').events), false, 'A15: correctly excluded (not authoritative)');
  assert.equal(track3SigmaCorrelationFires(rows.find((r) => r.scenario_id === 'A16').events), false, 'A16: correctly excluded (no notification after the change)');
});

test('Combined scenario A17: both Track 1 and Track 2 rules fire; Track 3 does not', () => {
  const a17 = rows.find((r) => r.scenario_id === 'A17');
  assert.equal(track1PrimaryFires(a17.events), true);
  assert.equal(track2Fires(a17.events), true);
  assert.equal(track3PrimaryFires(a17.events), false);
});
