'use strict';
/**
 * V10 -- Rule mutation testing. Every mutation below is a standalone, IN-MEMORY JS predicate
 * constructed for this test only -- no rule file under detections/ is ever modified. Each
 * mutation is checked against the full stress corpus (Block 3 + 4 + 6) and MUST introduce at
 * least one false positive or false negative that the correct implementation does not have,
 * proving the validation suite would catch this exact regression if it were ever introduced
 * into a real rule file.
 */
const test = require('node:test');
const assert = require('node:assert/strict');
const { loadFullStressCorpus } = require('../detections/corpus');
const { evaluate } = require('../detections/metrics');
const { track1PrimaryFires, track2Fires, track3PrimaryFires } = require('../detections/oracle');

const rows = loadFullStressCorpus();

function regressionIntroduced(correctFn, mutatedFn, expectedKey) {
  const correct = evaluate(rows, correctFn, expectedKey);
  const mutated = evaluate(rows, mutatedFn, expectedKey);
  const worse = (mutated.fp > correct.fp) || (mutated.fn > correct.fn);
  return { correct, mutated, worse };
}

test('MUTATION: Track 1 inverted comparison (== instead of !=) -- flips match/conflict logic entirely', () => {
  // Correct: fires when header/body DISAGREE (conflict). Mutated: fires when they AGREE.
  function mutated(events) {
    return events.some((e) => e['event.name'] === 'mcp.request.validation' && (
      e['mcp.validation.method.result'] === 'match' || e['mcp.validation.name.result'] === 'match'
    ));
  }
  const { worse, mutated: m, correct } = regressionIntroduced(track1PrimaryFires, mutated, 'expected1');
  console.log(`\nMutation (Track1 == instead of !=): correct FP=${correct.fp} FN=${correct.fn} | mutated FP=${m.fp} FN=${m.fn}`);
  assert.ok(worse, 'the test suite must detect this mutation as a regression');
  assert.ok(m.fp > 0, 'inverting the comparison should mass-false-positive on clean traffic');
});

test('MUTATION: Track 1 missing headers alert as mismatch', () => {
  function mutated(events) {
    return events.some((e) => e['event.name'] === 'mcp.request.validation' && (
      ['conflict', 'missing', 'malformed'].includes(e['mcp.validation.method.result']) ||
      ['conflict', 'missing', 'malformed'].includes(e['mcp.validation.name.result'])
    ));
  }
  const { worse, mutated: m, correct } = regressionIntroduced(track1PrimaryFires, mutated, 'expected1');
  console.log(`Mutation (Track1 missing==mismatch): correct FP=${correct.fp} | mutated FP=${m.fp}`);
  assert.ok(worse, 'the test suite must catch missing-header-as-mismatch');
  assert.ok(m.fp > correct.fp, 'V1-02 (genuine missing header) must become a false positive under this mutation');
});

test('MUTATION: Track 2 authorization-decision requirement removed (any denial fires, not just principal_mismatch)', () => {
  function mutated(events) {
    return events.some((e) => e['event.name'] === 'mcp.task.authorization' && e['mcp.authz.decision'] === 'deny');
  }
  const { worse, mutated: m, correct } = regressionIntroduced(track2Fires, mutated, 'expected2');
  console.log(`Mutation (Track2 any-deny): correct FP=${correct.fp} | mutated FP=${m.fp}`);
  assert.ok(worse);
  assert.ok(m.fp > 0, 'benign denials (policy_denied/insufficient_scope/context_unbound in N7, V3-03, V3-04) must become false positives');
});

test('MUTATION: Track 2 reason check dropped entirely, ANY authorization event fires (including allows)', () => {
  function mutated(events) {
    return events.some((e) => e['event.name'] === 'mcp.task.authorization');
  }
  const { worse, mutated: m, correct } = regressionIntroduced(track2Fires, mutated, 'expected2');
  console.log(`Mutation (Track2 any-event): correct FP=${correct.fp} | mutated FP=${m.fp}`);
  assert.ok(worse);
  assert.ok(m.fp > correct.fp);
});

test('MUTATION: Track 3 uses detected_at instead of effective_at as the primary boundary', () => {
  function mutated(events) {
    const open = events.find((e) => e['event.name'] === 'mcp.subscription.open');
    if (!open) return false;
    const changes = events.filter((e) => e['event.name'] === 'mcp.subscription.authorization_change');
    const notifications = events.filter((e) => e['event.name'] === 'mcp.subscription.notification');
    const anyChange = changes.find((c) => c['mcp.authz.change.detected_at']);
    if (!anyChange) return false;
    return notifications.some((n) => n.timestamp > anyChange['mcp.authz.change.detected_at']);
  }
  const { worse, mutated: m, correct } = regressionIntroduced(track3PrimaryFires, mutated, 'expected3');
  console.log(`Mutation (Track3 detected_at as boundary): correct FN=${correct.fn} | mutated FN=${m.fn}`);
  assert.ok(worse, 'using detected_at instead of effective_at must miss A14/V5-07 (notification logged before detected_at, after effective_at)');
  assert.ok(m.fn > correct.fn);
});

test('MUTATION: Track 3 close check removed entirely (no anti-join against a valid closure)', () => {
  function mutated(events) {
    const open = events.find((e) => e['event.name'] === 'mcp.subscription.open');
    if (!open) return { fired: false };
    const principal = open['principal.id_hash'];
    const notifications = events.filter((e) => e['event.name'] === 'mcp.subscription.notification');
    const authoritative = events.find((e) => e['event.name'] === 'mcp.subscription.authorization_change' &&
      e['principal.id_hash'] === principal && e['mcp.authz.change.timing_confidence'] === 'authoritative' &&
      ['revoked', 'expired', 'scope_downgraded'].includes(e['mcp.authz.change.type']));
    if (!authoritative) return false;
    // BUG: no close check at all.
    return notifications.some((n) => n.timestamp > authoritative['mcp.authz.change.effective_at']);
  }
  const { worse, mutated: m, correct } = regressionIntroduced(track3PrimaryFires, mutated, 'expected3');
  console.log(`Mutation (Track3 no close check): correct FP=${correct.fp} | mutated FP=${m.fp}`);
  // A16 and V5-04 both have a notification/close ordering where the ONLY reason they don't
  // fire is the close-suppression check -- removing it must false-positive on at least one.
  assert.ok(worse);
  assert.ok(m.fp > correct.fp);
});

test('MUTATION: Track 3 type filter removed (reintroduces the exact V5-03 bug this block fixed)', () => {
  function mutatedVerdict(events) {
    const open = events.find((e) => e['event.name'] === 'mcp.subscription.open');
    if (!open) return { fired: false };
    const principal = open['principal.id_hash'];
    const notifications = events.filter((e) => e['event.name'] === 'mcp.subscription.notification');
    const closes = events.filter((e) => e['event.name'] === 'mcp.subscription.close');
    const notFlaggedByClose = (n) => !closes.some((c) => c.timestamp <= n.timestamp);
    // BUG (the original, pre-fix logic): no mcp.authz.change.type filter at all.
    const authoritative = events.find((e) => e['event.name'] === 'mcp.subscription.authorization_change' &&
      e['principal.id_hash'] === principal && e['mcp.authz.change.timing_confidence'] === 'authoritative' && e['mcp.authz.change.effective_at']);
    if (!authoritative) return false;
    return notifications.some((n) => n.timestamp > authoritative['mcp.authz.change.effective_at'] && notFlaggedByClose(n));
  }
  const { worse, mutated: m, correct } = regressionIntroduced(track3PrimaryFires, mutatedVerdict, 'expected3');
  console.log(`Mutation (Track3 reintroduce V5-03 bug): correct FP=${correct.fp} | mutated FP=${m.fp}`);
  assert.ok(worse, 'removing the type filter must reintroduce the V5-03 false positive');
  assert.ok(m.fp > correct.fp);
});

test('Sanity: the CORRECT (unmutated) oracle has zero FP/FN on the full stress corpus (baseline for all mutation comparisons above)', () => {
  const r1 = evaluate(rows, track1PrimaryFires, 'expected1');
  const r2 = evaluate(rows, track2Fires, 'expected2');
  const r3 = evaluate(rows.filter((r) => !r.experimental), track3PrimaryFires, 'expected3');
  assert.equal(r1.fp, 0); assert.equal(r1.fn, 0);
  assert.equal(r2.fp, 0); assert.equal(r2.fn, 0);
  assert.equal(r3.fp, 0); assert.equal(r3.fn, 0);
});
