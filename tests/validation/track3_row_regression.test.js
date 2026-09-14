'use strict';
/**
 * Row-level regression tests for the Track 3 remediation pass (see docs/validation-report.md).
 * Unlike metrics.test.js and track3.test.js (which only check the collapsed boolean via
 * track3PrimaryFires/computeTrack3Verdict), these tests compare the ACTUAL alert ROWS produced
 * by computeTrack3AlertRows against independently-specified expected rows -- required whenever
 * a fixture has more than one notification, boundary, or principal, since a boolean cannot
 * distinguish "fired once, correctly" from "fired zero times, or twice, for the wrong reason".
 *
 * Each fixture here also proves the specific fix it targets actually matters -- see the
 * "restoring the bug" tests at the bottom of this file, which use tests/attack/track3util.js's
 * own OLD, buggy behavior model (re-derived independently here, not imported from the fixed
 * oracle) to show these tests would have failed before this pass's fixes.
 */
const test = require('node:test');
const assert = require('node:assert/strict');
const { loadValidationCorpus } = require('../detections/corpus');
const { computeTrack3AlertRows } = require('../attack/track3util');
const { hmacHash } = require('../../tools/harness/lib/hash');

function byId(id) {
  const rows = loadValidationCorpus();
  const r = rows.find((x) => x.scenario_id === id);
  assert.ok(r, `fixture ${id} must exist in data/validation/manifest.jsonl`);
  return r;
}

function highRows(events) {
  return computeTrack3AlertRows(events).filter((r) => r.confidence === 'high');
}

function stripUndefined(row) {
  const { subscription_id, principal_hash, notif_time, boundary, boundary_time } = row;
  return { subscription_id, principal_hash, notif_time, boundary, boundary_time };
}

test('V11-01: out-of-order multiple changes -- first notification matches only the earlier-effective_at change, second matches both', () => {
  const p = hmacHash('principal:alice-v11-01');
  const rows = highRows(byId('V11-01').events).map(stripUndefined);
  const n1 = rows.filter((r) => r.notif_time === '2026-10-01T17:30:00.000Z');
  const n2 = rows.filter((r) => r.notif_time === '2026-10-01T18:30:00.000Z');
  assert.deepEqual(n1, [
    { subscription_id: '10001', principal_hash: p, notif_time: '2026-10-01T17:30:00.000Z', boundary: 'effective_at', boundary_time: '2026-10-01T17:07:00.000Z' },
  ]);
  assert.deepEqual(n2.sort((a, b) => a.boundary_time.localeCompare(b.boundary_time)), [
    { subscription_id: '10001', principal_hash: p, notif_time: '2026-10-01T18:30:00.000Z', boundary: 'effective_at', boundary_time: '2026-10-01T17:07:00.000Z' },
    { subscription_id: '10001', principal_hash: p, notif_time: '2026-10-01T18:30:00.000Z', boundary: 'effective_at', boundary_time: '2026-10-01T18:00:00.000Z' },
  ]);
  assert.equal(rows.length, 3, 'exactly 3 high-confidence rows total across both notifications');
});

test('V11-02: same subscription_id, different principals -- only Alice\'s notification produces a row; Bob\'s own close does not suppress it', () => {
  const pA = hmacHash('principal:alice-v11-02');
  const pB = hmacHash('principal:bob-v11-02');
  const rows = highRows(byId('V11-02').events).map(stripUndefined);
  assert.deepEqual(rows, [
    { subscription_id: '10002', principal_hash: pA, notif_time: '2026-10-01T17:55:00.000Z', boundary: 'effective_at', boundary_time: '2026-10-01T17:45:00.000Z' },
  ]);
  assert.ok(!rows.some((r) => r.principal_hash === pB), 'Bob (unrevoked) must never appear as a violating row');
});

test('V11-03: revocation and expiry both applicable to the same notification -- two independent rows', () => {
  const p = hmacHash('principal:alice-v11-03');
  const rows = highRows(byId('V11-03').events).map(stripUndefined);
  assert.deepEqual(rows.sort((a, b) => a.boundary.localeCompare(b.boundary)), [
    { subscription_id: '10003', principal_hash: p, notif_time: '2026-10-01T18:20:00.000Z', boundary: 'effective_at', boundary_time: '2026-10-01T18:03:00.000Z' },
    { subscription_id: '10003', principal_hash: p, notif_time: '2026-10-01T18:20:00.000Z', boundary: 'valid_until', boundary_time: '2026-10-01T18:10:00.000Z' },
  ]);
});

test('V11-04: expiry precedes a later-recorded, future revocation -- independent per-notification results', () => {
  const p = hmacHash('principal:alice-v11-04');
  const rows = highRows(byId('V11-04').events).map(stripUndefined);
  const n1 = rows.filter((r) => r.notif_time === '2026-10-01T18:36:00.000Z');
  const n2 = rows.filter((r) => r.notif_time === '2026-10-01T18:50:00.000Z');
  assert.deepEqual(n1, [
    { subscription_id: '10004', principal_hash: p, notif_time: '2026-10-01T18:36:00.000Z', boundary: 'valid_until', boundary_time: '2026-10-01T18:35:00.000Z' },
  ]);
  assert.deepEqual(n2.sort((a, b) => a.boundary.localeCompare(b.boundary)), [
    { subscription_id: '10004', principal_hash: p, notif_time: '2026-10-01T18:50:00.000Z', boundary: 'effective_at', boundary_time: '2026-10-01T18:45:00.000Z' },
    { subscription_id: '10004', principal_hash: p, notif_time: '2026-10-01T18:50:00.000Z', boundary: 'valid_until', boundary_time: '2026-10-01T18:35:00.000Z' },
  ]);
});

test('V11-05 (RECLASSIFIED, ambiguous legacy telemetry): no retained open event AND no scope evidence now reports insufficient_evidence, not confirmed_drift', () => {
  const events = byId('V11-05').events;
  assert.equal(events.some((e) => e['event.name'] === 'mcp.subscription.open'), false, 'fixture must genuinely have no open event');
  assert.deepEqual(highRows(events), [], 'no confirmed_drift rows -- this is the exact principal-only join the scope-aware correction forbids');
  const { track3Resolution } = require('../detections/oracle');
  const { results, coverage } = track3Resolution(events);
  assert.equal(coverage.insufficientEvidence, 1);
  assert.equal(results[0].outcome, 'insufficient_evidence');
  assert.equal(results[0].reason, 'ambiguous_scope', 'the revocation timing crosses, but its scope is unknown (legacy shape) -- never inferred from candidate count, per example #6');
});

test('V11-06: a close on a DIFFERENT subscription_id (same principal) does not suppress the still-open one', () => {
  const p = hmacHash('principal:alice-v11-06');
  const rows = highRows(byId('V11-06').events).map(stripUndefined);
  assert.deepEqual(rows, [
    { subscription_id: '10006', principal_hash: p, notif_time: '2026-10-01T19:25:00.000Z', boundary: 'effective_at', boundary_time: '2026-10-01T19:20:00.000Z' },
  ]);
});

test('V11-07: close exactly at notification time suppresses it (inclusive close boundary)', () => {
  assert.deepEqual(highRows(byId('V11-07').events), []);
});

test('V11-08: notification exactly at valid_until does not fire (exclusive invalidation boundary, expiry leg)', () => {
  assert.deepEqual(highRows(byId('V11-08').events), []);
});

test('V11-09: scope_upgraded plus not-yet-reached valid_until produces zero rows', () => {
  assert.deepEqual(highRows(byId('V11-09').events), []);
});

test('V11-10: duplicate close events -- notification before both closes fires, notification after is suppressed', () => {
  const p = hmacHash('principal:alice-v11-10');
  const rows = highRows(byId('V11-10').events).map(stripUndefined);
  assert.equal(byId('V11-10').events.filter((e) => e['event.name'] === 'mcp.subscription.close').length, 2, 'fixture must contain two duplicate close events');
  assert.deepEqual(rows, [
    { subscription_id: '10011', principal_hash: p, notif_time: '2026-10-01T20:27:00.000Z', boundary: 'effective_at', boundary_time: '2026-10-01T20:25:00.000Z' },
  ]);
});

test('V11-11 (RECLASSIFIED, retained as ambiguous legacy telemetry): two concurrent bindings, no scope evidence -- both instances report insufficient_evidence, never a principal-only confirmed fire', () => {
  const events = byId('V11-11').events;
  assert.deepEqual(highRows(events), [], 'the scope-aware correction never falls back to a principal-only confirmed-drift join');
  const { track3Resolution } = require('../detections/oracle');
  const { results, coverage } = track3Resolution(events);
  assert.equal(coverage.insufficientEvidence, 1, 'exactly one notification exists in this fixture (on subscription B)');
  assert.equal(results[0].subscriptionId, '10013');
  assert.equal(results[0].outcome, 'insufficient_evidence');
  assert.equal(results[0].reason, 'ambiguous_scope', 'two candidate bindings exist for this principal at the change\'s effective_at, and the change names neither explicitly');
});

test('V12-13: the corrected counterpart to V11-11 -- explicit affected_binding_ids resolves the identical two-concurrent-subscription shape cleanly', () => {
  const { track3Resolution } = require('../detections/oracle');
  const events = byId('V12-13').events;
  const { results } = track3Resolution(events);
  const confirmed = results.filter((r) => r.outcome === 'confirmed_drift');
  const noViolation = results.filter((r) => r.outcome === 'evaluated_no_violation');
  assert.equal(confirmed.length, 1, 'exactly the revoked binding\'s subscription confirms drift');
  assert.equal(noViolation.length, 1, 'the untouched binding\'s subscription is definitively cleared, not left ambiguous');
  assert.notEqual(confirmed[0].subscriptionId, noViolation[0].subscriptionId);
});

// ---------------------------------------------------------------------------------------------
// Example-driven regression tests (this pass) -- see docs/validation-report.md "Track 3
// remediation pass, part 3" for the ten independently-specified examples these instantiate.
// ---------------------------------------------------------------------------------------------

test('V13-01 (EXAMPLE #4): confirmed drift during a genuinely invalid interval survives a later, unrelated renewal', () => {
  const { track3Resolution } = require('../detections/oracle');
  const events = byId('V13-01').events;
  const { results } = track3Resolution(events);
  const first = results.find((r) => r.notifTime === '2026-10-03T09:10:00.000Z');
  const second = results.find((r) => r.notifTime === '2026-10-03T09:20:00.000Z');
  assert.ok(first, 'the first notification must produce a result');
  assert.equal(first.outcome, 'confirmed_drift');
  assert.ok(second, 'the second (later, rebound) notification must produce a result');
  assert.equal(second.outcome, 'evaluated_no_violation', 'proven rebinding to a new, valid binding clears the later notification');
  // The critical assertion: the SECOND, clean notification's evaluation must not have altered
  // the FIRST notification's already-computed outcome (each is independent).
  assert.equal(first.outcome, 'confirmed_drift', 'the later renewal must not retroactively erase the earlier confirmed finding');
});

test('V13-02 (EXAMPLE #5, earlier direction): a binding revoked BEFORE the tested subscription even opened must not affect it', () => {
  const rows = highRows(byId('V13-02').events);
  assert.deepEqual(rows, [], 'the earlier, unrelated, explicitly-named binding revocation must not leak into the later, different binding');
});

test('V13-03 (EXAMPLE #6): unknown scope with exactly ONE observed candidate still reports insufficient_evidence, never confirmed_drift', () => {
  const { track3Resolution } = require('../detections/oracle');
  const events = byId('V13-03').events;
  assert.equal(events.filter((e) => e['event.name'] === 'mcp.subscription.open').length, 1, 'fixture must have exactly one subscription/candidate for this principal');
  const { results, coverage } = track3Resolution(events);
  assert.equal(coverage.confirmedDrift, 0, 'candidate count of exactly one must never substitute for scope evidence');
  assert.equal(coverage.insufficientEvidence, 1);
  assert.equal(results[0].reason, 'ambiguous_scope');
});

test('V13-04 (EXAMPLE #9, same-principal reopen): a revocation on the OLD instance must not affect the NEW instance after a wire-id reopen', () => {
  const rows = highRows(byId('V13-04').events);
  assert.deepEqual(rows, [], 'the new instance (new instance_id, new binding) is unaffected by the old instance\'s revocation, despite reusing the same wire subscription_id');
});

test('V13-05 (EXAMPLE #10, timing-specific): "authoritative" timing with no effective_at is incomplete evidence, not silently "does not apply"', () => {
  const { track3Resolution } = require('../detections/oracle');
  const events = byId('V13-05').events;
  const { results, coverage } = track3Resolution(events);
  assert.equal(coverage.confirmedDrift, 0);
  assert.equal(coverage.insufficientEvidence, 1);
  assert.equal(results[0].reason, 'incomplete_timing_evidence');
});

test('V13-06 (precise effective-time interval): an all_principal_bindings revocation confirms on the pre-existing binding, but not on a binding issued afterward', () => {
  const { track3Resolution } = require('../detections/oracle');
  const events = byId('V13-06').events;
  const { results } = track3Resolution(events);
  const confirmed = results.filter((r) => r.outcome === 'confirmed_drift');
  const noViolation = results.filter((r) => r.outcome === 'evaluated_no_violation');
  assert.equal(confirmed.length, 1, 'only the pre-existing binding, open at effective_at, confirms');
  assert.equal(confirmed[0].subscriptionId, '30008');
  assert.equal(noViolation.length, 1, 'the binding issued AFTER effective_at is definitively cleared, not confirmed');
  assert.equal(noViolation[0].subscriptionId, '30009');
});

// ---------------------------------------------------------------------------------------------
// Proof that these regression tests actually catch a reintroduction of THREE named bugs:
// join-key restoration (subscription_id-only close/expiry join), one-match (Splunk max=1
// default) behavior, and the sole-candidate scope inference removed in this pass. Re-derives
// each OLD, buggy behavior independently here (not by importing computeTrack3AlertRows and
// disabling a flag), then shows it disagrees with the fixed oracle's rows on the exact fixtures
// designed to expose each bug.
// ---------------------------------------------------------------------------------------------

function oldBuggyCloseSuppressed(events, notif) {
  // PRE-FIX: close suppression joined on subscription_id ALONE.
  const closes = events.filter((e) => e['event.name'] === 'mcp.subscription.close');
  return closes.some((c) => c['mcp.subscription.id'] === notif['mcp.subscription.id'] && c.timestamp <= notif.timestamp);
}

function oldBuggyOneMatchOnly(events, notif) {
  // PRE-FIX (mirrors Splunk's `join` max=1 default): only the FIRST matching authoritative
  // change for this principal is considered, instead of every applicable one.
  const changes = events.filter((e) =>
    e['event.name'] === 'mcp.subscription.authorization_change' &&
    e['mcp.authz.change.timing_confidence'] === 'authoritative' &&
    e['mcp.authz.change.effective_at'] &&
    ['revoked', 'expired', 'scope_downgraded'].includes(e['mcp.authz.change.type'])
  );
  const firstMatch = changes.find((c) => c['principal.id_hash'] === notif['principal.id_hash']);
  return firstMatch && notif.timestamp > firstMatch['mcp.authz.change.effective_at'] ? [firstMatch] : [];
}

test('RESTORED-BUG PROOF: reverting the close-join to subscription_id-only would wrongly suppress V11-02\'s genuine violation', () => {
  const events = byId('V11-02').events;
  const aliceNotif = events.find((e) => e['event.name'] === 'mcp.subscription.notification' && e.timestamp === '2026-10-01T17:55:00.000Z');
  assert.ok(aliceNotif, 'must find Alice\'s notification');
  // The FIXED oracle (this pass) does not suppress it:
  const fixedRows = highRows(events).filter((r) => r.notif_time === '2026-10-01T17:55:00.000Z');
  assert.equal(fixedRows.length, 1, 'fixed behavior: Alice\'s violation fires');
  // The OLD, buggy subscription_id-only close join WOULD have suppressed it (Bob\'s close on
  // the same subscription_id string incorrectly matches):
  assert.equal(oldBuggyCloseSuppressed(events, aliceNotif), true, 'pre-fix bug: Bob\'s close on the shared subscription_id would have wrongly suppressed Alice\'s real violation');
});

test('RESTORED-BUG PROOF: a max=1-style first-match-only join would silently drop one of V11-01\'s two independently-applicable revocation boundaries', () => {
  const events = byId('V11-01').events;
  const n2 = events.find((e) => e['event.name'] === 'mcp.subscription.notification' && e.timestamp === '2026-10-01T18:30:00.000Z');
  assert.ok(n2, 'must find the second notification (after both boundaries)');
  // The FIXED oracle (iterates every applicable change, mirroring KQL's whole-table join /
  // SPL's `max=0`) finds BOTH changes for this notification:
  const fixedRows = highRows(events).filter((r) => r.notif_time === '2026-10-01T18:30:00.000Z');
  assert.equal(fixedRows.length, 2, 'fixed behavior: both applicable authorization_change events produce independent rows');
  // The OLD, buggy "first match only" behavior (mirroring Splunk's join max=1 default) would
  // have kept only ONE of them -- silently dropping the other applicable boundary.
  const buggyRows = oldBuggyOneMatchOnly(events, n2);
  assert.equal(buggyRows.length, 1, 'pre-fix bug: max=1-style behavior keeps only the first matching change, not both');
});

function oldBuggySoleCandidateInference(events, notif) {
  // PRE-FIX (this pass): an `unknown`-scope change was resolved to a confirmed finding whenever
  // exactly ONE binding was observable for that principal -- independently re-derived here, not
  // imported from the (now-corrected) resolver.
  const opens = events.filter((e) => e['event.name'] === 'mcp.subscription.open' && e['principal.id_hash'] === notif['principal.id_hash']);
  const changes = events.filter((e) =>
    e['event.name'] === 'mcp.subscription.authorization_change' &&
    e['principal.id_hash'] === notif['principal.id_hash'] &&
    e['mcp.authz.change.timing_confidence'] === 'authoritative' &&
    e['mcp.authz.change.effective_at'] &&
    ['revoked', 'expired', 'scope_downgraded'].includes(e['mcp.authz.change.type']) &&
    !e['mcp.authz.change.affected_scope'] // legacy/unknown scope only
  );
  if (opens.length !== 1) return false; // the old inference only ever applied for exactly one candidate
  return changes.some((c) => notif.timestamp > c['mcp.authz.change.effective_at']);
}

test('RESTORED-BUG PROOF: a sole-candidate scope inference would wrongly confirm V13-03 and V6-02, both now correctly insufficient_evidence', () => {
  for (const id of ['V13-03', 'V6-02']) {
    const events = byId(id).events;
    const notif = events.find((e) => e['event.name'] === 'mcp.subscription.notification');
    assert.ok(notif, `${id} must have a notification`);
    // The FIXED resolver never confirms via candidate-count inference:
    const fixedRows = highRows(events);
    assert.equal(fixedRows.length, 0, `${id}: fixed behavior reports no confirmed_drift row`);
    // The OLD, removed sole-candidate inference WOULD have confirmed it:
    assert.equal(oldBuggySoleCandidateInference(events, notif), true, `${id}: pre-fix sole-candidate inference would have wrongly confirmed this`);
  }
});
