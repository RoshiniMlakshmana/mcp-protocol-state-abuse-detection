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

test('V11-05: revocation fires with no retained open event at all', () => {
  const p = hmacHash('principal:alice-v11-05');
  const rows = highRows(byId('V11-05').events).map(stripUndefined);
  assert.equal(byId('V11-05').events.some((e) => e['event.name'] === 'mcp.subscription.open'), false, 'fixture must genuinely have no open event');
  assert.deepEqual(rows, [
    { subscription_id: '10005', principal_hash: p, notif_time: '2026-10-01T19:05:00.000Z', boundary: 'effective_at', boundary_time: '2026-10-01T19:00:00.000Z' },
  ]);
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

test('V11-11: known, unresolved cross-subscription risk -- mechanically fires on the still-valid subscription\'s notification', () => {
  const p = hmacHash('principal:alice-v11-11');
  const rows = highRows(byId('V11-11').events).map(stripUndefined);
  assert.deepEqual(rows, [
    { subscription_id: '10013', principal_hash: p, notif_time: '2026-10-01T20:50:00.000Z', boundary: 'effective_at', boundary_time: '2026-10-01T20:45:00.000Z' },
  ], 'documents the mechanical (unresolved) behavior -- this is a reported risk, not a bug being silently patched over');
});

// ---------------------------------------------------------------------------------------------
// Proof that these regression tests actually catch a reintroduction of the two named bugs:
// join-key restoration (subscription_id-only close/expiry join) and one-match (Splunk max=1
// default) behavior. Re-derives the OLD, buggy behavior independently here (not by importing
// computeTrack3AlertRows and disabling a flag), then shows it disagrees with the fixed oracle's
// rows on the exact fixtures designed to expose each bug.
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
