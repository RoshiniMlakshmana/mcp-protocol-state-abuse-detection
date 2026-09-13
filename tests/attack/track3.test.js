'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const { readAllScenarios } = require('./helpers');
const { computeTrack3Verdict } = require('./track3util');

test('Track 3 (A12): notification after authoritative effective_at fires, high confidence', () => {
  const { byScenario } = readAllScenarios();
  const s = byScenario.get('A12');
  const v = computeTrack3Verdict(s.events);
  assert.equal(v.fired, true);
  assert.equal(v.confidence, 'high');
  assert.equal(v.boundaryUsed, 'effective_at');
  assert.equal(s.manifest.expected_detection_track_3, true);
});

test('Track 3 (A13): notification after mcp.authz.valid_until expires fires, even with no explicit revocation event', () => {
  const { byScenario } = readAllScenarios();
  const s = byScenario.get('A13');
  assert.equal(s.events.some((e) => e['event.name'] === 'mcp.subscription.authorization_change'), false, 'A13 must have no explicit revocation event -- silent expiry only');
  const v = computeTrack3Verdict(s.events);
  assert.equal(v.fired, true);
  assert.equal(v.boundaryUsed, 'valid_until');
  assert.equal(s.manifest.expected_detection_track_3, true);
});

test('Track 3 (A14): authoritative effective_at proves the violation even though detected_at arrived later', () => {
  const { byScenario } = readAllScenarios();
  const s = byScenario.get('A14');
  const change = s.events.find((e) => e['event.name'] === 'mcp.subscription.authorization_change');
  const notif = s.events.find((e) => e['event.name'] === 'mcp.subscription.notification');
  assert.ok(notif.timestamp < change['mcp.authz.change.detected_at'], 'the notification must precede detected_at in this fixture');
  assert.ok(notif.timestamp > change['mcp.authz.change.effective_at'], 'but must follow the authoritative effective_at');
  const v = computeTrack3Verdict(s.events);
  assert.equal(v.fired, true);
  assert.equal(v.confidence, 'high');
  assert.equal(s.manifest.expected_detection_track_3, true);
});

test('Track 3 (A15): detected_at-only uncertainty does not become a high-confidence violation', () => {
  const { byScenario } = readAllScenarios();
  const s = byScenario.get('A15');
  const change = s.events.find((e) => e['event.name'] === 'mcp.subscription.authorization_change');
  assert.equal(change['mcp.authz.change.timing_confidence'], 'detected_only');
  assert.equal('mcp.authz.change.effective_at' in change, false, 'A15 must genuinely lack an effective_at');
  const v = computeTrack3Verdict(s.events);
  assert.equal(v.fired, false, 'notification precedes detected_at, so it must not be flagged');
  assert.notEqual(v.confidence, 'high');
  assert.equal(s.manifest.expected_detection_track_3, false);
  assert.equal(s.manifest.expected_confidence, 'low');
});

test('Track 3 (A14 vs A15): identical notification/detected_at shape, opposite verdict, driven only by effective_at presence', () => {
  const { byScenario } = readAllScenarios();
  const a14 = byScenario.get('A14');
  const a15 = byScenario.get('A15');
  const n14 = a14.events.find((e) => e['event.name'] === 'mcp.subscription.notification');
  const n15 = a15.events.find((e) => e['event.name'] === 'mcp.subscription.notification');
  assert.equal(n14.timestamp, n15.timestamp, 'both fixtures must use the same notification timestamp to isolate the one true variable');
  const c14 = a14.events.find((e) => e['event.name'] === 'mcp.subscription.authorization_change');
  const c15 = a15.events.find((e) => e['event.name'] === 'mcp.subscription.authorization_change');
  assert.equal(c14['mcp.authz.change.detected_at'], c15['mcp.authz.change.detected_at']);
  assert.ok('mcp.authz.change.effective_at' in c14 && !('mcp.authz.change.effective_at' in c15));
  assert.notEqual(a14.manifest.expected_detection_track_3, a15.manifest.expected_detection_track_3);
});

test('Track 3 (A16 control): close before any post-revocation notification means no violation fires', () => {
  const { byScenario } = readAllScenarios();
  const s = byScenario.get('A16');
  const change = s.events.find((e) => e['event.name'] === 'mcp.subscription.authorization_change');
  const close = s.events.find((e) => e['event.name'] === 'mcp.subscription.close');
  const notificationsAfterChange = s.events.filter(
    (e) => e['event.name'] === 'mcp.subscription.notification' && e.timestamp > change['mcp.authz.change.effective_at']
  );
  assert.equal(notificationsAfterChange.length, 0, 'A16 must have zero notifications after the revocation');
  assert.ok(close.timestamp >= change['mcp.authz.change.effective_at']);
  const v = computeTrack3Verdict(s.events);
  assert.equal(v.fired, false);
  assert.equal(s.manifest.expected_detection_track_3, false);
});

test('Track 3: A12/A13/A14 (true positives) vs A15/A16 (negative/ambiguous) are cleanly separated', () => {
  const { byScenario } = readAllScenarios();
  for (const id of ['A12', 'A13', 'A14']) {
    assert.equal(computeTrack3Verdict(byScenario.get(id).events).fired, true, `${id} must fire`);
  }
  for (const id of ['A15', 'A16']) {
    assert.equal(computeTrack3Verdict(byScenario.get(id).events).fired, false, `${id} must not fire`);
  }
});
