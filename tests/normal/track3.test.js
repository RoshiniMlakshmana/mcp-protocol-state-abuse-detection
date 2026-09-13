'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const { readAllScenarioEvents } = require('./helpers');

function boundaryFor(changeEvt) {
  if (changeEvt['mcp.authz.change.timing_confidence'] === 'authoritative' && changeEvt['mcp.authz.change.effective_at']) {
    return changeEvt['mcp.authz.change.effective_at'];
  }
  return changeEvt['mcp.authz.change.detected_at'];
}

test('Track 3: no notification in the normal corpus is delivered after its subscription\'s authorization became invalid', () => {
  const { allEvents } = readAllScenarioEvents();

  const opens = allEvents.filter((e) => e['event.name'] === 'mcp.subscription.open');
  assert.ok(opens.length > 0);

  for (const open of opens) {
    const subId = open['mcp.subscription.id'];
    const principal = open['principal.id_hash'];
    const groupEvents = allEvents.filter((e) => e['mcp.subscription.id'] === subId);
    const notifications = groupEvents.filter((e) => e['event.name'] === 'mcp.subscription.notification');
    const changes = allEvents.filter(
      (e) => e['event.name'] === 'mcp.subscription.authorization_change' && e['principal.id_hash'] === principal
    );

    if (changes.length === 0) continue; // nothing to violate (e.g. N8)

    const boundaries = changes.map(boundaryFor).sort();
    const earliestBoundary = boundaries[0];

    for (const notif of notifications) {
      assert.ok(
        notif.timestamp <= earliestBoundary,
        `subscription ${subId} delivered a notification at ${notif.timestamp} after authorization boundary ${earliestBoundary}`
      );
    }
  }
});

test('Track 3: a revoked-but-active subscription (N9) is closed before any further notification is emitted', () => {
  const { byScenario } = readAllScenarioEvents();
  const n9 = byScenario.get('N9');
  assert.ok(n9);
  const change = n9.events.find((e) => e['event.name'] === 'mcp.subscription.authorization_change');
  const close = n9.events.find((e) => e['event.name'] === 'mcp.subscription.close');
  const notificationsAfterChange = n9.events.filter(
    (e) => e['event.name'] === 'mcp.subscription.notification' && e.timestamp > change['mcp.authz.change.effective_at']
  );
  assert.ok(change, 'N9 must contain an authorization_change event');
  assert.ok(close, 'N9 must contain a close event');
  assert.equal(notificationsAfterChange.length, 0, 'N9 must not emit any notification after the authorization change');
  assert.ok(close.timestamp >= change['mcp.authz.change.effective_at']);
  assert.equal(close['mcp.subscription.close.reason'], 'server_forced_authz');
  assert.equal(n9.manifest.expected_detection_track_3, false);
});

test('Track 3: mcp.subscription.id equals the JSON-RPC request id of the originating subscriptions/listen call', () => {
  const { allEvents } = readAllScenarioEvents();
  const opens = allEvents.filter((e) => e['event.name'] === 'mcp.subscription.open');
  for (const open of opens) {
    assert.equal(open['mcp.subscription.id'], open['jsonrpc.request.id']);
  }
});

test('Track 3: a "detected_only" (blind-window) authorization_change is never silently upgraded to "authoritative"', () => {
  // No fixture in this corpus fabricates detected_only->authoritative confidence; this test
  // guards the invariant structurally in case a future generator run introduces one.
  const { allEvents } = readAllScenarioEvents();
  const changes = allEvents.filter((e) => e['event.name'] === 'mcp.subscription.authorization_change');
  for (const c of changes) {
    if (c['mcp.authz.change.timing_confidence'] === 'detected_only') {
      assert.equal(c['mcp.authz.change.effective_at'], undefined, 'detected_only records must not also carry effective_at');
    }
    if (c['mcp.authz.change.effective_at']) {
      assert.equal(c['mcp.authz.change.timing_confidence'], 'authoritative');
    }
  }
});
