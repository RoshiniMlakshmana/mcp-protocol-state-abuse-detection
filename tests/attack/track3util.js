'use strict';
/**
 * Independent re-implementation of the Track 3 correlation logic described in
 * telemetry/correlation.md, used ONLY by tests to recompute a verdict from raw event fields --
 * never to just echo back the manifest's expected_* labels.
 *
 * Preference order (telemetry/correlation.md, "Answering the question" / preference list):
 *   1. An authoritative mcp.authz.change.effective_at, if present.
 *   2. mcp.authz.valid_until (or grant_expiry) for a silent-expiry boundary, if no
 *      authoritative change exists.
 *   3. mcp.authz.change.detected_at alone, ONLY as a low-confidence fallback -- a notification
 *      strictly after detected_at is flagged low-confidence; a notification at or before
 *      detected_at is NOT flagged (we cannot know if the true change was before or after it).
 *
 * A violation additionally requires no mcp.subscription.close at or before the notification
 * (a closed stream should not still be delivering).
 *
 * BLOCK 6 FIX #1 (docs/validation-report.md, finding from fixture V5-03): only
 * mcp.authz.change.type values that actually INVALIDATE authorization ("revoked", "expired",
 * "scope_downgraded") are treated as a boundary. "scope_upgraded" (a renewal/expansion of
 * access) must never be treated as an invalidating event -- the original logic ignored `type`
 * entirely and treated any authoritative change as invalidating, which produced a false
 * positive on a legitimate renewal.
 *
 * BLOCK 6 FIX #2 (docs/validation-report.md, finding from fixture V6-02): this oracle mirrors
 * detections/kql/mcp_subscription_authorization_drift.kql's ACTUAL join structure precisely:
 * the authoritative-revocation leg and the detected_only leg join Notifications to the change
 * event by principal_hash ONLY (KQL: `join kind=inner (AuthoritativeChanges) on principal_hash`)
 * -- subscription_id is used only later, for the close-suppression anti-join. Only the silent-
 * expiry leg joins on BOTH subscription_id and principal_hash (KQL:
 * `join kind=inner (ExpiryBoundaries) on subscription_id, principal_hash`), since valid_until
 * is a per-subscription value. The original version of this oracle incorrectly pre-filtered
 * ALL notifications to the specific open event's subscription_id before ever considering them,
 * which is stricter than the real KQL query and produced a false negative on a notification
 * missing mcp.subscription.id entirely (malformed telemetry) even though the real KQL's
 * principal-scoped join would still have correlated it via the revocation leg.
 *
 * KNOWN RESIDUAL LIMITATION (documented, not fixed in Block 6 -- see
 * docs/validation-report.md "remaining risks"): because the authoritative/detected_only legs
 * join by principal only, a principal holding TWO OR MORE concurrent subscriptions, where one
 * is revoked and another remains legitimately valid, could have the still-valid subscription's
 * notifications incorrectly matched to the other subscription's revocation. Scoping this join
 * more tightly by subscription_id as well would fix that but would reintroduce the V6-02
 * blind spot (a notification missing mcp.subscription.id would no longer correlate at all).
 * This is a genuine, currently-unresolved precision/recall tradeoff in the real KQL/SPL rules,
 * not an oracle-only artifact -- it is reported, not silently resolved.
 */
const INVALIDATING_CHANGE_TYPES = new Set(['revoked', 'expired', 'scope_downgraded']);

function computeTrack3Verdict(events) {
  const open = events.find((e) => e['event.name'] === 'mcp.subscription.open');
  if (!open) return { fired: false, confidence: 'not_applicable', boundaryUsed: null };

  const subId = open['mcp.subscription.id'];
  const principal = open['principal.id_hash'];
  const allNotifications = events.filter((e) => e['event.name'] === 'mcp.subscription.notification');
  const notificationsForSub = allNotifications.filter((e) => e['mcp.subscription.id'] === subId);
  const closes = events.filter((e) => e['event.name'] === 'mcp.subscription.close' && e['mcp.subscription.id'] === subId);
  const changes = events.filter((e) => e['event.name'] === 'mcp.subscription.authorization_change' && e['principal.id_hash'] === principal);

  const notFlaggedByClose = (notif) => !closes.some((c) => c.timestamp <= notif.timestamp);

  const authoritative = changes.find((c) =>
    c['mcp.authz.change.timing_confidence'] === 'authoritative' &&
    c['mcp.authz.change.effective_at'] &&
    INVALIDATING_CHANGE_TYPES.has(c['mcp.authz.change.type'])
  );
  if (authoritative) {
    const boundary = authoritative['mcp.authz.change.effective_at'];
    // Principal-scoped join, matching the real KQL/SPL query -- see Fix #2 above.
    const violating = allNotifications.filter((n) => n['principal.id_hash'] === principal && n.timestamp > boundary && notFlaggedByClose(n));
    return { fired: violating.length > 0, confidence: 'high', boundaryUsed: 'effective_at' };
  }

  const expiryBoundary = open['mcp.authz.valid_until'] || open['mcp.authz.grant_expiry'];
  if (expiryBoundary) {
    // Subscription-scoped join (subscription_id AND principal_hash), matching KQL's expiry leg.
    const violating = notificationsForSub.filter((n) => n.timestamp > expiryBoundary && notFlaggedByClose(n));
    if (violating.length > 0) return { fired: true, confidence: 'high', boundaryUsed: 'valid_until' };
  }

  const detectedOnly = changes.find((c) =>
    c['mcp.authz.change.timing_confidence'] === 'detected_only' &&
    INVALIDATING_CHANGE_TYPES.has(c['mcp.authz.change.type'])
  );
  if (detectedOnly) {
    const detBoundary = detectedOnly['mcp.authz.change.detected_at'];
    const anyAfter = allNotifications.some((n) => n['principal.id_hash'] === principal && n.timestamp > detBoundary && notFlaggedByClose(n));
    return { fired: anyAfter, confidence: 'low', boundaryUsed: 'detected_at' };
  }

  return { fired: false, confidence: expiryBoundary ? 'high' : 'not_applicable', boundaryUsed: expiryBoundary ? 'valid_until' : null };
}

module.exports = { computeTrack3Verdict };
