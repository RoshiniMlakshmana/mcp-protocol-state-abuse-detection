'use strict';
/**
 * Independent re-implementation of the Track 3 correlation logic described in
 * telemetry/correlation.md, used ONLY by tests to recompute a verdict/alert-rows from raw event
 * fields -- never to just echo back the manifest's expected_* labels.
 *
 * Preference order (telemetry/correlation.md, "Answering the question" / preference list):
 *   1. An authoritative mcp.authz.change.effective_at, if present.
 *   2. mcp.authz.valid_until (or grant_expiry) for a silent-expiry boundary -- evaluated
 *      INDEPENDENTLY of (1), not only "if no authoritative change exists": see FIX #3 below.
 *   3. mcp.authz.change.detected_at alone, ONLY as a low-confidence fallback -- a notification
 *      strictly after detected_at is flagged low-confidence; a notification at or before
 *      detected_at is NOT flagged (we cannot know if the true change was before or after it).
 *
 * A violation additionally requires no mcp.subscription.close at or before the notification, on
 * the SAME subscription_id AND SAME principal_hash (a closed stream should not still be
 * delivering -- see FIX #4 below for why principal_hash was added to this join).
 *
 * BLOCK 6 FIX #1 (docs/validation-report.md, finding from fixture V5-03): only
 * mcp.authz.change.type values that actually INVALIDATE authorization ("revoked", "expired",
 * "scope_downgraded") are treated as a boundary. "scope_upgraded" (a renewal/expansion of
 * access) must never be treated as an invalidating event -- the original logic ignored `type`
 * entirely and treated any authoritative change as invalidating, which produced a false
 * positive on a legitimate renewal.
 *
 * BLOCK 6 FIX #2 (docs/validation-report.md, finding from fixture V6-02): the authoritative-
 * revocation leg and the detected_only leg join Notifications to the change event by
 * principal_hash ONLY (mirrors KQL: `join kind=inner (AuthoritativeChanges) on principal_hash`)
 * -- subscription_id is used only later, for the close-suppression anti-join. Only the silent-
 * expiry leg joins on BOTH subscription_id and principal_hash (mirrors KQL:
 * `join kind=inner (ExpiryBoundaries) on subscription_id, principal_hash`), since valid_until is
 * a per-subscription value. This oracle does NOT pre-filter notifications to a single open
 * event's subscription_id before considering them -- doing so is stricter than the real
 * KQL/SPL query and would produce a false negative on a notification missing
 * mcp.subscription.id entirely (malformed telemetry), even though the real query's
 * principal-scoped revocation-leg join would still correlate it.
 *
 * THIS-PASS FIX #3 (Track 3 remediation, see docs/validation-report.md): the previous version
 * of this oracle was an if/else-if CHAIN -- it checked the revocation leg, and only evaluated
 * the expiry leg (or the detected_only leg) if the revocation leg found nothing, then returned
 * immediately on the first non-empty leg. That does not match the real KQL/SPL queries, which
 * compute RevocationDrift and ExpiryDrift as two fully independent queries and `union` (KQL) /
 * `append` (SPL) the results -- so a notification that is a violation under BOTH an
 * authoritative revocation AND a silent expiry produces TWO independent alert rows, and a
 * fixture with only a later, inapplicable expiry boundary would not have silently masked an
 * earlier revocation, or vice versa. This oracle now evaluates both legs unconditionally and
 * unions their rows, and iterates ALL matching authorization_change / open events for a
 * notification (`.filter`, not `.find`) so multiple authorization changes for the same
 * principal (e.g. an earlier legitimate change followed by a later real revocation, in EITHER
 * timestamp order) are each independently considered, exactly like a real SQL/KQL/SPL join over
 * a whole table -- not silently collapsed to "the first one found".
 *
 * THIS-PASS FIX #4 (Track 3 remediation): the close-suppression check now requires the close
 * event to match BOTH subscription_id AND principal_hash of the notification, not
 * subscription_id alone. mcp.subscription.id is only a per-connection JSON-RPC request id
 * (Block 1 SS7) and is not guaranteed unique across different principals' connections -- a
 * subscription_id-only check could let one principal's close event incorrectly suppress a
 * DIFFERENT principal's genuine violation notification that happens to share the same
 * subscription_id string. principal.id_hash is already a required field on
 * mcp.subscription.close (telemetry/schema.md), confirmed present in generated fixtures -- this
 * uses existing, already-collected telemetry, and mirrors the identical fix now applied to
 * detections/kql/mcp_subscription_authorization_drift.kql and
 * detections/spl/mcp_subscription_authorization_drift.spl.
 *
 * KNOWN RESIDUAL LIMITATION (documented, NOT fixed in this pass -- see
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

/**
 * Returns every independent alert row the authoritative KQL/SPL Track 3 query would produce:
 * one row per (notification, applicable boundary) combination that survives close-suppression,
 * from BOTH the revocation leg and the expiry leg (unioned, not short-circuited), plus a
 * separately-tagged set of low-confidence detected_at-only rows (never merged with the
 * high-confidence rows, mirroring the separate informational KQL/SPL section). Field names
 * match the KQL query's final `project` list so rows can be compared directly against
 * independently-specified expected rows in tests.
 */
function computeTrack3AlertRows(events) {
  const notifications = events.filter((e) => e['event.name'] === 'mcp.subscription.notification');
  const closes = events.filter((e) => e['event.name'] === 'mcp.subscription.close');
  const opens = events.filter((e) => e['event.name'] === 'mcp.subscription.open');
  const authoritativeChanges = events.filter((e) =>
    e['event.name'] === 'mcp.subscription.authorization_change' &&
    e['mcp.authz.change.timing_confidence'] === 'authoritative' &&
    e['mcp.authz.change.effective_at'] &&
    INVALIDATING_CHANGE_TYPES.has(e['mcp.authz.change.type'])
  );
  const detectedOnlyChanges = events.filter((e) =>
    e['event.name'] === 'mcp.subscription.authorization_change' &&
    e['mcp.authz.change.timing_confidence'] === 'detected_only' &&
    e['mcp.authz.change.detected_at'] &&
    INVALIDATING_CHANGE_TYPES.has(e['mcp.authz.change.type'])
  );

  const suppressedByClose = (notif) =>
    closes.some((c) =>
      c['mcp.subscription.id'] === notif['mcp.subscription.id'] &&
      c['principal.id_hash'] === notif['principal.id_hash'] &&
      c.timestamp <= notif.timestamp
    );

  const rows = [];

  // Leg A: authoritative revocation -- principal_hash-only join (see FIX #2 above).
  for (const notif of notifications) {
    for (const change of authoritativeChanges) {
      if (change['principal.id_hash'] !== notif['principal.id_hash']) continue;
      if (!(notif.timestamp > change['mcp.authz.change.effective_at'])) continue;
      if (suppressedByClose(notif)) continue;
      rows.push({
        subscription_id: notif['mcp.subscription.id'],
        principal_hash: notif['principal.id_hash'],
        notif_time: notif.timestamp,
        notification_type: notif['mcp.subscription.notification_type'],
        confidence: 'high',
        boundary: 'effective_at',
        boundary_time: change['mcp.authz.change.effective_at'],
        change_type: change['mcp.authz.change.type'],
        change_source: change['mcp.authz.change.source'],
      });
    }
  }

  // Leg B: silent expiry -- subscription_id AND principal_hash join (see FIX #2 above).
  for (const notif of notifications) {
    for (const open of opens) {
      const validUntil = open['mcp.authz.valid_until'] || open['mcp.authz.grant_expiry'];
      if (!validUntil) continue;
      if (open['mcp.subscription.id'] !== notif['mcp.subscription.id']) continue;
      if (open['principal.id_hash'] !== notif['principal.id_hash']) continue;
      if (!(notif.timestamp > validUntil)) continue;
      if (suppressedByClose(notif)) continue;
      rows.push({
        subscription_id: notif['mcp.subscription.id'],
        principal_hash: notif['principal.id_hash'],
        notif_time: notif.timestamp,
        notification_type: notif['mcp.subscription.notification_type'],
        confidence: 'high',
        boundary: 'valid_until',
        boundary_time: validUntil,
        change_type: 'expired',
        change_source: 'token_expiry_computed',
      });
    }
  }

  // Low-confidence, informational-only leg: detected_at-only timing. Never merged into the
  // high-confidence rows above -- mirrors the separate saved search / commented-out section in
  // the real KQL/SPL files.
  for (const notif of notifications) {
    for (const change of detectedOnlyChanges) {
      if (change['principal.id_hash'] !== notif['principal.id_hash']) continue;
      if (!(notif.timestamp > change['mcp.authz.change.detected_at'])) continue;
      if (suppressedByClose(notif)) continue;
      rows.push({
        subscription_id: notif['mcp.subscription.id'],
        principal_hash: notif['principal.id_hash'],
        notif_time: notif.timestamp,
        notification_type: notif['mcp.subscription.notification_type'],
        confidence: 'low',
        boundary: 'detected_at',
        boundary_time: change['mcp.authz.change.detected_at'],
      });
    }
  }

  rows.sort((a, b) => (a.notif_time < b.notif_time ? -1 : a.notif_time > b.notif_time ? 1 : (a.boundary < b.boundary ? -1 : a.boundary > b.boundary ? 1 : 0)));
  return rows;
}

/**
 * Backward-compatible scalar summary over computeTrack3AlertRows, for tests written against a
 * single dominant subscription/principal per fixture (Block 4 A12-A16 style). Prefer
 * computeTrack3AlertRows directly for any fixture with more than one notification, boundary, or
 * principal -- collapsing to one verdict necessarily discards information that rows preserve.
 */
function computeTrack3Verdict(events) {
  const rows = computeTrack3AlertRows(events);
  const highRows = rows.filter((r) => r.confidence === 'high');
  const lowRows = rows.filter((r) => r.confidence === 'low');

  if (highRows.length > 0) {
    const boundaryUsed = highRows.some((r) => r.boundary === 'effective_at') ? 'effective_at' : 'valid_until';
    return { fired: true, confidence: 'high', boundaryUsed, rows: highRows };
  }
  if (lowRows.length > 0) {
    return { fired: true, confidence: 'low', boundaryUsed: 'detected_at', rows: lowRows };
  }

  // Nothing fired. Classify confidence for callers that inspect it on a negative result,
  // matching the original single-subscription semantics: prefer an open event's principal,
  // else fall back to any notification's principal, so this still works when no open event
  // exists at all (e.g. the "revocation with no retained open event" regression case).
  const open = events.find((e) => e['event.name'] === 'mcp.subscription.open');
  const anyNotif = events.find((e) => e['event.name'] === 'mcp.subscription.notification');
  const principal = open ? open['principal.id_hash'] : (anyNotif ? anyNotif['principal.id_hash'] : null);
  const hasDetectedOnly = !!principal && events.some((e) =>
    e['event.name'] === 'mcp.subscription.authorization_change' &&
    e['principal.id_hash'] === principal &&
    e['mcp.authz.change.timing_confidence'] === 'detected_only' &&
    INVALIDATING_CHANGE_TYPES.has(e['mcp.authz.change.type'])
  );
  if (hasDetectedOnly) return { fired: false, confidence: 'low', boundaryUsed: null, rows: [] };

  const hasExpiryBoundary = !!(open && (open['mcp.authz.valid_until'] || open['mcp.authz.grant_expiry']));
  if (hasExpiryBoundary) return { fired: false, confidence: 'high', boundaryUsed: 'valid_until', rows: [] };

  return { fired: false, confidence: 'not_applicable', boundaryUsed: null, rows: [] };
}

module.exports = { computeTrack3Verdict, computeTrack3AlertRows, INVALIDATING_CHANGE_TYPES };
