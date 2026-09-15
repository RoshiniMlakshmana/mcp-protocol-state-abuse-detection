'use strict';
/**
 * Track 3 reference resolver (scope-aware correction, example-driven regression pass).
 * Independently re-implements telemetry/correlation.md's "Resolving affected bindings"
 * algorithm in plain JS, used ONLY by tests to recompute a resolution from raw event fields --
 * never to echo back the manifest's expected_* labels.
 *
 * SCOPE-AWARE CORRECTION (see docs/validation-report.md): a prior version of this oracle joined
 * a principal's authorization_change event to EVERY subscription that principal held, treating
 * "same principal.id_hash" as sufficient to scope a revocation. Verified against current
 * MCP/OAuth documentation, that conflates principal identity with authorization scope (see
 * telemetry/schema.md SS5 for the full citation trail).
 *
 * THIS PASS removes a second, subtler unsound shortcut a prior revision introduced to preserve
 * legacy test expectations: a "sole-candidate fallback" that resolved an `unknown`-scope change
 * to a confirmed finding whenever exactly one binding was observed for that principal. THAT IS
 * STILL AN INFERENCE, not evidence -- an authorization server that does not report which binding
 * a change affects has not told us it affects "the only one we happen to know about." This
 * resolver now NEVER resolves `affected_scope = unknown` (or a legacy event lacking the field)
 * to anything but `insufficient_evidence`, regardless of how many candidate bindings exist --
 * including exactly one. Only two things can confirm a violation's scope: (a) `affected_scope =
 * binding` explicitly naming the notification's own binding, or (b) `affected_scope =
 * all_principal_bindings` (an explicit, authoritative claim that covers every binding by
 * definition, not an inference from what we happen to have observed).
 */
const INVALIDATING_CHANGE_TYPES = new Set(['revoked', 'expired', 'scope_downgraded']);

function legacyBindingId(principalHash, subId) {
  return `legacy:${principalHash}:${subId === undefined ? '(none)' : subId}`;
}

// Legacy-compatibility fallback (telemetry/schema.md): an event lacking mcp.subscription.id
// gets instance_id = principal_hash + ":" + subscription_id, NOT bare subscription_id -- two
// different principals legitimately reusing the identical wire subscription_id would otherwise
// collide onto the same instance_id, silently borrowing one principal's open record for
// another's notification.
function resolveInstanceId(evt) {
  if (evt['mcp.subscription.instance_id'] !== undefined) return evt['mcp.subscription.instance_id'];
  return `${evt['principal.id_hash']}:${evt['mcp.subscription.id']}`;
}

/**
 * Returns { results, coverage }. `results` has exactly one entry per evaluated notification for
 * EVALUATED_NO_VIOLATION/INSUFFICIENT_EVIDENCE outcomes, and one entry PER independently
 * confirmed boundary for CONFIRMED_DRIFT (a notification violating two independent boundaries at
 * once produces two rows, by design -- matches the KQL/SPL union semantics).
 */
function computeTrack3Resolution(events) {
  const opens = events
    .filter((e) => e['event.name'] === 'mcp.subscription.open')
    .map((e) => ({
      instanceId: resolveInstanceId(e),
      subId: e['mcp.subscription.id'],
      principalHash: e['principal.id_hash'],
      bindingId: e['mcp.authz.binding_id'] !== undefined ? e['mcp.authz.binding_id'] : legacyBindingId(e['principal.id_hash'], e['mcp.subscription.id']),
      requiredScope: e['mcp.subscription.required_scope'],
      validUntil: e['mcp.authz.valid_until'] || e['mcp.authz.grant_expiry'],
      openTime: e.timestamp,
      keyId: e['security.hash.key_id'],
    }));

  const notifications = events
    .filter((e) => e['event.name'] === 'mcp.subscription.notification')
    .map((e) => ({
      instanceId: resolveInstanceId(e),
      subId: e['mcp.subscription.id'],
      principalHash: e['principal.id_hash'],
      notifTime: e.timestamp,
      notificationType: e['mcp.subscription.notification_type'],
      ownBindingId: e['mcp.authz.binding_id'],
      ownValidUntil: e['mcp.authz.valid_until'],
      keyId: e['security.hash.key_id'],
    }));

  const closes = events
    .filter((e) => e['event.name'] === 'mcp.subscription.close')
    .map((e) => ({
      instanceId: resolveInstanceId(e),
      principalHash: e['principal.id_hash'],
      closeTime: e.timestamp,
      keyId: e['security.hash.key_id'],
    }));

  const changes = events
    .filter((e) => e['event.name'] === 'mcp.subscription.authorization_change')
    .map((e) => ({
      principalHash: e['principal.id_hash'],
      type: e['mcp.authz.change.type'],
      source: e['mcp.authz.change.source'],
      effectiveAt: e['mcp.authz.change.effective_at'],
      detectedAt: e['mcp.authz.change.detected_at'],
      timingConfidence: e['mcp.authz.change.timing_confidence'],
      affectedScope: e['mcp.authz.change.affected_scope'] || 'unknown',
      affectedBindingIds: e['mcp.authz.change.affected_binding_ids'] || [],
      removedScope: e['mcp.authz.change.removed_scope'],
      keyId: e['security.hash.key_id'],
    }));

  // Conflicting-evidence pre-pass: a binding named as invalidated by one authoritative change and
  // ALSO named as scope_upgraded by another authoritative change cannot be resolved by picking a
  // side -- a revoked binding legitimately receiving further grants is a data-quality conflict,
  // not a timeline to order.
  const invalidatedBindingIds = new Set();
  const upgradedBindingIds = new Set();
  for (const c of changes) {
    if (c.timingConfidence !== 'authoritative' || c.affectedScope !== 'binding') continue;
    const target = c.type === 'scope_upgraded' ? upgradedBindingIds : (INVALIDATING_CHANGE_TYPES.has(c.type) ? invalidatedBindingIds : null);
    if (target) for (const id of c.affectedBindingIds) target.add(id);
  }
  const conflictedBindingIds = new Set([...invalidatedBindingIds].filter((id) => upgradedBindingIds.has(id)));

  // Does change `c` apply to a notification whose resolved binding is `effectiveBindingId`
  // (undefined if genuinely unknown)? Returns 'yes' | 'no' | 'ambiguous'. NEVER infers from how
  // many bindings happen to be observed -- see the file header for why that was removed.
  // `bindingOpenTime`/`bindingClosedBeforeEffectiveAt` give `all_principal_bindings` a PRECISE
  // effective-time interval check (replacing an earlier "ever observed anywhere in the queried
  // window" approximation): a binding that did not yet exist, or was already closed, at the
  // moment the change took effect was never one of "all bindings this principal held" then.
  function changeApplies(c, effectiveBindingId, bindingOpenTime, bindingClosedBeforeEffectiveAt) {
    if (c.affectedScope === 'all_principal_bindings') {
      if (bindingOpenTime !== undefined && bindingOpenTime > c.effectiveAt) return 'no'; // didn't exist yet
      if (bindingClosedBeforeEffectiveAt) return 'no'; // already closed by then
      return 'yes';
    }
    if (c.affectedScope === 'binding') {
      if (effectiveBindingId === undefined) return 'ambiguous'; // named bindings exist, but we don't know which (if any) this notification's own binding is
      return c.affectedBindingIds.includes(effectiveBindingId) ? 'yes' : 'no';
    }
    // 'unknown' (absent, or a legacy event predating the field): the scope is genuinely
    // unresolvable from this record alone, REGARDLESS of candidate count.
    return 'ambiguous';
  }

  const results = [];

  for (const n of notifications) {
    const open = opens.find((o) => o.instanceId === n.instanceId);
    const effectiveBindingId = n.ownBindingId !== undefined ? n.ownBindingId : (open ? open.bindingId : undefined);
    const effectiveValidUntil = (n.ownBindingId !== undefined && n.ownValidUntil !== undefined) ? n.ownValidUntil : (open ? open.validUntil : undefined);
    const requiredScope = open ? open.requiredScope : undefined;
    const suppressed = closes.some((c) => c.instanceId === n.instanceId && c.principalHash === n.principalHash && c.closeTime <= n.notifTime);
    const epochMismatch = !!(open && n.keyId && open.keyId && n.keyId !== open.keyId);

    let confirmedAny = false;
    let insufficientReason = null;
    // A notification can independently satisfy MULTIPLE "no violation" conditions at once
    // (e.g. valid_until not yet crossed AND a scope-irrelevant downgrade) -- collected as a set
    // of short reason tags, all retained, rather than a single boolean that discards which
    // condition(s) actually applied. This is ONE row per notification (unchanged from before),
    // not a source of row duplication -- see KQL/SPL's ExpirySignals+RevocationSignals union,
    // which independently produced ONE ROW PER CONTRIBUTING SIGNAL for the same tie and is fixed
    // to match this oracle's one-row shape (docs/validation-report.md, "Track 3 remediation
    // pass, part 5").
    const noViolationReasons = new Set();

    if (epochMismatch) {
      insufficientReason = 'incompatible_hash_epoch';
    } else {
      // Leg A: silent expiry -- inherently instance-scoped (valid_until lives on the record
      // that's already tied to this exact instance/binding), never ambiguous.
      if (effectiveValidUntil) {
        if (n.notifTime > effectiveValidUntil) {
          if (suppressed) noViolationReasons.add('expiry_suppressed_by_close');
          else {
            results.push({
              instanceId: n.instanceId, subscriptionId: n.subId, principalHash: n.principalHash,
              notifTime: n.notifTime, notificationType: n.notificationType, outcome: 'confirmed_drift',
              boundary: 'valid_until', boundaryTime: effectiveValidUntil, bindingId: effectiveBindingId,
            });
            confirmedAny = true;
          }
        } else noViolationReasons.add('expiry_not_yet_reached');
      }

      // Leg B: authoritative revocation / scope downgrade -- binding-scoped. Timing is checked
      // BEFORE scope resolution: a change whose effective_at hasn't even been reached yet by
      // this notification cannot be a violation regardless of scope, so scope ambiguity is only
      // surfaced when it would actually matter.
      for (const c of changes) {
        if (c.principalHash !== n.principalHash) continue;
        if (c.keyId && n.keyId && c.keyId !== n.keyId) { insufficientReason = insufficientReason || 'incompatible_hash_epoch'; continue; }
        if (!INVALIDATING_CHANGE_TYPES.has(c.type)) continue;
        if (c.timingConfidence !== 'authoritative') {
          if (n.notifTime > c.detectedAt) insufficientReason = insufficientReason || 'timing_unconfirmed';
          continue;
        }
        if (c.effectiveAt === undefined || c.effectiveAt === null) {
          // Self-contradictory record: claims authoritative timing but carries no effective_at
          // at all. This is incomplete evidence, not "does not apply".
          insufficientReason = insufficientReason || 'incomplete_timing_evidence';
          continue;
        }
        if (!(n.notifTime > c.effectiveAt)) { noViolationReasons.add('revocation_not_yet_effective'); continue; }

        // A legitimately closed stream needs no scope resolution at all -- suppression is
        // checked BEFORE scope ambiguity, since "the subscriber already stopped receiving
        // notifications through the proper channel" is a definitive answer regardless of which
        // binding the revocation targeted.
        if (suppressed) { noViolationReasons.add('revocation_suppressed_by_close'); continue; }

        if (effectiveBindingId !== undefined && conflictedBindingIds.has(effectiveBindingId)) {
          insufficientReason = insufficientReason || 'conflicting_evidence';
          continue;
        }
        const bindingClosedBeforeEffectiveAt = closes.some((cl) => cl.instanceId === n.instanceId && cl.principalHash === n.principalHash && cl.closeTime <= c.effectiveAt);
        const applies = changeApplies(c, effectiveBindingId, open ? open.openTime : undefined, bindingClosedBeforeEffectiveAt);
        if (applies === 'ambiguous') { insufficientReason = insufficientReason || 'ambiguous_scope'; continue; }
        if (applies === 'no') continue;

        if (c.type === 'scope_downgraded') {
          if (!requiredScope || !c.removedScope) { insufficientReason = insufficientReason || 'missing_scope_evidence'; continue; }
          if (!c.removedScope.some((s) => requiredScope.includes(s))) { noViolationReasons.add('scope_downgrade_irrelevant'); continue; }
        }

        results.push({
          instanceId: n.instanceId, subscriptionId: n.subId, principalHash: n.principalHash,
          notifTime: n.notifTime, notificationType: n.notificationType, outcome: 'confirmed_drift',
          boundary: 'effective_at', boundaryTime: c.effectiveAt, bindingId: effectiveBindingId,
          changeType: c.type, changeSource: c.source,
        });
        confirmedAny = true;
      }
    }

    if (!confirmedAny) {
      const evaluatedNoViolation = noViolationReasons.size > 0;
      const outcome = insufficientReason ? 'insufficient_evidence' : (evaluatedNoViolation ? 'evaluated_no_violation' : 'insufficient_evidence');
      // For evaluated_no_violation, ALL contributing reasons are retained (semicolon-joined, sorted
      // for determinism), not just the first/only one -- matches the KQL/SPL output contract below.
      const reason = insufficientReason || (evaluatedNoViolation ? [...noViolationReasons].sort().join('; ') : 'no_invalidity_evidence');
      results.push({
        instanceId: n.instanceId, subscriptionId: n.subId, principalHash: n.principalHash,
        notifTime: n.notifTime, notificationType: n.notificationType, outcome, reason,
      });
    }
  }

  const coverage = {
    total: results.length,
    confirmedDrift: results.filter((r) => r.outcome === 'confirmed_drift').length,
    evaluatedNoViolation: results.filter((r) => r.outcome === 'evaluated_no_violation').length,
    insufficientEvidence: results.filter((r) => r.outcome === 'insufficient_evidence').length,
  };

  return { results, coverage };
}

/** Backward-compatible: confirmed_drift rows only, in the pre-existing field shape. */
function computeTrack3AlertRows(events) {
  const { results } = computeTrack3Resolution(events);
  return results
    .filter((r) => r.outcome === 'confirmed_drift')
    .map((r) => ({
      subscription_id: r.subscriptionId, principal_hash: r.principalHash, notif_time: r.notifTime,
      notification_type: r.notificationType, confidence: 'high', boundary: r.boundary,
      boundary_time: r.boundaryTime, change_type: r.changeType, change_source: r.changeSource,
    }));
}

/** Backward-compatible scalar summary, for single-subscription/single-principal fixtures. */
function computeTrack3Verdict(events) {
  const { results } = computeTrack3Resolution(events);
  const confirmed = results.filter((r) => r.outcome === 'confirmed_drift');
  if (confirmed.length > 0) {
    const boundaryUsed = confirmed.some((r) => r.boundary === 'effective_at') ? 'effective_at' : 'valid_until';
    return { fired: true, confidence: 'high', boundaryUsed, rows: confirmed };
  }
  const insufficient = results.filter((r) => r.outcome === 'insufficient_evidence');
  if (insufficient.some((r) => r.reason === 'timing_unconfirmed')) {
    return { fired: false, confidence: 'low', boundaryUsed: null, rows: [] };
  }
  if (insufficient.length > 0) {
    return { fired: false, confidence: 'insufficient_evidence', boundaryUsed: null, rows: [] };
  }
  return { fired: false, confidence: 'not_applicable', boundaryUsed: null, rows: [] };
}

module.exports = {
  computeTrack3Resolution, computeTrack3AlertRows, computeTrack3Verdict,
  INVALIDATING_CHANGE_TYPES, legacyBindingId, resolveInstanceId,
};
