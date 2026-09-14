'use strict';
/**
 * Track 3 reference resolver (scope-aware correction). Independently re-implements
 * telemetry/correlation.md's "Resolving affected bindings" algorithm in plain JS, used ONLY by
 * tests to recompute a resolution from raw event fields -- never to echo back the manifest's
 * expected_* labels.
 *
 * SCOPE-AWARE CORRECTION (this pass, see docs/validation-report.md): the previous oracle joined
 * a principal's authorization_change event to EVERY subscription that principal held, treating
 * "same principal.id_hash" as sufficient to scope a revocation. Verified against current
 * MCP/OAuth documentation, that conflates principal identity with authorization scope:
 *   - A principal can hold multiple independent, independently-revocable bindings at once
 *     (OAuth token revocation, RFC 7009, scopes revocation to "a particular token"; cascading to
 *     related tokens is an explicit server-policy choice, never automatic).
 *   - A scope downgrade removes specific permissions, not blanket access (MCP's authorization
 *     page requires servers to reason about scope per operation).
 *   - The wire mcp.subscription.id is connection-scoped only (MCP's subscriptions pattern: "the
 *     server holds no subscription state across reconnections") -- not a globally unique stream
 *     incarnation.
 *   - mcp.authz.grant_snapshot_hash is a content fingerprint, not a stable identifier (OAuth
 *     token refresh, RFC 6749 SS6, issues a new token value for what is conventionally the same
 *     grant).
 *
 * This resolver NEVER falls back to a principal-only confirmed-drift join. Ambiguous or
 * incomplete evidence produces an explicit `insufficient_evidence` outcome instead.
 */
const INVALIDATING_CHANGE_TYPES = new Set(['revoked', 'expired', 'scope_downgraded']);

function legacyBindingId(principalHash, subId) {
  return `legacy:${principalHash}:${subId === undefined ? '(none)' : subId}`;
}

// Legacy-compatibility fallback (telemetry/schema.md): an event lacking mcp.subscription.id
// gets instance_id = principal_hash + ":" + subscription_id, NOT bare subscription_id -- two
// different principals legitimately reusing the identical wire subscription_id (fixture V11-02)
// would otherwise collide onto the same instance_id, silently borrowing one principal's open
// record (bindingId/requiredScope/validUntil) for another's notification. Scoping the fallback
// by principal_hash as well fixes that while leaving every single-subscription-per-principal
// legacy fixture's join key unchanged (same principal + same subId => same fallback value as
// before).
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

  // Every binding known for a principal that was open (not yet closed) at or before `atTime`,
  // from either a retained .open event or an earlier proven-rebinding .notification.
  function candidateBindingsForPrincipal(principalHash, atTime) {
    const seen = new Map();
    for (const o of opens) {
      if (o.principalHash !== principalHash || o.openTime > atTime) continue;
      const closedBefore = closes.some((c) => c.instanceId === o.instanceId && c.principalHash === principalHash && c.closeTime <= atTime);
      if (closedBefore) continue;
      if (!seen.has(o.bindingId)) seen.set(o.bindingId, o.bindingId);
    }
    for (const n of notifications) {
      if (n.principalHash !== principalHash || !n.ownBindingId || n.notifTime > atTime) continue;
      const closedBefore = closes.some((c) => c.instanceId === n.instanceId && c.principalHash === principalHash && c.closeTime <= atTime);
      if (closedBefore) continue;
      if (!seen.has(n.ownBindingId)) seen.set(n.ownBindingId, n.ownBindingId);
    }
    return [...seen.values()];
  }

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
  // (undefined if genuinely unknown)? Returns { applies: true|false|'ambiguous', ambiguousIds? }.
  function changeApplies(c, effectiveBindingId) {
    if (c.affectedScope === 'all_principal_bindings') return { applies: true };
    if (c.affectedScope === 'binding') {
      return { applies: effectiveBindingId !== undefined && c.affectedBindingIds.includes(effectiveBindingId) };
    }
    // 'unknown' (or a legacy event predating the field): sole-candidate fallback only.
    const candidates = candidateBindingsForPrincipal(c.principalHash, c.effectiveAt || c.detectedAt);
    if (candidates.length === 0) return { applies: false };
    if (candidates.length === 1) {
      const only = candidates[0];
      return { applies: effectiveBindingId === undefined || effectiveBindingId === only, resolvedBindingId: only };
    }
    return { applies: 'ambiguous', ambiguousIds: candidates };
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
    let evaluatedNoViolation = false;

    if (epochMismatch) {
      insufficientReason = 'incompatible_hash_epoch';
    } else {
      // Leg A: silent expiry -- inherently instance-scoped (valid_until lives on the record
      // that's already tied to this exact instance/binding), never ambiguous.
      if (effectiveValidUntil) {
        if (n.notifTime > effectiveValidUntil) {
          if (suppressed) evaluatedNoViolation = true;
          else {
            results.push({
              instanceId: n.instanceId, subscriptionId: n.subId, principalHash: n.principalHash,
              notifTime: n.notifTime, notificationType: n.notificationType, outcome: 'confirmed_drift',
              boundary: 'valid_until', boundaryTime: effectiveValidUntil, bindingId: effectiveBindingId,
            });
            confirmedAny = true;
          }
        } else evaluatedNoViolation = true;
      }

      // Leg B: authoritative revocation / scope downgrade -- binding-scoped.
      for (const c of changes) {
        if (c.principalHash !== n.principalHash) continue;
        if (c.keyId && n.keyId && c.keyId !== n.keyId) { insufficientReason = insufficientReason || 'incompatible_hash_epoch'; continue; }
        if (!INVALIDATING_CHANGE_TYPES.has(c.type)) continue;
        if (c.timingConfidence !== 'authoritative') {
          if (n.notifTime > c.detectedAt) insufficientReason = insufficientReason || 'timing_unconfirmed';
          continue;
        }
        if (effectiveBindingId !== undefined && conflictedBindingIds.has(effectiveBindingId)) {
          insufficientReason = insufficientReason || 'conflicting_evidence';
          continue;
        }
        const resolved = changeApplies(c, effectiveBindingId);
        if (resolved.applies === 'ambiguous') {
          if (effectiveBindingId === undefined || resolved.ambiguousIds.includes(effectiveBindingId)) {
            insufficientReason = insufficientReason || 'ambiguous_scope';
          }
          continue;
        }
        if (!resolved.applies) continue;

        if (c.type === 'scope_downgraded') {
          if (!requiredScope || !c.removedScope) { insufficientReason = insufficientReason || 'missing_scope_evidence'; continue; }
          if (!c.removedScope.some((s) => requiredScope.includes(s))) { evaluatedNoViolation = true; continue; }
        }

        if (n.notifTime > c.effectiveAt) {
          if (suppressed) evaluatedNoViolation = true;
          else {
            results.push({
              instanceId: n.instanceId, subscriptionId: n.subId, principalHash: n.principalHash,
              notifTime: n.notifTime, notificationType: n.notificationType, outcome: 'confirmed_drift',
              boundary: 'effective_at', boundaryTime: c.effectiveAt,
              bindingId: resolved.resolvedBindingId || effectiveBindingId,
              changeType: c.type, changeSource: c.source,
            });
            confirmedAny = true;
          }
        } else evaluatedNoViolation = true;
      }
    }

    if (!confirmedAny) {
      const outcome = insufficientReason ? 'insufficient_evidence' : (evaluatedNoViolation ? 'evaluated_no_violation' : 'insufficient_evidence');
      const reason = insufficientReason || (evaluatedNoViolation ? null : 'no_invalidity_evidence');
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
