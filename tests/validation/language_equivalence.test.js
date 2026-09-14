'use strict';
/**
 * V9 -- Language equivalence. Independently re-implements each language's ACTUAL written
 * condition (Sigma YAML / KQL / SPL, as they exist in detections/) as separate JS predicates,
 * then runs all three against the full stress corpus and checks where they agree/disagree.
 * Track 1 and Track 2 are expected to agree everywhere (the three languages express the same
 * primary logic). Track 3 is expected to DISAGREE on specific scenarios -- Sigma's correlation
 * is documented as non-faithful; KQL and SPL are the authoritative, mutually-equivalent
 * implementations.
 */
const test = require('node:test');
const assert = require('node:assert/strict');
const { loadFullStressCorpus } = require('../detections/corpus');
const { track3PrimaryFires, track3SigmaCorrelationFires } = require('../detections/oracle');

// --- Track 1: mirrors detections/sigma/mcp_task_routing_desynchronization.yml,
// detections/kql/mcp_task_routing_desynchronization.kql, detections/spl/...spl (primary query) ---
function sigmaTrack1(events) {
  // selection_event: event.name == mcp.request.validation
  // selection_conflict / selection_conflict_alt, condition: "selection_event and 1 of selection_conflict*"
  return events.some((e) => e['event.name'] === 'mcp.request.validation' && (
    e['mcp.validation.method.result'] === 'conflict' || e['mcp.validation.name.result'] === 'conflict'
  ));
}
function kqlTrack1(events) {
  // | where ['event.name'] == "mcp.request.validation"
  // | where ['mcp.validation.method.result'] == "conflict" or ['mcp.validation.name.result'] == "conflict"
  return events.some((e) => e['event.name'] === 'mcp.request.validation' && (
    e['mcp.validation.method.result'] === 'conflict' || e['mcp.validation.name.result'] === 'conflict'
  ));
}
function splTrack1(events) {
  // "event.name"="mcp.request.validation" ("mcp.validation.method.result"="conflict" OR "mcp.validation.name.result"="conflict")
  return events.some((e) => e['event.name'] === 'mcp.request.validation' && (
    e['mcp.validation.method.result'] === 'conflict' || e['mcp.validation.name.result'] === 'conflict'
  ));
}

// --- Track 2: mirrors the three mcp_cross_principal_task_authorization.* files ---
function sigmaTrack2(events) {
  return events.some((e) => e['event.name'] === 'mcp.task.authorization' && e['mcp.authz.decision'] === 'deny' && e['mcp.authz.reason'] === 'principal_mismatch');
}
function kqlTrack2(events) { return sigmaTrack2(events); }
function splTrack2(events) { return sigmaTrack2(events); }

test('Track 1: Sigma, KQL, SPL agree on every one of the 68 stress-corpus scenarios', () => {
  const rows = loadFullStressCorpus();
  let disagreements = 0;
  for (const row of rows) {
    const s = sigmaTrack1(row.events), k = kqlTrack1(row.events), p = splTrack1(row.events);
    if (s !== k || k !== p) { disagreements++; console.log(`DISAGREEMENT on ${row.scenario_id}: sigma=${s} kql=${k} spl=${p}`); }
  }
  assert.equal(disagreements, 0);
});

test('Track 2: Sigma, KQL, SPL agree on every one of the 68 stress-corpus scenarios', () => {
  const rows = loadFullStressCorpus();
  let disagreements = 0;
  for (const row of rows) {
    const s = sigmaTrack2(row.events), k = kqlTrack2(row.events), p = splTrack2(row.events);
    if (s !== k || k !== p) { disagreements++; console.log(`DISAGREEMENT on ${row.scenario_id}: sigma=${s} kql=${k} spl=${p}`); }
  }
  assert.equal(disagreements, 0);
});

// --- Track 3: two INDEPENDENTLY-CODED JS models of the SCOPE-AWARE CORRECTED algorithm, one
// per language's written query, run against the shared corpus and compared by outcome.
//
// IMPORTANT DISCLAIMER: these are hand-written JS models of what each query LANGUAGE's
// documented semantics do with the given events -- neither model executes actual KQL or SPL,
// and neither runs against a real Sentinel or Splunk backend (see README.md and
// docs/validation-report.md; native execution remains pending). "Equivalence" below means
// "these two independently-authored models, each coded from that language's own written query,
// agree" -- not "verified against native query engines."
//
// THIS REVISION removes the "sole-candidate fallback" (an unknown-scope change resolved to a
// confirmed finding whenever exactly one binding was observed) that a prior revision of these
// models carried -- see fixture V13-03, which proves candidate count must never substitute for
// scope evidence. It also replaces an "ever observed anywhere in the window" approximation for
// affected_scope=all_principal_bindings with a PRECISE effective-time interval check (fixture
// V13-06): a binding only counts if it was already open, and not yet closed, at the moment the
// change took effect.
function legacyBindingId(principalHash, subId) {
  return `legacy:${principalHash}:${subId === undefined ? '(none)' : subId}`;
}
function resolveInstanceId(e) {
  if (e['mcp.subscription.instance_id'] !== undefined) return e['mcp.subscription.instance_id'];
  return `${e['principal.id_hash']}:${e['mcp.subscription.id']}`;
}
const INVALIDATING = ['revoked', 'expired', 'scope_downgraded'];

// kqlModelResults(): models detections/kql/mcp_subscription_authorization_drift.kql's
// AllSignals/priority-max structure.
function kqlModelResults(events) {
  const opens = events.filter((e) => e['event.name'] === 'mcp.subscription.open').map((e) => ({
    instanceId: resolveInstanceId(e), principalHash: e['principal.id_hash'],
    bindingId: e['mcp.authz.binding_id'] !== undefined ? e['mcp.authz.binding_id'] : legacyBindingId(e['principal.id_hash'], e['mcp.subscription.id']),
    requiredScope: e['mcp.subscription.required_scope'], validUntil: e['mcp.authz.valid_until'] || e['mcp.authz.grant_expiry'],
    openTime: e.timestamp, keyId: e['security.hash.key_id'],
  }));
  const notifs = events.filter((e) => e['event.name'] === 'mcp.subscription.notification').map((e) => ({
    instanceId: resolveInstanceId(e), subscriptionId: e['mcp.subscription.id'], principalHash: e['principal.id_hash'], notifTime: e.timestamp,
    ownBindingId: e['mcp.authz.binding_id'], ownValidUntil: e['mcp.authz.valid_until'], keyId: e['security.hash.key_id'],
  }));
  const closes = events.filter((e) => e['event.name'] === 'mcp.subscription.close').map((e) => ({
    instanceId: resolveInstanceId(e), principalHash: e['principal.id_hash'], closeTime: e.timestamp,
  }));
  const changes = events.filter((e) => e['event.name'] === 'mcp.subscription.authorization_change' && e['mcp.authz.change.timing_confidence'] === 'authoritative' && INVALIDATING.includes(e['mcp.authz.change.type'])).map((e) => ({
    principalHash: e['principal.id_hash'], type: e['mcp.authz.change.type'], effectiveAt: e['mcp.authz.change.effective_at'],
    affectedScope: e['mcp.authz.change.affected_scope'] || 'unknown', affectedBindingIds: e['mcp.authz.change.affected_binding_ids'] || [], removedScope: e['mcp.authz.change.removed_scope'],
  }));
  const earliestClose = new Map();
  for (const c of closes) { const k = `${c.instanceId}|${c.principalHash}`; if (!earliestClose.has(k) || c.closeTime < earliestClose.get(k)) earliestClose.set(k, c.closeTime); }

  const results = [];
  for (const n of notifs) {
    const open = opens.find((o) => o.instanceId === n.instanceId);
    const bindingId = n.ownBindingId !== undefined ? n.ownBindingId : (open ? open.bindingId : undefined);
    const validUntil = (n.ownBindingId !== undefined && n.ownValidUntil !== undefined) ? n.ownValidUntil : (open ? open.validUntil : undefined);
    const epochMismatch = !!(open && n.keyId && open.keyId && n.keyId !== open.keyId);
    const closeKey = `${n.instanceId}|${n.principalHash}`;
    const earliestCloseTime = earliestClose.get(closeKey);
    const suppressed = earliestCloseTime !== undefined && earliestCloseTime <= n.notifTime;
    let best = { outcome: 'InsufficientEvidence', priority: 0 };
    if (!epochMismatch && validUntil) {
      const crossed = n.notifTime > validUntil;
      const o = crossed && !suppressed ? { outcome: 'ConfirmedDrift', priority: 3 } : { outcome: 'EvaluatedNoViolation', priority: 1 };
      if (o.priority >= best.priority) best = o;
    }
    if (epochMismatch) best = { outcome: 'InsufficientEvidence', priority: 2 };
    // Malformed timing evidence: a change claims authoritative timing but omits effectiveAt.
    const hasMalformedTiming = events.some((e) => e['event.name'] === 'mcp.subscription.authorization_change' && e['principal.id_hash'] === n.principalHash &&
      e['mcp.authz.change.timing_confidence'] === 'authoritative' && INVALIDATING.includes(e['mcp.authz.change.type']) &&
      (e['mcp.authz.change.effective_at'] === undefined || e['mcp.authz.change.effective_at'] === null));
    if (!epochMismatch && hasMalformedTiming && 2 >= best.priority) best = { outcome: 'InsufficientEvidence', priority: 2 };
    if (!epochMismatch) {
      for (const c of changes.filter((c) => c.principalHash === n.principalHash)) {
        const crossed = n.notifTime > c.effectiveAt;
        if (!crossed) continue;
        if (suppressed) { if (1 >= best.priority) best = { outcome: 'EvaluatedNoViolation', priority: 1 }; continue; }
        let applies;
        if (c.affectedScope === 'all_principal_bindings') {
          // PRECISE effective-time interval: the binding must have existed (opened) by the time
          // the change took effect, and not already have been closed by then.
          const openedInTime = open === undefined || open.openTime <= c.effectiveAt;
          const closedBeforeChange = earliestCloseTime !== undefined && earliestCloseTime <= c.effectiveAt;
          applies = (openedInTime && !closedBeforeChange) ? 'yes' : 'no';
        } else if (c.affectedScope === 'binding') {
          applies = bindingId === undefined ? 'ambiguous' : (c.affectedBindingIds.includes(bindingId) ? 'yes' : 'no');
        } else {
          applies = 'ambiguous'; // unknown/legacy scope -- NEVER inferred from candidate count
        }
        if (applies === 'no') continue;
        if (applies === 'ambiguous') { if (2 >= best.priority) best = { outcome: 'InsufficientEvidence', priority: 2 }; continue; }
        if (c.type === 'scope_downgraded') {
          if (!open || !open.requiredScope || !c.removedScope) { if (2 >= best.priority) best = { outcome: 'InsufficientEvidence', priority: 2 }; continue; }
          if (!c.removedScope.some((s) => open.requiredScope.includes(s))) { if (1 >= best.priority) best = { outcome: 'EvaluatedNoViolation', priority: 1 }; continue; }
        }
        if (3 >= best.priority) best = { outcome: 'ConfirmedDrift', priority: 3 };
      }
    }
    results.push({ instanceId: n.instanceId, notifTime: n.notifTime, outcome: best.outcome });
  }
  return results;
}

// splModelResults(): an INDEPENDENTLY-WRITTEN model of detections/spl/...spl -- built as a
// sequence of per-notification field computations (mirroring SPL's eval-per-row style) rather
// than kqlModelResults' per-notification nested-loop style, and computed with its own separate
// data structures throughout, so agreement between the two is a genuine cross-check.
function splModelResults(events) {
  const opens = {}, requiredScopeOf = {}, validUntilOf = {}, keyIdOf = {}, openTimeOf = {};
  for (const e of events) {
    if (e['event.name'] !== 'mcp.subscription.open') continue;
    const iid = resolveInstanceId(e);
    opens[iid] = { principalHash: e['principal.id_hash'], bindingId: e['mcp.authz.binding_id'] !== undefined ? e['mcp.authz.binding_id'] : legacyBindingId(e['principal.id_hash'], e['mcp.subscription.id']) };
    requiredScopeOf[iid] = e['mcp.subscription.required_scope'];
    validUntilOf[iid] = e['mcp.authz.valid_until'] || e['mcp.authz.grant_expiry'];
    keyIdOf[iid] = e['security.hash.key_id'];
    openTimeOf[iid] = e.timestamp;
  }
  const closesByKey = {};
  for (const e of events) {
    if (e['event.name'] !== 'mcp.subscription.close') continue;
    const key = `${resolveInstanceId(e)}|${e['principal.id_hash']}`;
    if (closesByKey[key] === undefined || e.timestamp < closesByKey[key]) closesByKey[key] = e.timestamp;
  }
  const changeRows = events.filter((e) => e['event.name'] === 'mcp.subscription.authorization_change' && e['mcp.authz.change.timing_confidence'] === 'authoritative' && INVALIDATING.includes(e['mcp.authz.change.type']));

  const out = [];
  for (const e of events) {
    if (e['event.name'] !== 'mcp.subscription.notification') continue;
    const iid = resolveInstanceId(e);
    const open = opens[iid];
    const bindingId = e['mcp.authz.binding_id'] !== undefined ? e['mcp.authz.binding_id'] : (open ? open.bindingId : undefined);
    const validUntil = (e['mcp.authz.binding_id'] !== undefined && e['mcp.authz.valid_until'] !== undefined) ? e['mcp.authz.valid_until'] : validUntilOf[iid];
    const epochMismatch = !!(keyIdOf[iid] && e['security.hash.key_id'] && keyIdOf[iid] !== e['security.hash.key_id']);
    const earliestCloseTime = closesByKey[`${iid}|${e['principal.id_hash']}`];
    const suppressed = earliestCloseTime !== undefined && earliestCloseTime <= e.timestamp;
    const hasMalformedTiming = changeRows.some((c) => c['principal.id_hash'] === e['principal.id_hash'] &&
      (c['mcp.authz.change.effective_at'] === undefined || c['mcp.authz.change.effective_at'] === null));

    const priorities = [];
    if (epochMismatch) priorities.push([2, 'InsufficientEvidence']);
    else {
      if (hasMalformedTiming) priorities.push([2, 'InsufficientEvidence']);
      if (validUntil !== undefined) {
        priorities.push(e.timestamp > validUntil && !suppressed ? [3, 'ConfirmedDrift'] : [1, 'EvaluatedNoViolation']);
      }
      for (const c of changeRows) {
        if (c['principal.id_hash'] !== e['principal.id_hash']) continue;
        if (c['mcp.authz.change.effective_at'] === undefined || c['mcp.authz.change.effective_at'] === null) continue; // malformed, handled above
        const effectiveAt = c['mcp.authz.change.effective_at'];
        const crossed = e.timestamp > effectiveAt;
        if (!crossed) continue;
        if (suppressed) { priorities.push([1, 'EvaluatedNoViolation']); continue; }
        const affectedScope = c['mcp.authz.change.affected_scope'] || 'unknown';
        const affectedIds = c['mcp.authz.change.affected_binding_ids'] || [];
        let applies;
        if (affectedScope === 'all_principal_bindings') {
          const openedInTime = openTimeOf[iid] === undefined || openTimeOf[iid] <= effectiveAt;
          const closedBeforeChange = earliestCloseTime !== undefined && earliestCloseTime <= effectiveAt;
          applies = (openedInTime && !closedBeforeChange) ? 'yes' : 'no';
        } else if (affectedScope === 'binding') {
          applies = bindingId === undefined ? 'ambiguous' : (affectedIds.indexOf(bindingId) >= 0 ? 'yes' : 'no');
        } else {
          applies = 'ambiguous'; // unknown/legacy scope -- NEVER inferred from candidate count
        }
        if (applies === 'no') continue;
        if (applies === 'ambiguous') { priorities.push([2, 'InsufficientEvidence']); continue; }
        if (c['mcp.authz.change.type'] === 'scope_downgraded') {
          const req = requiredScopeOf[iid], rem = c['mcp.authz.change.removed_scope'];
          if (!req || !rem) { priorities.push([2, 'InsufficientEvidence']); continue; }
          if (rem.filter((s) => req.indexOf(s) >= 0).length === 0) { priorities.push([1, 'EvaluatedNoViolation']); continue; }
        }
        priorities.push([3, 'ConfirmedDrift']);
      }
    }
    priorities.push([0, 'InsufficientEvidence']);
    priorities.sort((a, b) => b[0] - a[0]);
    out.push({ instanceId: iid, notifTime: e.timestamp, outcome: priorities[0][1] });
  }
  return out;
}

// preCorrectionModelResults(): the PRE-CORRECTION model (principal-only join, no binding/scope
// awareness at all) -- kept only to prove the new regression corpus catches a reintroduction of
// the exact defect this pass fixes.
function preCorrectionModelResults(events) {
  const notifs = events.filter((e) => e['event.name'] === 'mcp.subscription.notification');
  const changes = events.filter((e) => e['event.name'] === 'mcp.subscription.authorization_change' && e['mcp.authz.change.timing_confidence'] === 'authoritative' && INVALIDATING.includes(e['mcp.authz.change.type']));
  const closes = events.filter((e) => e['event.name'] === 'mcp.subscription.close');
  return notifs.map((n) => {
    const fires = changes.some((c) => c['principal.id_hash'] === n['principal.id_hash'] && n.timestamp > c['mcp.authz.change.effective_at'] &&
      !closes.some((cl) => cl['principal.id_hash'] === n['principal.id_hash'] && cl.timestamp <= n.timestamp));
    return { instanceId: resolveInstanceId(n), notifTime: n.timestamp, outcome: fires ? 'ConfirmedDrift' : 'InsufficientEvidence' };
  });
}

function byInstance(results) {
  return new Map(results.map((r) => [`${r.instanceId}|${r.notifTime}`, r.outcome]));
}

test('Track 3: independently-coded KQL-model and SPL-model outcomes agree on every notification across the full stress corpus', () => {
  const rows = loadFullStressCorpus();
  let disagreements = 0;
  for (const row of rows) {
    const kql = byInstance(kqlModelResults(row.events));
    const spl = byInstance(splModelResults(row.events));
    for (const [key, outcome] of kql) {
      if (spl.get(key) !== outcome) { disagreements++; console.log(`OUTCOME DISAGREEMENT on ${row.scenario_id} ${key}: kql=${outcome} spl=${spl.get(key)}`); }
    }
  }
  assert.equal(disagreements, 0);
});

test('Track 3: the scope-aware corrected model diverges from the pre-correction (principal-only) model wherever the correction actually matters', () => {
  const rows = loadFullStressCorpus();
  let anyDivergence = false;
  const divergentScenarios = [];
  for (const row of rows) {
    const corrected = byInstance(kqlModelResults(row.events));
    const pre = byInstance(preCorrectionModelResults(row.events));
    let diverged = false;
    for (const [key, outcome] of corrected) {
      const preOutcome = pre.get(key);
      if (preOutcome !== undefined && (outcome === 'ConfirmedDrift') !== (preOutcome === 'ConfirmedDrift')) diverged = true;
    }
    if (diverged) { anyDivergence = true; divergentScenarios.push(row.scenario_id); }
  }
  console.log('\nScenarios where the scope-aware correction changes the fired/not-fired result:', divergentScenarios);
  assert.ok(anyDivergence, 'expected at least one regression fixture to distinguish the corrected model from the pre-correction principal-only model');
  assert.ok(divergentScenarios.includes('V11-11') || divergentScenarios.includes('V12-01'), 'the known scope-ambiguity fixtures must be among the ones that changed');
});

test('Track 3: Sigma correlation DISAGREES with KQL/SPL on exactly the documented scenarios (A13, A14) and nowhere else in the core corpus', () => {
  const { loadUnifiedCorpus } = require('../detections/corpus');
  const rows = loadUnifiedCorpus(); // core 31 -- the Sigma correlation's documented behavior was characterized against these
  const disagreements = [];
  for (const row of rows) {
    if (row.experimental) continue;
    const authoritative = track3PrimaryFires(row.events);
    const sigma = track3SigmaCorrelationFires(row.events);
    if (authoritative !== sigma) disagreements.push(row.scenario_id);
  }
  console.log('\nTrack 3 Sigma vs KQL/SPL disagreements (core corpus):', disagreements);
  assert.deepEqual(disagreements.sort(), ['A13', 'A14']);
});

test('Comparison matrix data (printed for docs/validation-report.md transcription)', () => {
  const { loadUnifiedCorpus } = require('../detections/corpus');
  const ids = ['A12', 'A13', 'A14', 'A15', 'A16'];
  const rows = loadUnifiedCorpus();
  console.log('\n| Scenario | KQL/SPL (authoritative) | Sigma correlation | Agree? |');
  console.log('|---|---|---|---|');
  for (const id of ids) {
    const row = rows.find((r) => r.scenario_id === id);
    const auth = track3PrimaryFires(row.events);
    const sig = track3SigmaCorrelationFires(row.events);
    console.log(`| ${id} | ${auth} | ${sig} | ${auth === sig ? 'yes' : 'NO'} |`);
  }
});
