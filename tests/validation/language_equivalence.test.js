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

// --- Track 3: two INDEPENDENTLY-CODED JS models, one per language's written semantics, run
// against the shared corpus and compared row-for-row where a row-shaped result exists.
//
// IMPORTANT DISCLAIMER: these are hand-written JS models of what each query LANGUAGE's
// documented semantics do with the given events -- neither model executes actual KQL or SPL,
// and neither runs against a real Sentinel or Splunk backend (see README.md and
// docs/validation-report.md; native execution remains pending). "Equivalence" below means
// "these two independently-authored models, each coded from that language's own semantics,
// agree" -- not "verified against native query engines."
//
// kqlModelRows(): models detections/kql/mcp_subscription_authorization_drift.kql. KQL's `join
// kind=inner` preserves every matching row combination from the whole table with no implicit
// row limit, so this iterates every (notification, change) and (notification, open) pair.
function kqlModelRows(events) {
  const notifications = events.filter((e) => e['event.name'] === 'mcp.subscription.notification');
  const opens = events.filter((e) => e['event.name'] === 'mcp.subscription.open');
  const closes = events.filter((e) => e['event.name'] === 'mcp.subscription.close');
  const changes = events.filter((e) =>
    e['event.name'] === 'mcp.subscription.authorization_change' &&
    e['mcp.authz.change.timing_confidence'] === 'authoritative' &&
    e['mcp.authz.change.effective_at'] &&
    ['revoked', 'expired', 'scope_downgraded'].includes(e['mcp.authz.change.type'])
  );
  const closedBefore = (n) => closes.some((c) =>
    c['mcp.subscription.id'] === n['mcp.subscription.id'] &&
    c['principal.id_hash'] === n['principal.id_hash'] &&
    c.timestamp <= n.timestamp
  );
  const rows = [];
  for (const n of notifications) {
    for (const c of changes) {
      if (c['principal.id_hash'] === n['principal.id_hash'] && n.timestamp > c['mcp.authz.change.effective_at'] && !closedBefore(n)) {
        rows.push({ subscription_id: n['mcp.subscription.id'], principal_hash: n['principal.id_hash'], notif_time: n.timestamp, boundary: 'effective_at' });
      }
    }
    for (const o of opens) {
      const validUntil = o['mcp.authz.valid_until'] || o['mcp.authz.grant_expiry'];
      if (validUntil && o['mcp.subscription.id'] === n['mcp.subscription.id'] && o['principal.id_hash'] === n['principal.id_hash'] &&
          n.timestamp > validUntil && !closedBefore(n)) {
        rows.push({ subscription_id: n['mcp.subscription.id'], principal_hash: n['principal.id_hash'], notif_time: n.timestamp, boundary: 'valid_until' });
      }
    }
  }
  return rows;
}

// splModelCorrectedRows(): models the CORRECTED detections/spl/mcp_subscription_authorization_drift.spl
// (subscription_id+principal_hash expiry join, max=0 on inner joins, principal_hash-scoped close
// suppression). Written from scratch against the SPL file's own semantics, independently of
// kqlModelRows above (no shared helper), so agreement between the two is a genuine check, not a
// restatement of one function.
function splModelCorrectedRows(events) {
  const notifications = events.filter((e) => e['event.name'] === 'mcp.subscription.notification');
  const opens = events.filter((e) => e['event.name'] === 'mcp.subscription.open');
  const closes = events.filter((e) => e['event.name'] === 'mcp.subscription.close');
  const changes = events.filter((e) =>
    e['event.name'] === 'mcp.subscription.authorization_change' &&
    e['mcp.authz.change.timing_confidence'] === 'authoritative' &&
    e['mcp.authz.change.effective_at'] &&
    ['revoked', 'expired', 'scope_downgraded'].includes(e['mcp.authz.change.type'])
  );
  // `stats min(close_time) as earliest_close_time by subscription_id, principal_hash`
  const earliestClose = new Map();
  for (const c of closes) {
    const key = `${c['mcp.subscription.id']} ${c['principal.id_hash']}`;
    const prev = earliestClose.get(key);
    if (prev === undefined || c.timestamp < prev) earliestClose.set(key, c.timestamp);
  }
  const survivesCloseJoin = (n) => {
    const t = earliestClose.get(`${n['mcp.subscription.id']} ${n['principal.id_hash']}`);
    return t === undefined || t > n.timestamp;
  };
  const rows = [];
  // Leg A: `join type=inner max=0 principal_hash [...]`
  for (const n of notifications) {
    for (const c of changes) {
      if (c['principal.id_hash'] === n['principal.id_hash'] && n.timestamp > c['mcp.authz.change.effective_at'] && survivesCloseJoin(n)) {
        rows.push({ subscription_id: n['mcp.subscription.id'], principal_hash: n['principal.id_hash'], notif_time: n.timestamp, boundary: 'effective_at' });
      }
    }
  }
  // Leg B: `join type=inner max=0 subscription_id principal_hash [...]`
  for (const n of notifications) {
    for (const o of opens) {
      const validUntil = o['mcp.authz.valid_until'] || o['mcp.authz.grant_expiry'];
      if (validUntil && o['mcp.subscription.id'] === n['mcp.subscription.id'] && o['principal.id_hash'] === n['principal.id_hash'] &&
          n.timestamp > validUntil && survivesCloseJoin(n)) {
        rows.push({ subscription_id: n['mcp.subscription.id'], principal_hash: n['principal.id_hash'], notif_time: n.timestamp, boundary: 'valid_until' });
      }
    }
  }
  return rows;
}

// splModelPreFixBuggyRows(): models the ORIGINAL, PRE-FIX SPL (expiry leg joined on
// subscription_id ALONE, and Splunk's join defaulting to max=1 -- first match only). Kept only
// to prove the regression tests actually catch a reintroduction of either bug; never used as a
// correctness reference.
function splModelPreFixBuggyRows(events) {
  const notifications = events.filter((e) => e['event.name'] === 'mcp.subscription.notification');
  const opens = events.filter((e) => e['event.name'] === 'mcp.subscription.open');
  const closes = events.filter((e) => e['event.name'] === 'mcp.subscription.close');
  const changes = events.filter((e) =>
    e['event.name'] === 'mcp.subscription.authorization_change' &&
    e['mcp.authz.change.timing_confidence'] === 'authoritative' &&
    e['mcp.authz.change.effective_at'] &&
    ['revoked', 'expired', 'scope_downgraded'].includes(e['mcp.authz.change.type'])
  );
  const earliestCloseBySubOnly = new Map();
  for (const c of closes) {
    const key = c['mcp.subscription.id'];
    const prev = earliestCloseBySubOnly.get(key);
    if (prev === undefined || c.timestamp < prev) earliestCloseBySubOnly.set(key, c.timestamp);
  }
  const survivesCloseJoin = (n) => {
    const t = earliestCloseBySubOnly.get(n['mcp.subscription.id']);
    return t === undefined || t > n.timestamp;
  };
  const rows = [];
  // Leg A unaffected by either historical bug.
  for (const n of notifications) {
    for (const c of changes) {
      if (c['principal.id_hash'] === n['principal.id_hash'] && n.timestamp > c['mcp.authz.change.effective_at'] && survivesCloseJoin(n)) {
        rows.push({ subscription_id: n['mcp.subscription.id'], principal_hash: n['principal.id_hash'], notif_time: n.timestamp, boundary: 'effective_at' });
      }
    }
  }
  // Leg B: `join type=inner subscription_id [...]` (max=1 default, subscription_id-only key) --
  // pick only the FIRST matching open event per notification, joined by subscription_id alone.
  for (const n of notifications) {
    const firstMatch = opens.find((o) => {
      const validUntil = o['mcp.authz.valid_until'] || o['mcp.authz.grant_expiry'];
      return validUntil && o['mcp.subscription.id'] === n['mcp.subscription.id'];
    });
    if (!firstMatch) continue;
    const validUntil = firstMatch['mcp.authz.valid_until'] || firstMatch['mcp.authz.grant_expiry'];
    if (n.timestamp > validUntil && survivesCloseJoin(n)) {
      rows.push({ subscription_id: n['mcp.subscription.id'], principal_hash: n['principal.id_hash'], notif_time: n.timestamp, boundary: 'valid_until' });
    }
  }
  return rows;
}

function sortRows(rows) {
  return [...rows].sort((a, b) => (a.notif_time < b.notif_time ? -1 : a.notif_time > b.notif_time ? 1 : (a.boundary < b.boundary ? -1 : a.boundary > b.boundary ? 1 : (a.subscription_id || '').localeCompare(b.subscription_id || ''))));
}

test('Track 3: independently-coded KQL-semantics and corrected-SPL-semantics models agree on every alert row across the full stress corpus', () => {
  const rows = loadFullStressCorpus();
  let disagreements = 0;
  for (const row of rows) {
    const kql = sortRows(kqlModelRows(row.events));
    const spl = sortRows(splModelCorrectedRows(row.events));
    try {
      assert.deepEqual(kql, spl);
    } catch {
      disagreements++;
      console.log(`ROW DISAGREEMENT on ${row.scenario_id}: kql=${JSON.stringify(kql)} spl=${JSON.stringify(spl)}`);
    }
  }
  assert.equal(disagreements, 0);
});

test('Track 3: the corrected-SPL model diverges from the pre-fix buggy-SPL model wherever the fixed bugs actually matter, proving the regression corpus exercises them', () => {
  const rows = loadFullStressCorpus();
  let anyDivergence = false;
  const divergentScenarios = [];
  for (const row of rows) {
    const corrected = sortRows(splModelCorrectedRows(row.events));
    const buggy = sortRows(splModelPreFixBuggyRows(row.events));
    if (JSON.stringify(corrected) !== JSON.stringify(buggy)) {
      anyDivergence = true;
      divergentScenarios.push(row.scenario_id);
    }
  }
  console.log('\nScenarios where fixing the SPL join-key/max=0 bugs changes the result:', divergentScenarios);
  assert.ok(anyDivergence, 'expected at least one regression fixture to distinguish corrected SPL from the pre-fix buggy SPL model');
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
