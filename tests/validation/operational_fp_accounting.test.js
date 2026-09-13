'use strict';
/**
 * Operational stress / environmental false-positive accounting (post-hoc audit correction).
 *
 * This is DELIBERATELY SEPARATE from metrics.test.js's "controlled in-scope correctness"
 * view. That view measures whether each rule fires exactly when ITS OWN declared trigger
 * condition is met, GIVEN trustworthy inputs and no unmodeled deployment policy (grace
 * periods, permanent exemptions, correct canonicalization). Several scenarios satisfy that
 * declared trigger condition while being, in an actual deployment, entirely benign -- because
 * the trigger condition's own PREREQUISITES (trustworthy parsing; no unmodeled grace period or
 * exemption policy) are violated. Those scenarios are false positives in the OPERATIONAL
 * sense, and reporting only the in-scope numbers without this table would hide that.
 *
 * This test computes the table mechanically (not by re-reading prose) and pins the exact set
 * of scenarios it identifies, so a future change that silently grows or shrinks this set is
 * caught rather than drifting unnoticed.
 */
const test = require('node:test');
const assert = require('node:assert/strict');
const { loadValidationCorpus } = require('../detections/corpus');
const { track1PrimaryFires, track2Fires, track3PrimaryFires } = require('../detections/oracle');

function classify(row) {
  const f1 = track1PrimaryFires(row.events);
  const f2 = track2Fires(row.events);
  const f3 = track3PrimaryFires(row.events);
  const firesAny = f1 || f2 || f3;
  return { f1, f2, f3, firesAny };
}

test('Operational false-positive accounting table (mechanically computed)', () => {
  const rows = loadValidationCorpus();
  const flaggedAndFiring = rows
    .filter((r) => r.false_positive_test)
    .map((r) => ({ row: r, ...classify(r) }))
    .filter((x) => x.firesAny);

  console.log('\n| Scenario | Rule fires? | Benign? | Root cause | Rule defect? | Deployment prerequisite/tuning |');
  console.log('|---|---|---|---|---|---|');
  for (const x of flaggedAndFiring) {
    console.log(`| ${x.row.scenario_id} | Track${x.f1 ? '1' : x.f2 ? '2' : '3'}=true | ? | see docs/false-positive-analysis.md | ? | see docs/false-positive-analysis.md |`);
  }

  const ids = flaggedAndFiring.map((x) => x.row.scenario_id).sort();
  // Pinned set, re-derived mechanically each run rather than hand-maintained:
  // V1-08 (collector canonicalization artifact), V5-02 (grace-period policy),
  // V5-09 (permanent exemption policy) are TRUE operational false positives: the rule fires
  // on an event that is entirely benign once the violated prerequisite is accounted for.
  // V3-02 is EXCLUDED from that bucket on purpose: it fires because it contains a genuine
  // historical Track 2 violation event (denied under policy-v1) alongside a later benign
  // allow (policy-v2) in the SAME file -- the fire is correct given a REAL violation, not an
  // artifact of a violated prerequisite. See the per-event assertion in metrics.test.js.
  assert.deepEqual(ids, ['V1-08', 'V3-02', 'V5-02', 'V5-09'].sort(), 'the set of false_positive_test-flagged scenarios that mechanically fire must be exactly these four');

  const trueOperationalFPs = ids.filter((id) => id !== 'V3-02');
  assert.deepEqual(trueOperationalFPs.sort(), ['V1-08', 'V5-02', 'V5-09'].sort(), 'true operational false positives (benign trigger, not a real violation)');
});

test('V3-02 is correctly excluded from the operational-FP bucket: its fire is a genuine historical violation, not a benign artifact', () => {
  const rows = loadValidationCorpus();
  const v302 = rows.find((r) => r.scenario_id === 'V3-02');
  const denyEvent = v302.events.find((e) => e['event.name'] === 'mcp.task.authorization' && e['mcp.authz.decision'] === 'deny');
  const allowEvent = v302.events.find((e) => e['event.name'] === 'mcp.task.authorization' && e['mcp.authz.decision'] === 'allow');
  assert.equal(track2Fires([denyEvent]), true, 'the deny event alone is a genuine violation -- not benign');
  assert.equal(track2Fires([allowEvent]), false);
});

test('Every true operational false positive (V1-08, V5-02, V5-09) has NOT been classified as a rule defect', () => {
  const fs = require('fs');
  const path = require('path');
  const manifestPath = path.join(__dirname, '..', '..', 'data', 'validation', 'manifest.jsonl');
  const manifest = fs.readFileSync(manifestPath, 'utf8').trim().split('\n').map(JSON.parse);
  for (const id of ['V1-08', 'V5-02', 'V5-09']) {
    const row = manifest.find((r) => r.scenario_id === id);
    assert.ok(row.telemetry_limitation, `${id} must document its telemetry_limitation / prerequisite gap`);
    assert.doesNotMatch(row.telemetry_limitation.toLowerCase(), /rule defect|logic (bug|defect|error)/, `${id} must not be described as a rule-logic defect`);
  }
});
