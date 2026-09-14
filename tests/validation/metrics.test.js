'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const { loadUnifiedCorpus, loadValidationCorpus, loadFullStressCorpus } = require('../detections/corpus');
const { track1PrimaryFires, track1DiagnosticFires, track2Fires, track3PrimaryFires, track3Resolution } = require('../detections/oracle');
const { evaluate, formatReport } = require('../detections/metrics');

test('Track 3 coverage report (mechanically computed): confirmed_drift / evaluated_no_violation / insufficient_evidence, reported separately -- reduced evaluability must never masquerade as clean detection', () => {
  const rows = loadFullStressCorpus().filter((r) => !r.experimental);
  let confirmed = 0, noViolation = 0, insufficient = 0;
  const reasons = {};
  for (const row of rows) {
    const { results } = track3Resolution(row.events);
    for (const r of results) {
      if (r.outcome === 'confirmed_drift') confirmed++;
      else if (r.outcome === 'evaluated_no_violation') noViolation++;
      else { insufficient++; reasons[r.reason] = (reasons[r.reason] || 0) + 1; }
    }
  }
  const total = confirmed + noViolation + insufficient;
  console.log(`\n=== Track 3 coverage (n=${total} evaluated notifications, full stress corpus) ===`);
  console.log(`confirmed_drift=${confirmed} (${(100 * confirmed / total).toFixed(1)}%)  evaluated_no_violation=${noViolation} (${(100 * noViolation / total).toFixed(1)}%)  insufficient_evidence=${insufficient} (${(100 * insufficient / total).toFixed(1)}%)`);
  console.log('insufficient_evidence reasons:', reasons);
  // Pinned so a change to this count is a deliberate, reviewed decision (new fixture, or a real
  // resolver change), not a silent drift -- see docs/validation-report.md for the full breakdown.
  assert.equal(total, 69);
  assert.equal(confirmed, 31);
  assert.equal(noViolation, 27);
  assert.equal(insufficient, 11);
  assert.deepEqual(reasons, {
    ambiguous_scope: 5, no_invalidity_evidence: 1, missing_scope_evidence: 2,
    conflicting_evidence: 1, incompatible_hash_epoch: 1, incomplete_timing_evidence: 1,
  });
});

test('Block 6 corpus sanity: 75 scenarios, 351 events, separate from Block 3/4 on disk', () => {
  const rows = loadValidationCorpus();
  assert.equal(rows.length, 75);
  const totalEvents = rows.reduce((n, r) => n + r.events.length, 0);
  assert.equal(totalEvents, 351);
  const fs = require('fs');
  const path = require('path');
  const normalDir = path.join(__dirname, '..', '..', 'data', 'normal');
  const attackDir = path.join(__dirname, '..', '..', 'data', 'attack');
  const validationDir = path.join(__dirname, '..', '..', 'data', 'validation');
  for (const r of rows) {
    const full = path.join(validationDir, r.file);
    assert.ok(fs.existsSync(full), `${r.scenario_id} file must live under data/validation/`);
    assert.ok(!full.startsWith(normalDir) || full.startsWith(validationDir), 'must not resolve into data/normal');
    assert.ok(!full.startsWith(attackDir), 'must not resolve into data/attack');
  }
});

test('CURATED CORE (Block 3 + Block 4, 31 scenarios): per-track metrics', () => {
  const rows = loadUnifiedCorpus();
  const r1 = evaluate(rows, track1PrimaryFires, 'expected1');
  const r2 = evaluate(rows, track2Fires, 'expected2');
  const r3 = evaluate(rows.filter((r) => !r.experimental), track3PrimaryFires, 'expected3');
  console.log('\n=== CURATED CORE (n=31) ===');
  console.log(formatReport('Track 1', r1));
  console.log(formatReport('Track 2', r2));
  console.log(formatReport('Track 3', r3));
  assert.equal(r1.fn, 0); assert.equal(r1.fp, 0);
  assert.equal(r2.fn, 0); assert.equal(r2.fp, 0);
  assert.equal(r3.fn, 0); assert.equal(r3.fp, 0);
});

test('FULL STRESS-TEST CORPUS (Block 3 + 4 + 6, 106 scenarios): per-track metrics -- NOT a real-world performance claim', () => {
  const rows = loadFullStressCorpus();
  assert.equal(rows.length, 106, '31 curated + 75 Block 6 validation scenarios');
  const r1 = evaluate(rows, track1PrimaryFires, 'expected1');
  const r2 = evaluate(rows, track2Fires, 'expected2');
  const r3 = evaluate(rows.filter((r) => !r.experimental), track3PrimaryFires, 'expected3');
  console.log('\n=== FULL STRESS-TEST CORPUS (n=106) -- controlled-corpus correctness only ===');
  console.log(formatReport('Track 1', r1));
  console.log(formatReport('Track 2', r2));
  console.log(formatReport('Track 3', r3));
  // Post-fix (scope_upgraded), the full stress corpus must ALSO show zero FP/FN. If a future
  // change reintroduces the bug or a new gap, this is where it will be caught.
  assert.equal(r1.fn, 0); assert.equal(r1.fp, 0);
  assert.equal(r2.fn, 0); assert.equal(r2.fp, 0);
  assert.equal(r3.fn, 0, 'Track 3 must have zero false negatives on the full stress corpus after the V5-03 fix');
  assert.equal(r3.fp, 0, 'Track 3 must have zero false positives on the full stress corpus after the V5-03 fix (V5-02/V5-09 are DELIBERATE, documented, accepted false positives excluded from this count -- see below)');
});

test('V5-09 (permanent policy exemption) still fires as an accepted false positive -- NOT a rule defect', () => {
  const rows = loadValidationCorpus();
  const v509 = rows.find((r) => r.scenario_id === 'V5-09');
  assert.equal(track3PrimaryFires(v509.events), true, 'V5-09 mechanically fires -- no policy-exception field exists in the locked schema to suppress it');
  assert.equal(v509.expected3, true);
});

test('V5-02 (scope-downgrade grace period, RECLASSIFIED by the scope-aware correction): now reports insufficient_evidence, not a confirmed accepted false positive', () => {
  const rows = loadValidationCorpus();
  const v502 = rows.find((r) => r.scenario_id === 'V5-02');
  assert.equal(track3PrimaryFires(v502.events), false, 'POST-CORRECTION: no required_scope/removed_scope evidence exists to establish relevance, so this no longer mechanically fires');
  assert.equal(v502.expected3, false);
  const { track3Resolution } = require('../detections/oracle');
  const { coverage } = track3Resolution(v502.events);
  assert.equal(coverage.insufficientEvidence, 1, 'the one notification must be reported as insufficient_evidence, not silently cleared as evaluated_no_violation');
});

test('V5-03 (the fixed bug): renewal (scope_upgraded) no longer produces a false positive', () => {
  const rows = loadValidationCorpus();
  const v503 = rows.find((r) => r.scenario_id === 'V5-03');
  assert.equal(track3PrimaryFires(v503.events), false, 'POST-FIX behavior');
  assert.equal(v503.expected3, false);
});

test('Track 1 required-behavior spot checks across the full validation corpus', () => {
  const rows = loadValidationCorpus();
  for (const id of ['V1-01','V1-02','V1-03','V1-04','V1-05','V1-06','V1-07','V1-09']) {
    const r = rows.find((x) => x.scenario_id === id);
    assert.equal(track1PrimaryFires(r.events), false, `${id} must not fire Track 1 primary`);
  }
  const v108 = rows.find((r) => r.scenario_id === 'V1-08');
  assert.equal(track1PrimaryFires(v108.events), true, 'V1-08 mechanically fires given its (artifactual) conflict field -- documented instrumentation-risk case, not a rule defect');
  const v201 = rows.find((r) => r.scenario_id === 'V2-01');
  assert.equal(track1PrimaryFires(v201.events), false);
  assert.equal(track2Fires(v201.events), true, 'V2-01: Track 2 must independently catch what Track 1 correctly cannot');
});

test('Track 1 diagnostic fires exactly on V1-02 (the one genuine "missing under a required version" fixture in the whole project)', () => {
  const rows = loadValidationCorpus();
  const v102 = rows.find((r) => r.scenario_id === 'V1-02');
  assert.equal(track1DiagnosticFires(v102.events), true);
  assert.equal(track1PrimaryFires(v102.events), false, 'must not ALSO fire the primary rule');
});

test('Track 2 required-behavior spot checks across the full validation corpus', () => {
  const rows = loadValidationCorpus();
  for (const id of ['V3-01','V3-03','V3-04','V3-05','V3-06','V3-07','V4-01','V4-02']) {
    const r = rows.find((x) => x.scenario_id === id);
    assert.equal(track2Fires(r.events), false, `${id} must not fire Track 2`);
  }
  const v302 = rows.find((r) => r.scenario_id === 'V3-02');
  // V3-02 contains BOTH a real historical deny (must fire) and a later allow (must not) --
  // evaluate per JSON-RPC request id, not per-file, to make the point meaningfully.
  const denyEvent = v302.events.find((e) => e['event.name'] === 'mcp.task.authorization' && e['mcp.authz.decision'] === 'deny');
  const allowEvent = v302.events.find((e) => e['event.name'] === 'mcp.task.authorization' && e['mcp.authz.decision'] === 'allow');
  assert.equal(track2Fires([denyEvent]), true, 'the earlier deny (policy-v1) is a real historical Track 2 hit');
  assert.equal(track2Fires([allowEvent]), false, 'the later allow (policy-v2) is not');
});

test('Track 3 required-behavior spot checks across the full validation corpus', () => {
  const rows = loadValidationCorpus();
  const mustNotFire = [
    'V5-01', 'V5-02', 'V5-04', 'V5-05', 'V5-06', 'V6-01', 'V6-02',
    'V11-05', 'V11-07', 'V11-08', 'V11-09', 'V11-11',
    'V12-03', 'V12-06', 'V12-09', 'V12-10', 'V12-11',
    'V13-02', 'V13-03', 'V13-04', 'V13-05',
    'V14-04', 'V14-05', 'V14-06', 'V14-07',
  ];
  for (const id of mustNotFire) {
    const r = rows.find((x) => x.scenario_id === id);
    assert.equal(track3PrimaryFires(r.events), false, `${id} must not fire`);
  }
  const mustFire = [
    'V5-07',
    'V11-01', 'V11-02', 'V11-03', 'V11-04', 'V11-06', 'V11-10',
    'V12-01', 'V12-02', 'V12-04', 'V12-05', 'V12-07', 'V12-08', 'V12-12', 'V12-13',
    'V13-01', 'V13-06',
    'V14-01', 'V14-02', 'V14-03', 'V14-08',
  ];
  for (const id of mustFire) {
    const r = rows.find((x) => x.scenario_id === id);
    assert.equal(track3PrimaryFires(r.events), true, `${id} must fire`);
  }
});

test('Enrichment (V8) required behavior', () => {
  const rows = loadValidationCorpus();
  assert.equal(track1PrimaryFires(rows.find((r) => r.scenario_id === 'V8-01').events), true, 'tiny payload must not suppress a real Track 1 hit');
  assert.equal(track1PrimaryFires(rows.find((r) => r.scenario_id === 'V8-02').events), false);
  assert.equal(track2Fires(rows.find((r) => r.scenario_id === 'V8-02').events), false);
  assert.equal(track3PrimaryFires(rows.find((r) => r.scenario_id === 'V8-02').events), false, 'huge output alone must never fire any track');
  assert.equal(track2Fires(rows.find((r) => r.scenario_id === 'V8-03').events), false);
  assert.equal(track1PrimaryFires(rows.find((r) => r.scenario_id === 'V8-03').events), false, 'high token count alone must never fire any track');
  assert.equal(track2Fires(rows.find((r) => r.scenario_id === 'V8-04').events), false, 'schema-invalid benign bug must not fire');
  assert.equal(track2Fires(rows.find((r) => r.scenario_id === 'V8-05').events), true, 'low-token violation must still fire');
});
