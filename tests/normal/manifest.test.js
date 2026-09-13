'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const { readAllScenarioEvents } = require('./helpers');

test('Manifest: all 13 required scenarios are present exactly once', () => {
  const { manifest } = readAllScenarioEvents();
  const ids = manifest.map((r) => r.scenario_id);
  const expected = ['N1','N2','N3','N4','N5','N6','N7','N8','N9','N10','N11','N12','N13'];
  for (const id of expected) assert.ok(ids.includes(id), `missing scenario ${id}`);
  assert.equal(new Set(ids).size, ids.length, 'duplicate scenario_id in manifest');
});

test('Manifest: every normal scenario expects zero Track 1/2/3 alerts', () => {
  const { manifest } = readAllScenarioEvents();
  for (const row of manifest) {
    assert.equal(row.expected_detection_track_1, false, `${row.scenario_id} track1 must be false`);
    assert.equal(row.expected_detection_track_2, false, `${row.scenario_id} track2 must be false`);
    assert.equal(row.expected_detection_track_3, false, `${row.scenario_id} track3 must be false`);
    assert.ok(row.expected_security_outcome.startsWith('benign'), `${row.scenario_id} outcome must be a benign_* label, got ${row.expected_security_outcome}`);
  }
});

test('Manifest: reported event_count matches the actual number of lines in each file', () => {
  const { manifest } = readAllScenarioEvents();
  const { readJsonl } = require('./helpers');
  for (const row of manifest) {
    const actual = readJsonl(row.file).length;
    assert.equal(row.event_count, actual, `${row.scenario_id} event_count mismatch`);
  }
});

test('Manifest: every scenario declares a recognized provenance label, never claims official_sdk_v2 without cause', () => {
  const { manifest } = readAllScenarioEvents();
  const allowed = new Set(['official_sdk_v2', 'project_reference_harness', 'synthetic_enrichment']);
  for (const row of manifest) {
    assert.ok(allowed.has(row.provenance), `${row.scenario_id} has unrecognized provenance ${row.provenance}`);
    // Per docs/sdk-discrepancy.md: no scenario in this corpus is currently SDK-captured.
    assert.notEqual(row.provenance, 'official_sdk_v2');
  }
});

test('Manifest: non-conformant/synthetic scenarios are labeled, never bare "benign"', () => {
  const { manifest } = readAllScenarioEvents();
  const n11 = manifest.find((r) => r.scenario_id === 'N11');
  const n12 = manifest.find((r) => r.scenario_id === 'N12');
  const n13 = manifest.find((r) => r.scenario_id === 'N13');
  assert.equal(n11.provenance, 'synthetic_enrichment');
  assert.notEqual(n11.expected_security_outcome, 'benign');
  assert.notEqual(n12.expected_security_outcome, 'benign');
  assert.notEqual(n13.expected_security_outcome, 'benign');
});
