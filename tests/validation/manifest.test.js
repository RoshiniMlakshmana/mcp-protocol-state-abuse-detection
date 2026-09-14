'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const { loadValidationCorpus } = require('../detections/corpus');
const fs = require('fs');
const path = require('path');

const REQUIRED_FIELDS = [
  'scenario_id', 'file', 'purpose', 'expected_detection_track_1', 'expected_detection_track_2',
  'expected_detection_track_3', 'expected_confidence', 'false_positive_test', 'evasion_test',
  'telemetry_limitation', 'notes'
];

test('Every Block 6 validation scenario has all required ground-truth fields', () => {
  const manifestPath = path.join(__dirname, '..', '..', 'data', 'validation', 'manifest.jsonl');
  const rows = fs.readFileSync(manifestPath, 'utf8').trim().split('\n').map(JSON.parse);
  assert.equal(rows.length, 61);
  const ids = rows.map((r) => r.scenario_id);
  assert.equal(new Set(ids).size, ids.length, 'no duplicate scenario_id');
  for (const row of rows) {
    for (const field of REQUIRED_FIELDS) {
      assert.ok(field in row, `${row.scenario_id} missing required field ${field}`);
    }
  }
});

test('Every declared false_positive_test or evasion_test scenario carries a non-empty purpose', () => {
  const rows = loadValidationCorpus();
  const manifestPath = path.join(__dirname, '..', '..', 'data', 'validation', 'manifest.jsonl');
  const manifest = fs.readFileSync(manifestPath, 'utf8').trim().split('\n').map(JSON.parse);
  for (const row of manifest) {
    if (row.false_positive_test || row.evasion_test) {
      assert.ok(row.purpose && row.purpose.length > 20, `${row.scenario_id}: needs a substantive purpose`);
    }
  }
  assert.equal(rows.length, 61);
});

test('Every evasion_test scenario is classified in its notes/telemetry_limitation as detectable/partially/not detectable', () => {
  const manifestPath = path.join(__dirname, '..', '..', 'data', 'validation', 'manifest.jsonl');
  const manifest = fs.readFileSync(manifestPath, 'utf8').trim().split('\n').map(JSON.parse);
  const evasions = manifest.filter((r) => r.evasion_test);
  assert.ok(evasions.length >= 5, 'expected multiple evasion-documentation scenarios across V2/V4/V6 (V2-01, V4-01, V4-02, V6-01, V6-02)');
  for (const row of evasions) {
    const text = `${row.purpose} ${row.telemetry_limitation || ''}`.toUpperCase();
    assert.ok(
      text.includes('NOT DETECTABLE') || text.includes('PARTIALLY DETECTABLE') || text.includes('DETECTABLE'),
      `${row.scenario_id}: evasion scenario must state a detectability classification`
    );
  }
});

test('Scenario directories match the suggested Block 6 layout (track1/track2/track3/enrichment/hashing)', () => {
  const manifestPath = path.join(__dirname, '..', '..', 'data', 'validation', 'manifest.jsonl');
  const manifest = fs.readFileSync(manifestPath, 'utf8').trim().split('\n').map(JSON.parse);
  const allowedDirs = new Set(['track1', 'track2', 'track3', 'enrichment', 'hashing']);
  for (const row of manifest) {
    const dir = row.file.split('/')[0];
    assert.ok(allowedDirs.has(dir), `${row.scenario_id}: unexpected directory ${dir}`);
  }
});

test('Block 6 corpus never overlaps Block 3/4 file paths', () => {
  const manifestPath = path.join(__dirname, '..', '..', 'data', 'validation', 'manifest.jsonl');
  const manifest = fs.readFileSync(manifestPath, 'utf8').trim().split('\n').map(JSON.parse);
  for (const row of manifest) {
    assert.ok(!row.file.includes('..'), `${row.scenario_id}: must not reference outside data/validation/ (unlike Block 4's A11 pattern)`);
  }
});
