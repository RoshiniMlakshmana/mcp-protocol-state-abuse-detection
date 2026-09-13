'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const { readAllScenarios, readJsonl } = require('./helpers');

const EXPECTED_IDS = ['A1','A2','A3','A4','A5','A6','A7','A8','A9','A10','A11','A12','A13','A14','A15','A16','A-EXP1','A17'];
const REQUIRED_FIELDS = [
  'scenario_id', 'description', 'provenance',
  'expected_detection_track_1', 'expected_detection_track_2', 'expected_detection_track_3',
  'expected_confidence', 'violated_invariant', 'required_evidence', 'notes'
];

test('Manifest: all required scenarios present exactly once, with every required ground-truth field', () => {
  const { manifest } = readAllScenarios();
  const ids = manifest.map((r) => r.scenario_id);
  for (const id of EXPECTED_IDS) assert.ok(ids.includes(id), `missing scenario ${id}`);
  assert.equal(new Set(ids).size, ids.length, 'duplicate scenario_id');
  for (const row of manifest) {
    for (const field of REQUIRED_FIELDS) {
      assert.ok(field in row, `${row.scenario_id} missing required field ${field}`);
    }
    assert.ok(Array.isArray(row.required_evidence) && row.required_evidence.length > 0, `${row.scenario_id} required_evidence must be a non-empty array`);
  }
});

test('Manifest: A1/A10/A12 ground truth matches the brief\'s worked examples exactly', () => {
  const { byScenario } = readAllScenarios();
  const a1 = byScenario.get('A1').manifest;
  assert.equal(a1.expected_detection_track_1, true);
  assert.equal(a1.expected_detection_track_2, false);
  assert.equal(a1.expected_detection_track_3, false);

  const a10 = byScenario.get('A10').manifest;
  assert.equal(a10.expected_detection_track_1, false);
  assert.equal(a10.expected_detection_track_2, true);
  assert.equal(a10.expected_detection_track_3, false);

  const a12 = byScenario.get('A12').manifest;
  assert.equal(a12.expected_detection_track_1, false);
  assert.equal(a12.expected_detection_track_2, false);
  assert.equal(a12.expected_detection_track_3, true);

  const a15 = byScenario.get('A15').manifest;
  assert.equal(a15.expected_detection_track_3, false);
});

test('Manifest: provenance is always a recognized label; experimental scenarios are marked', () => {
  const { manifest } = readAllScenarios();
  const allowed = new Set(['official_sdk_v2', 'project_reference_harness', 'synthetic_enrichment']);
  for (const row of manifest) {
    assert.ok(allowed.has(row.provenance), `${row.scenario_id} has unrecognized provenance ${row.provenance}`);
  }
  const exp = manifest.find((r) => r.scenario_id === 'A-EXP1');
  assert.equal(exp.experimental, true);
  assert.ok(exp.notes.toLowerCase().includes('experimental') || exp.description.toLowerCase().includes('experimental'));
  for (const row of manifest) {
    if (row.scenario_id !== 'A-EXP1') assert.equal(row.experimental, false, `${row.scenario_id} must not be marked experimental`);
  }
});

test('Manifest: event_count (where present) matches the actual file line count', () => {
  const { manifest } = readAllScenarios();
  for (const row of manifest) {
    if (typeof row.event_count === 'number') {
      const actual = readJsonl(row.file).length;
      assert.equal(row.event_count, actual, `${row.scenario_id} event_count mismatch`);
    }
  }
});

test('Every attack event carrying a *_hash field also carries security.hash.key_id/algorithm (same scheme as Block 3)', () => {
  const { manifest } = readAllScenarios();
  const { HASH_KEY_ID, HASH_ALGORITHM } = require('../../tools/harness/lib/hash');
  for (const row of manifest) {
    for (const evt of readJsonl(row.file)) {
      const hasHash = Object.keys(evt).some((k) => k.endsWith('_hash') && evt[k] !== null);
      if (hasHash) {
        assert.equal(evt['security.hash.key_id'], HASH_KEY_ID);
        assert.equal(evt['security.hash.algorithm'], HASH_ALGORITHM);
      }
    }
  }
});

test('No attack/control event contains a raw bearer token, credential, or secret-shaped field', () => {
  const { manifest } = readAllScenarios();
  const allowlist = new Set(['gen_ai.usage.input_tokens', 'gen_ai.usage.output_tokens']);
  const forbidden = ['bearer', 'authorization_header', 'secret', 'password', 'api_key', 'access_token', 'refresh_token', 'client_secret'];
  for (const row of manifest) {
    for (const evt of readJsonl(row.file)) {
      for (const key of Object.keys(evt)) {
        if (allowlist.has(key)) continue;
        const lower = key.toLowerCase();
        for (const bad of forbidden) {
          assert.ok(!lower.includes(bad), `forbidden-looking field "${key}" in ${row.scenario_id}`);
        }
      }
    }
  }
});
