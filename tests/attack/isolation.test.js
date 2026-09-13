'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const { readAllScenarios } = require('./helpers');

test('Cross-track isolation: at least one scenario fires Track 1 only', () => {
  const { manifest } = readAllScenarios();
  const hits = manifest.filter((r) =>
    r.expected_detection_track_1 === true &&
    r.expected_detection_track_2 === false &&
    r.expected_detection_track_3 === false
  );
  assert.ok(hits.length > 0, 'expected at least one Track-1-only scenario (e.g. A1)');
  assert.ok(hits.every((r) => r.cross_track_isolation === 'track1_only'), 'every Track-1-only hit must be tagged track1_only');
});

test('Cross-track isolation: at least one scenario fires Track 2 only', () => {
  const { manifest } = readAllScenarios();
  const hits = manifest.filter((r) =>
    r.expected_detection_track_1 === false &&
    r.expected_detection_track_2 === true &&
    r.expected_detection_track_3 === false
  );
  assert.ok(hits.length > 0, 'expected at least one Track-2-only scenario (e.g. A7/A10)');
  assert.ok(hits.every((r) => r.cross_track_isolation === 'track2_only'));
});

test('Cross-track isolation: at least one scenario fires Track 3 only', () => {
  const { manifest } = readAllScenarios();
  const hits = manifest.filter((r) =>
    r.expected_detection_track_1 === false &&
    r.expected_detection_track_2 === false &&
    r.expected_detection_track_3 === true &&
    !r.experimental
  );
  assert.ok(hits.length > 0, 'expected at least one non-experimental Track-3-only scenario (e.g. A12/A13/A14)');
  assert.ok(hits.every((r) => r.cross_track_isolation === 'track3_only'));
});

test('Cross-track isolation: no scenario fires all three tracks simultaneously (none constructed here)', () => {
  const { manifest } = readAllScenarios();
  const all3 = manifest.filter((r) => r.expected_detection_track_1 && r.expected_detection_track_2 && r.expected_detection_track_3);
  assert.equal(all3.length, 0);
});

test('Combined scenario (A17): both Track 1 and Track 2 fire, proving they are additive, not exclusive', () => {
  const { byScenario } = readAllScenarios();
  const a17 = byScenario.get('A17');
  assert.ok(a17, 'A17 combined scenario must exist');
  assert.equal(a17.manifest.expected_detection_track_1, true);
  assert.equal(a17.manifest.expected_detection_track_2, true);
  assert.equal(a17.manifest.expected_detection_track_3, false);
  assert.equal(a17.manifest.cross_track_isolation, 'combined');
  // The two findings must come from two DISTINCT requests, per Block 1/2 (a HeaderMismatch
  // rejection never reaches authorization) -- not one event magically tripping both tracks.
  const reqIds = new Set(a17.events.map((e) => e['jsonrpc.request.id']).filter(Boolean));
  assert.equal(reqIds.size, 2, 'A17 must involve exactly two distinct JSON-RPC requests');
});
