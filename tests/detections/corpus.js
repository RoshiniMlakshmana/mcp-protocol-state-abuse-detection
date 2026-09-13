'use strict';
const fs = require('fs');
const path = require('path');

const NORMAL_DIR = path.join(__dirname, '..', '..', 'data', 'normal');
const ATTACK_DIR = path.join(__dirname, '..', '..', 'data', 'attack');
const VALIDATION_DIR = path.join(__dirname, '..', '..', 'data', 'validation');

function readJsonl(fullPath) {
  return fs.readFileSync(fullPath, 'utf8').trim().split('\n').filter(Boolean).map((l) => JSON.parse(l));
}

/**
 * Loads every scenario from both the Block 3 normal manifest and the Block 4 attack manifest
 * into one unified list: { scenario_id, source, expected1, expected2, expected3, events }.
 * File paths are resolved relative to each manifest's own directory (data/attack's A11 points
 * at "../normal/authorized_shared_access.jsonl", which correctly resolves back into
 * data/normal/).
 */
function loadUnifiedCorpus() {
  const rows = [];

  const normalManifest = readJsonl(path.join(NORMAL_DIR, 'manifest.jsonl'));
  for (const r of normalManifest) {
    rows.push({
      scenario_id: r.scenario_id,
      source: 'block3_normal',
      expected1: r.expected_detection_track_1,
      expected2: r.expected_detection_track_2,
      expected3: r.expected_detection_track_3,
      experimental: false,
      events: readJsonl(path.join(NORMAL_DIR, r.file))
    });
  }

  const attackManifest = readJsonl(path.join(ATTACK_DIR, 'manifest.jsonl'));
  for (const r of attackManifest) {
    rows.push({
      scenario_id: r.scenario_id,
      source: 'block4_attack',
      expected1: r.expected_detection_track_1,
      expected2: r.expected_detection_track_2,
      expected3: r.expected_detection_track_3,
      experimental: !!r.experimental,
      events: readJsonl(path.join(ATTACK_DIR, r.file))
    });
  }

  return rows;
}

/**
 * Block 6 validation/stress-test corpus (data/validation/) loaded on its own -- never mixed
 * on disk with Block 3 normal or Block 4 attack fixtures, per the Block 6 instruction.
 */
function loadValidationCorpus() {
  const rows = [];
  const manifest = readJsonl(path.join(VALIDATION_DIR, 'manifest.jsonl'));
  for (const r of manifest) {
    rows.push({
      scenario_id: r.scenario_id,
      source: 'block6_validation',
      file: r.file,
      expected1: r.expected_detection_track_1,
      expected2: r.expected_detection_track_2,
      expected3: r.expected_detection_track_3,
      experimental: false,
      false_positive_test: !!r.false_positive_test,
      evasion_test: !!r.evasion_test,
      events: readJsonl(path.join(VALIDATION_DIR, r.file))
    });
  }
  return rows;
}

/** Curated core (Block 3 + Block 4, 31 scenarios) plus the Block 6 stress-test additions,
 *  clearly separable by `source` for reporting "curated" vs "full stress-test" metrics. */
function loadFullStressCorpus() {
  return [...loadUnifiedCorpus(), ...loadValidationCorpus()];
}

module.exports = { loadUnifiedCorpus, loadValidationCorpus, loadFullStressCorpus, NORMAL_DIR, ATTACK_DIR, VALIDATION_DIR };
