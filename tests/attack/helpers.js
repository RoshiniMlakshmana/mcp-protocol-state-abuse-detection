'use strict';
const fs = require('fs');
const path = require('path');

const ATTACK_DIR = path.join(__dirname, '..', '..', 'data', 'attack');

function readJsonl(relPath) {
  const full = path.join(ATTACK_DIR, relPath);
  const text = fs.readFileSync(full, 'utf8');
  return text.split('\n').filter((l) => l.trim().length > 0).map((l) => JSON.parse(l));
}

function readManifest() {
  return readJsonl('manifest.jsonl');
}

function readAllScenarios() {
  const manifest = readManifest();
  const byScenario = new Map();
  for (const row of manifest) {
    byScenario.set(row.scenario_id, { manifest: row, events: readJsonl(row.file) });
  }
  return { manifest, byScenario };
}

module.exports = { ATTACK_DIR, readJsonl, readManifest, readAllScenarios };
