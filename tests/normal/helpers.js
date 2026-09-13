'use strict';
const fs = require('fs');
const path = require('path');

const DATA_DIR = path.join(__dirname, '..', '..', 'data', 'normal');

function readJsonl(filename) {
  const full = path.join(DATA_DIR, filename);
  const text = fs.readFileSync(full, 'utf8');
  return text.split('\n').filter((l) => l.trim().length > 0).map((l) => JSON.parse(l));
}

function readManifest() {
  return readJsonl('manifest.jsonl');
}

function readAllScenarioEvents() {
  const manifest = readManifest();
  const byScenario = new Map();
  const byFile = new Map();
  for (const row of manifest) {
    if (!byFile.has(row.file)) byFile.set(row.file, readJsonl(row.file));
    byScenario.set(row.scenario_id, { manifest: row, events: byFile.get(row.file) });
  }
  const allEvents = [].concat(...byFile.values());
  return { manifest, byScenario, allEvents };
}

module.exports = { DATA_DIR, readJsonl, readManifest, readAllScenarioEvents };
