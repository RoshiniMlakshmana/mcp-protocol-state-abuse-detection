'use strict';
/**
 * Evaluates the EXISTING Track 1 detector logic (tests/detections/oracle.js's
 * track1PrimaryFires / track1DiagnosticFires -- a plain-JS reference oracle mirroring the
 * Sigma/KQL/SPL rule condition, unchanged, not reimplemented here) against the telemetry events
 * this lab actually derived from real request processing (lib/audit.js -> evidence/telemetry-events.json).
 *
 * IMPORTANT, explicit per instruction: this is JS-MODEL evaluation, the SAME reference-oracle
 * approach the main project's own test suite uses (see detections/README.md "validation tooling
 * used") -- it is NOT execution against a native query engine (Sigma backend, Sentinel/KQL, or
 * Splunk/SPL). Splunk was NOT restarted or re-attempted for this lab: the main project's Splunk
 * attempt remains permanently closed out per evidence/native-execution/splunk-prep/STATUS.md, and
 * this lab does not touch it.
 */
const fs = require('node:fs');
const path = require('node:path');
const { track1PrimaryFires, track1DiagnosticFires } = require('../../tests/detections/oracle');

const EVENTS_FILE = path.join(__dirname, 'evidence', 'telemetry-events.json');
const OUT_FILE = path.join(__dirname, 'evidence', 'detector-evaluation.json');

function main() {
  const { events } = JSON.parse(fs.readFileSync(EVENTS_FILE, 'utf8'));

  // Group by requestInstanceId (the gateway-generated correlation key, NOT the client-chosen
  // JSON-RPC id -- bounded case 5 deliberately reuses id="1" across two concurrent, independent
  // requests, so grouping by JSON-RPC id would silently merge them).
  const byInstance = new Map();
  for (const e of events) {
    if (!byInstance.has(e.requestInstanceId)) byInstance.set(e.requestInstanceId, []);
    byInstance.get(e.requestInstanceId).push(e);
  }

  const perRequest = [];
  for (const [requestInstanceId, instanceEvents] of byInstance) {
    perRequest.push({
      requestInstanceId,
      labCase: instanceEvents[0].labCase,
      sourcesPresent: instanceEvents.map((e) => e['mcp.validation.source']),
      primaryFires: track1PrimaryFires(instanceEvents),
      diagnosticFires: track1DiagnosticFires(instanceEvents),
    });
  }

  const overallPrimaryFires = track1PrimaryFires(events);
  const overallDiagnosticFires = track1DiagnosticFires(events);

  const expectedPrimaryFiringCases = ['conflict', 'weakened'];
  const actualPrimaryFiringCases = perRequest.filter((r) => r.primaryFires).map((r) => r.labCase);
  const matchesExpectation =
    JSON.stringify([...new Set(actualPrimaryFiringCases)].sort()) === JSON.stringify([...expectedPrimaryFiringCases].sort());

  const report = {
    evaluationMethod: 'JS reference-oracle model (tests/detections/oracle.js), NOT a native query engine execution',
    splunkRestarted: false,
    splunkNote: 'not restarted or re-attempted; see evidence/native-execution/splunk-prep/STATUS.md in the main project for the closed-out prior attempt',
    perRequest,
    overallPrimaryFires,
    overallDiagnosticFires,
    expectedPrimaryFiringCases,
    actualPrimaryFiringCases: [...new Set(actualPrimaryFiringCases)],
    matchesExpectation,
  };

  fs.mkdirSync(path.dirname(OUT_FILE), { recursive: true });
  fs.writeFileSync(OUT_FILE, JSON.stringify(report, null, 2), 'utf8');
  console.log(`[evaluate-detector] JS-model evaluation (not a query engine) -- overallPrimaryFires=${overallPrimaryFires}, matchesExpectation=${matchesExpectation}`);
  console.log(`[evaluate-detector] wrote evidence/detector-evaluation.json`);
}

main();
