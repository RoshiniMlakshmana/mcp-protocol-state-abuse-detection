'use strict';
// Same mechanical JSONL -> datatable approach as build_kql_input.js, generalized for
// Track 1 (mcp.request.validation) and Track 2 (mcp.task.authorization) single-event queries.
const fs = require('fs');
const path = require('path');

function kqlStr(v) {
  if (v === undefined || v === null) return '""';
  return '"' + String(v).replace(/\\/g, '\\\\').replace(/"/g, '\\"') + '"';
}
function kqlBool(v) {
  if (v === undefined || v === null) return 'bool(null)';
  return v ? 'true' : 'false';
}

const T1_FIELDS = [
  ['timestamp', 'string'], ['event.name', 'string'], ['jsonrpc.request.id', 'string'],
  ['mcp.body.identity_hash', 'string'], ['mcp.body.method', 'string'], ['mcp.header.method', 'string'],
  ['mcp.header.name_hash', 'string'], ['mcp.protocol.version', 'string'],
  ['mcp.validation.method.result', 'string'], ['mcp.validation.name.result', 'string'],
  ['mcp.validation.reason', 'string'], ['mcp.validation.source', 'string'],
];
const T2_FIELDS = [
  ['timestamp', 'string'], ['event.name', 'string'], ['mcp.authz.decision', 'string'],
  ['mcp.authz.policy_version', 'string'], ['mcp.authz.reason', 'string'],
  ['mcp.task.authz_context_id_hash', 'string'], ['mcp.task.id_hash', 'string'],
  ['mcp.task.operation', 'string'], ['principal.authenticated', 'bool'], ['principal.id_hash', 'string'],
];

function buildDatatable(fields, events, filterEventName) {
  const rows = events.filter((e) => e['event.name'] === filterEventName);
  const schema = fields.map(([k, t]) => `['${k}']:${t}`).join(', ');
  const body = rows.map((e) => '  ' + fields.map(([k, t]) => (t === 'bool' ? kqlBool(e[k]) : kqlStr(e[k]))).join(', ')).join(',\n');
  return { datatable: `let MCPSecurityAudit = datatable(${schema}) [\n${body}\n];\n`, count: rows.length };
}

function loadJsonl(file) { return fs.readFileSync(file, 'utf8').split('\n').filter((l) => l.trim()).map((l) => JSON.parse(l)); }

const repoRoot = path.resolve(__dirname, '..', '..', '..'); // evidence/native-execution/converters -> repo root
const t1Query = fs.readFileSync(path.join(repoRoot, 'detections/kql/mcp_task_routing_desynchronization.kql'), 'utf8');
const t2Query = fs.readFileSync(path.join(repoRoot, 'detections/kql/mcp_cross_principal_task_authorization.kql'), 'utf8');

const outDir = path.join(__dirname, '..', 'runs');
const jobs = [
  ['A1-t1', 'track1', 'mcp.request.validation', 'data/attack/track1/task_get_identity_mismatch.jsonl', t1Query, T1_FIELDS],
  ['A6-t1', 'track1', 'mcp.request.validation', 'data/attack/controls/missing_header_compatibility.jsonl', t1Query, T1_FIELDS],
  ['A11-t1', 'track1', 'mcp.request.validation', 'data/normal/authorized_shared_access.jsonl', t1Query, T1_FIELDS],
  ['A17-t1', 'track1', 'mcp.request.validation', 'data/attack/combined/mismatch_and_unauthorized.jsonl', t1Query, T1_FIELDS],
  ['A7-t2', 'track2', 'mcp.task.authorization', 'data/attack/track2/unauthorized_get.jsonl', t2Query, T2_FIELDS],
  ['A11-t2', 'track2', 'mcp.task.authorization', 'data/normal/authorized_shared_access.jsonl', t2Query, T2_FIELDS],
  ['A17-t2', 'track2', 'mcp.task.authorization', 'data/attack/combined/mismatch_and_unauthorized.jsonl', t2Query, T2_FIELDS],
];

for (const [id, , eventName, relFile, query, fields] of jobs) {
  const events = loadJsonl(path.join(repoRoot, relFile));
  const { datatable, count } = buildDatatable(fields, events, eventName);
  const fullQuery = datatable + '\n' + query;
  fs.writeFileSync(path.join(outDir, `${id}.kql`), fullQuery, 'utf8');
  fs.writeFileSync(path.join(outDir, `${id}.request.json`), JSON.stringify({ db: 'NetDefaultDB', csl: fullQuery }), 'utf8');
  console.log(`Wrote ${id}.kql (${count} matching events out of ${events.length} total)`);
}
