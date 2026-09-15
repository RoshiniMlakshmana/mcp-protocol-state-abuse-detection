'use strict';
// Mechanical converter: JSONL fixture events -> a KQL `datatable(...)` literal matching
// exactly the 18 bracketed field references the real .kql query uses. Pure format
// translation -- no detection-logic change. Then prepends that datatable, as `let
// MCPSecurityAudit = ...;`, to the UNMODIFIED, verbatim contents of
// detections/kql/mcp_subscription_authorization_drift.kql.
const fs = require('fs');
const path = require('path');

const FIELDS = [
  ['timestamp', 'timestamp', 'string'],
  ['event.name', 'eventName', 'string'],
  ['principal.id_hash', 'principalIdHash', 'string'],
  ['mcp.subscription.id', 'subscriptionId', 'string'],
  ['mcp.subscription.instance_id', 'subscriptionInstanceId', 'string'],
  ['mcp.authz.binding_id', 'authzBindingId', 'string'],
  ['mcp.subscription.required_scope', 'requiredScope', 'dynamic'],
  ['mcp.authz.valid_until', 'authzValidUntil', 'string'],
  ['mcp.authz.grant_expiry', 'authzGrantExpiry', 'string'],
  ['security.hash.key_id', 'securityHashKeyId', 'string'],
  ['mcp.subscription.notification_type', 'notificationType', 'string'],
  ['mcp.authz.change.type', 'changeType', 'string'],
  ['mcp.authz.change.source', 'changeSource', 'string'],
  ['mcp.authz.change.effective_at', 'changeEffectiveAt', 'string'],
  ['mcp.authz.change.timing_confidence', 'changeTimingConfidence', 'string'],
  ['mcp.authz.change.affected_scope', 'changeAffectedScope', 'string'],
  ['mcp.authz.change.affected_binding_ids', 'changeAffectedBindingIds', 'dynamic'],
  ['mcp.authz.change.removed_scope', 'changeRemovedScope', 'dynamic'],
];

function kqlStr(v) {
  if (v === undefined || v === null) return '""';
  return '"' + String(v).replace(/\\/g, '\\\\').replace(/"/g, '\\"') + '"';
}
function kqlDynamic(v) {
  if (v === undefined) return 'dynamic(null)';
  return 'dynamic(' + JSON.stringify(v) + ')';
}

function eventToRow(e) {
  return FIELDS.map(([jsonKey, , type]) => {
    const v = e[jsonKey];
    return type === 'dynamic' ? kqlDynamic(v) : kqlStr(v);
  }).join(', ');
}

function buildDatatable(events) {
  const schema = FIELDS.map(([jsonKey, , type]) => `['${jsonKey}']:${type}`).join(', ');
  const rows = events.map((e) => '  ' + eventToRow(e)).join(',\n');
  return `let MCPSecurityAudit = datatable(${schema}) [\n${rows}\n];\n`;
}

function loadJsonl(file) {
  return fs.readFileSync(file, 'utf8').split('\n').filter((l) => l.trim()).map((l) => JSON.parse(l));
}

const repoRoot = path.resolve(__dirname, '..', '..', '..'); // evidence/native-execution/converters -> repo root
const kqlQueryPath = path.join(repoRoot, 'detections/kql/mcp_subscription_authorization_drift.kql');
const kqlQuery = fs.readFileSync(kqlQueryPath, 'utf8');

const fixtures = [
  ['V14-01', 'v14_scope_match_non_first_position.jsonl'],
  ['V14-02', 'v14_scope_reordered_same_result.jsonl'],
  ['V14-03', 'v14_scope_duplicate_tags.jsonl'],
  ['V14-04', 'v14_scope_no_overlap.jsonl'],
  ['V14-05', 'v14_scope_exact_string_not_substring.jsonl'],
  ['V14-06', 'v14_scope_missing_entirely.jsonl'],
  ['V14-07', 'v14_scope_explicitly_empty.jsonl'],
  ['V14-08', 'v14_scope_multiple_matches_single_alert.jsonl'],
  ['V11-01', 'v11_multiple_changes_out_of_order.jsonl'],
  ['V11-02', 'v11_same_subid_different_principals.jsonl'],
  ['V11-07', 'v11_close_exactly_at_notification.jsonl'],
  ['V12-01', 'v12_same_principal_only_a_alerts.jsonl'],
  ['V12-13', 'v12_corrected_cross_subscription_counterpart.jsonl'],
  ['V13-01', 'v13_confirmed_during_invalid_interval.jsonl'],
  ['V13-03', 'v13_unknown_scope_single_candidate.jsonl'],
  ['V13-05', 'v13_incomplete_timing_evidence.jsonl'],
  ['V13-06', 'v13_all_principal_bindings_precise_interval.jsonl'],
  ['V11-03', 'v11_revocation_and_expiry_both_apply.jsonl'],
];

const outDir = path.join(__dirname, '..', 'runs');
for (const [id, file] of fixtures) {
  const events = loadJsonl(path.join(repoRoot, 'data/validation/track3', file));
  const datatable = buildDatatable(events);
  const fullQuery = datatable + '\n' + kqlQuery;
  fs.writeFileSync(path.join(outDir, `${id}.kql`), fullQuery, 'utf8');
  fs.writeFileSync(path.join(outDir, `${id}.request.json`), JSON.stringify({ db: 'NetDefaultDB', csl: fullQuery }), 'utf8');
  console.log(`Wrote ${id}.kql (${events.length} events)`);
}
