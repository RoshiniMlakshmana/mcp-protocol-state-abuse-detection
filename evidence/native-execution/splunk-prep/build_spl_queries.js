'use strict';
// Builds the exact per-fixture SPL search text to execute natively: the real, UNMODIFIED
// detections/spl/*.spl query body, with the base search's index/sourcetype line scoped to
// `source="<fixture-file>"` so each fixture's real JSONL events (ingested separately, one
// `source` per file via `splunk add oneshot`) can be queried in isolation without needing to
// reshape or duplicate any query logic. This is the SPL equivalent of the KQL evidence's
// `let MCPSecurityAudit = datatable(...)` substitution -- only the input source is adapted,
// never the query body -- but here it is even more faithful: the RAW fixture JSONL is ingested
// and extracted through Splunk's real JSON pipeline (KV_MODE=json, see props.conf), not
// reshaped into a synthetic literal.
//
// Track 3's query references the base search FOUR times (the primary search plus three
// subsearches for .open and .authorization_change events) -- all four are scoped identically,
// mechanically, via a global string replace. Track 1/2 reference it once each.
const fs = require('fs');
const path = require('path');

const repoRoot = path.resolve(__dirname, '..', '..', '..');
const BASE_SEARCH = 'index=mcp_security_audit sourcetype=mcp:audit:json';

// Each *.spl file is a fenced-comment header, then the executable query body, then (for some)
// a further fenced comment block of purely informational prose. Only the EXECUTABLE body
// (between the first and second ``` fence) may legitimately contain the base search string as
// real SPL; the header/footer prose also happens to mention it in passing (e.g. "Placeholder
// source: index=..."), which must NOT be rewritten -- only the real query logic is being scoped.
function scopeToSource(queryText, sourceFile) {
  // Fence 0 opens the header comment, fence 1 closes it (executable body starts right after
  // fence 1 ends). Fence 2, if present, opens a trailing informational comment block (the
  // executable body ends right where fence 2 starts); otherwise the body runs to end of file.
  const fences = [...queryText.matchAll(/^```[ \t]*\r?\n/gm)].map((m) => ({ start: m.index, end: m.index + m[0].length }));
  if (fences.length < 2) throw new Error('Could not find the executable-body fence boundaries');
  const bodyStart = fences[1].end;
  const bodyEnd = fences.length >= 3 ? fences[2].start : queryText.length;
  const header = queryText.slice(0, bodyStart);
  const body = queryText.slice(bodyStart, bodyEnd);
  const footer = queryText.slice(bodyEnd);
  const scopedSearch = `${BASE_SEARCH} source="${sourceFile}"`;
  const count = body.split(BASE_SEARCH).length - 1;
  if (count === 0) throw new Error(`Base search string not found in the executable body -- cannot scope to ${sourceFile}`);
  const scopedBody = body.split(BASE_SEARCH).join(scopedSearch);
  return { scoped: header + scopedBody + footer, occurrences: count };
}

const track3Query = fs.readFileSync(path.join(repoRoot, 'detections/spl/mcp_subscription_authorization_drift.spl'), 'utf8');
const track1Query = fs.readFileSync(path.join(repoRoot, 'detections/spl/mcp_task_routing_desynchronization.spl'), 'utf8');
const track2Query = fs.readFileSync(path.join(repoRoot, 'detections/spl/mcp_cross_principal_task_authorization.spl'), 'utf8');

// Same 25-fixture set already natively validated for KQL (evidence/native-execution/manifest.jsonl)
// -- covers all 8 V14 fixtures, the 3 previously-duplicated no-violation cases (V11-07/V14-04/
// V14-05), 5 distinct-notification controls (V11-02, V12-01, V12-13, V13-01, V13-06), further
// Track 3 binding/timing regressions (V11-01, V11-03, V13-03, V13-05), and 7 representative
// Track 1/2 fixtures.
const fixtures = [
  ['V14-01', 'track3', 'data/validation/track3/v14_scope_match_non_first_position.jsonl'],
  ['V14-02', 'track3', 'data/validation/track3/v14_scope_reordered_same_result.jsonl'],
  ['V14-03', 'track3', 'data/validation/track3/v14_scope_duplicate_tags.jsonl'],
  ['V14-04', 'track3', 'data/validation/track3/v14_scope_no_overlap.jsonl'],
  ['V14-05', 'track3', 'data/validation/track3/v14_scope_exact_string_not_substring.jsonl'],
  ['V14-06', 'track3', 'data/validation/track3/v14_scope_missing_entirely.jsonl'],
  ['V14-07', 'track3', 'data/validation/track3/v14_scope_explicitly_empty.jsonl'],
  ['V14-08', 'track3', 'data/validation/track3/v14_scope_multiple_matches_single_alert.jsonl'],
  ['V11-01', 'track3', 'data/validation/track3/v11_multiple_changes_out_of_order.jsonl'],
  ['V11-02', 'track3', 'data/validation/track3/v11_same_subid_different_principals.jsonl'],
  ['V11-03', 'track3', 'data/validation/track3/v11_revocation_and_expiry_both_apply.jsonl'],
  ['V11-07', 'track3', 'data/validation/track3/v11_close_exactly_at_notification.jsonl'],
  ['V12-01', 'track3', 'data/validation/track3/v12_same_principal_only_a_alerts.jsonl'],
  ['V12-13', 'track3', 'data/validation/track3/v12_corrected_cross_subscription_counterpart.jsonl'],
  ['V13-01', 'track3', 'data/validation/track3/v13_confirmed_during_invalid_interval.jsonl'],
  ['V13-03', 'track3', 'data/validation/track3/v13_unknown_scope_single_candidate.jsonl'],
  ['V13-05', 'track3', 'data/validation/track3/v13_incomplete_timing_evidence.jsonl'],
  ['V13-06', 'track3', 'data/validation/track3/v13_all_principal_bindings_precise_interval.jsonl'],
  ['A1-t1', 'track1', 'data/attack/track1/task_get_identity_mismatch.jsonl'],
  ['A6-t1', 'track1', 'data/attack/controls/missing_header_compatibility.jsonl'],
  ['A11-t1', 'track1', 'data/normal/authorized_shared_access.jsonl'],
  ['A17-t1', 'track1', 'data/attack/combined/mismatch_and_unauthorized.jsonl'],
  ['A7-t2', 'track2', 'data/attack/track2/unauthorized_get.jsonl'],
  ['A11-t2', 'track2', 'data/normal/authorized_shared_access.jsonl'],
  ['A17-t2', 'track2', 'data/attack/combined/mismatch_and_unauthorized.jsonl'],
];

const outDir = path.join(__dirname, 'queries');
fs.mkdirSync(outDir, { recursive: true });

const manifest = [];
for (const [id, track, relFixturePath] of fixtures) {
  const query = track === 'track3' ? track3Query : track === 'track1' ? track1Query : track2Query;
  const sourceFile = path.basename(relFixturePath);
  const { scoped, occurrences } = scopeToSource(query, sourceFile);
  const outFile = path.join(outDir, `${id}.spl`);
  fs.writeFileSync(outFile, scoped, 'utf8');
  manifest.push({ id, track, fixture_file: relFixturePath, source_scope: sourceFile, base_search_occurrences_scoped: occurrences, query_file: `evidence/native-execution/splunk-prep/queries/${id}.spl` });
  console.log(`Wrote ${id}.spl (scoped ${occurrences} base-search occurrence(s) to source="${sourceFile}")`);
}

fs.writeFileSync(path.join(__dirname, 'fixtures-manifest.json'), JSON.stringify(manifest, null, 2), 'utf8');
console.log(`\nWrote fixtures-manifest.json (${manifest.length} fixtures prepared, not yet executed)`);
