'use strict';
// Builds evidence/native-execution/manifest.jsonl from the actual saved query/response pairs --
// mechanically, from the response files themselves, not hand-typed, so the manifest cannot drift
// from what was actually executed.
const fs = require('fs');
const path = require('path');

const repoRoot = path.resolve(__dirname, '..', '..', '..'); // evidence/native-execution/converters -> repo root
const runsDir = path.join(repoRoot, 'evidence/native-execution/runs');
const prefixDir = path.join(repoRoot, 'evidence/native-execution/prefix-baseline');

const track3ExpectedOutcome = {
  'V14-01': 'ConfirmedDrift', 'V14-02': 'ConfirmedDrift', 'V14-03': 'ConfirmedDrift',
  'V14-04': 'EvaluatedNoViolation', 'V14-05': 'EvaluatedNoViolation', 'V14-06': 'InsufficientEvidence',
  'V14-07': 'EvaluatedNoViolation', 'V14-08': 'ConfirmedDrift',
};
// Multi-notification / multi-row fixtures: described per test intent (tests/validation/
// track3_row_regression.test.js) rather than a single expected Outcome string.
const track3MultiRowExpectation = {
  'V11-01': { rowCount: 3, description: 'notif1 (17:30): 1 ConfirmedDrift row (earlier change only). notif2 (18:30): 2 ConfirmedDrift rows (both applicable changes independently confirm).' },
  'V11-02': { rowCount: 2, description: 'Bob (17:50, own close): 1 EvaluatedNoViolation row. Alice (17:55, unaffected by Bob\'s close): 1 ConfirmedDrift row.' },
  'V11-03': { rowCount: 2, description: 'One notification (18:20): 2 ConfirmedDrift rows, one per independently-crossed boundary (valid_until AND effective_at) -- ConfirmedDrift ties are NEVER collapsed by the part 5 fix.' },
  'V11-07': { rowCount: 1, description: 'One notification (19:40): exactly 1 EvaluatedNoViolation row after the part 5 fix (was 2 pre-fix -- see prefix-baseline), joining "expiry_not_yet_reached; revocation_suppressed_by_close".' },
  'V12-01': { rowCount: 2, description: 'Binding B notification: 1 EvaluatedNoViolation row. Binding A notification (different subscription, same principal): 1 ConfirmedDrift row -- distinct notifications correctly stay separate.' },
  'V12-13': { rowCount: 2, description: 'Same shape as V12-01 for the corrected all_principal_bindings counterpart to V11-11.' },
  'V13-01': { rowCount: 2, description: 'Pre-renewal notification (09:10): 1 ConfirmedDrift row. Post-renewal notification (09:20, proven rebinding): 1 EvaluatedNoViolation row -- distinct notifications correctly stay separate; the later one never erases the earlier confirmed finding.' },
  'V13-03': { rowCount: 1, description: 'One notification: 1 InsufficientEvidence row (ambiguous_scope) -- proves the removed sole-candidate inference stays removed.' },
  'V13-05': { rowCount: 1, description: 'One notification: 1 InsufficientEvidence row (incomplete_timing_evidence) -- validates the KQL MalformedTimingSignals leg natively for the first time.' },
  'V13-06': { rowCount: 2, description: 'Old-binding notification: 1 ConfirmedDrift row. New-binding notification (issued after the account-wide revocation): 1 EvaluatedNoViolation row -- distinct notifications correctly stay separate.' },
};

const track1t2ExpectedFires = {
  'A1-t1': true, 'A6-t1': false, 'A11-t1': false, 'A17-t1': true,
  'A7-t2': true, 'A11-t2': false, 'A17-t2': true,
};

function readOutcomes(file, id) {
  const r = JSON.parse(fs.readFileSync(file, 'utf8'));
  const t = r.Tables[0];
  const hasOutcomeColumn = t.Columns.some((c) => c.ColumnName === 'Outcome');
  const outcomeIdx = hasOutcomeColumn ? t.Columns.findIndex((c) => c.ColumnName === 'Outcome') : 0;
  const reasonIdx = t.Columns.findIndex((c) => c.ColumnName === 'Reason');
  const statsTable = r.Tables.find((tb) => tb.Columns.some((c) => c.ColumnName === 'Timestamp' && c.ColumnType === 'datetime'));
  let executedAt = null;
  if (statsTable) {
    const tsIdx = statsTable.Columns.findIndex((c) => c.ColumnName === 'Timestamp');
    const sevIdx = statsTable.Columns.findIndex((c) => c.ColumnName === 'SeverityName');
    const infoRow = statsTable.Rows.find((row) => row[sevIdx] === 'Info');
    if (infoRow) executedAt = infoRow[tsIdx];
  }
  return {
    rowCount: t.Rows.length,
    fires: t.Rows.length > 0,
    outcomes: hasOutcomeColumn ? t.Rows.map((row) => row[outcomeIdx]) : null,
    reasons: reasonIdx >= 0 ? t.Rows.map((row) => row[reasonIdx]) : null,
    executedAt,
  };
}

const entries = [];

// --- "current" batch: the 25 executions against the FINAL query (part 4 + part 5 fixes) ---
const runFiles = fs.readdirSync(runsDir).filter((f) => f.endsWith('.response.json')).map((f) => f.replace('.response.json', ''));
runFiles.sort();
for (const id of runFiles) {
  const { rowCount, fires, outcomes, reasons, executedAt } = readOutcomes(path.join(runsDir, `${id}.response.json`), id);
  const track = id.endsWith('-t1') ? 'track1' : id.endsWith('-t2') ? 'track2' : 'track3';
  const expected = track3ExpectedOutcome[id];
  const entry = {
    id, batch: 'current', track,
    query_file: `evidence/native-execution/runs/${id}.kql`,
    response_file: `evidence/native-execution/runs/${id}.response.json`,
    row_count: rowCount,
    executed_at: executedAt,
    query_commit: 'HEAD (post Track 3 remediation pass, part 5 -- see README.md for the exact commit)',
  };
  if (track === 'track3') {
    entry.outcomes = outcomes;
    entry.reasons = reasons;
    if (expected) {
      entry.expected_outcome = expected;
      entry.matches_expectation = outcomes.every((o) => o === expected);
    } else if (track3MultiRowExpectation[id]) {
      const exp = track3MultiRowExpectation[id];
      entry.expected_description = exp.description;
      entry.matches_expectation = rowCount === exp.rowCount;
    }
  } else {
    entry.fires = fires;
    entry.expected_fires = track1t2ExpectedFires[id];
    entry.matches_expectation = fires === track1t2ExpectedFires[id];
  }
  entries.push(entry);
}

// --- "prefix-baseline" batch: pre-fix (commit d08bfd6) re-execution of the 3 affected fixtures ---
const prefixFiles = fs.readdirSync(prefixDir).filter((f) => f.endsWith('.prefix.response.json')).map((f) => f.replace('.prefix.response.json', ''));
prefixFiles.sort();
for (const id of prefixFiles) {
  const { rowCount, outcomes, reasons, executedAt } = readOutcomes(path.join(prefixDir, `${id}.prefix.response.json`), id);
  entries.push({
    id, batch: 'prefix-baseline', track: 'track3',
    query_file: `evidence/native-execution/prefix-baseline/${id}.prefix.kql`,
    response_file: `evidence/native-execution/prefix-baseline/${id}.prefix.response.json`,
    row_count: rowCount, outcomes, reasons,
    expected_outcome: track3ExpectedOutcome[id] || 'EvaluatedNoViolation',
    matches_expectation: outcomes.every((o) => o === (track3ExpectedOutcome[id] || 'EvaluatedNoViolation')),
    executed_at: executedAt,
    query_commit: 'd08bfd6df263aa8b0be129e5f10e3379aa1b988e',
    note: 'Re-executed the EXACT query text as of this commit to honestly capture the pre-fix row-duplication defect -- not the original session\'s first execution, which was not saved to disk.',
  });
}

const out = entries.map((e) => JSON.stringify(e)).join('\n') + '\n';
fs.writeFileSync(path.join(repoRoot, 'evidence/native-execution/manifest.jsonl'), out, 'utf8');
console.log(`Wrote ${entries.length} manifest entries (${runFiles.length} current + ${prefixFiles.length} prefix-baseline)`);
