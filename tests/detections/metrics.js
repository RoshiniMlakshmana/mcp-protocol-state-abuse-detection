'use strict';

/**
 * Computes a confusion matrix + precision/recall for one rule (predicate fn) against the
 * unified corpus, using each scenario's manifest-declared expected boolean as ground truth.
 * This is a controlled-corpus correctness check, not a real-world prevalence/performance claim
 * (see detections/README.md).
 */
function evaluate(rows, predicateFn, expectedKey) {
  const cases = [];
  let tp = 0, fp = 0, tn = 0, fn = 0;
  for (const row of rows) {
    const expected = row[expectedKey];
    const actual = predicateFn(row.events);
    let outcome;
    if (expected && actual) { tp++; outcome = 'TP'; }
    else if (!expected && actual) { fp++; outcome = 'FP'; }
    else if (!expected && !actual) { tn++; outcome = 'TN'; }
    else { fn++; outcome = 'FN'; }
    cases.push({ scenario_id: row.scenario_id, source: row.source, expected, actual, outcome, experimental: row.experimental });
  }
  const precision = (tp + fp) === 0 ? null : tp / (tp + fp);
  const recall = (tp + fn) === 0 ? null : tp / (tp + fn);
  return { tp, fp, tn, fn, precision, recall, total: rows.length, cases };
}

function formatReport(name, result) {
  const lines = [];
  lines.push(`${name}: TP=${result.tp} FP=${result.fp} TN=${result.tn} FN=${result.fn} (n=${result.total})`);
  lines.push(`  precision=${result.precision === null ? 'n/a' : result.precision.toFixed(3)} recall=${result.recall === null ? 'n/a' : result.recall.toFixed(3)}`);
  const bad = result.cases.filter((c) => c.outcome === 'FP' || c.outcome === 'FN');
  if (bad.length) lines.push(`  unexpected: ${bad.map((c) => `${c.scenario_id}(${c.outcome})`).join(', ')}`);
  return lines.join('\n');
}

module.exports = { evaluate, formatReport };
