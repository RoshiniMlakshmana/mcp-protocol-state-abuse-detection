'use strict';
/**
 * Reference oracle: re-implements, in plain JS, EXACTLY the filter/correlation conditions
 * written in the Sigma/KQL/SPL rule files under detections/ -- used to validate those rules'
 * logic against the Block 3 + Block 4 corpora without needing a live Sigma backend, Sentinel
 * workspace, or Splunk instance (none are available in this environment; see
 * detections/README.md "validation tooling used" for the honest account of what was and
 * wasn't run against real backend software).
 *
 * Each function below is annotated with the exact rule file(s) it mirrors. Track 3 reuses
 * tests/attack/track3util.js unchanged, rather than re-deriving the same logic a third time.
 */
const { computeTrack3Verdict, computeTrack3AlertRows } = require('../attack/track3util');

/**
 * Mirrors: detections/sigma/mcp_task_routing_desynchronization.yml (condition:
 * "selection_event and 1 of selection_conflict*"), detections/kql/..., detections/spl/...
 * (primary query): event.name=mcp.request.validation AND (method.result=conflict OR
 * name.result=conflict).
 */
function track1PrimaryFires(events) {
  return events.some((e) =>
    e['event.name'] === 'mcp.request.validation' &&
    (e['mcp.validation.method.result'] === 'conflict' || e['mcp.validation.name.result'] === 'conflict')
  );
}

/**
 * Mirrors: detections/sigma/mcp_task_routing_missing_header_diagnostic.yml and the "OPTIONAL
 * DIAGNOSTIC" sections of the Track 1 KQL/SPL files: missing or malformed, NEVER "conflict" or
 * "version_incompatible".
 */
function track1DiagnosticFires(events) {
  return events.some((e) =>
    e['event.name'] === 'mcp.request.validation' &&
    (['missing', 'malformed'].includes(e['mcp.validation.method.result']) ||
     ['missing', 'malformed'].includes(e['mcp.validation.name.result']))
  );
}

/**
 * Mirrors: detections/sigma/mcp_cross_principal_task_authorization.yml,
 * detections/kql/mcp_cross_principal_task_authorization.kql,
 * detections/spl/mcp_cross_principal_task_authorization.spl:
 * event.name=mcp.task.authorization AND decision=deny AND reason=principal_mismatch.
 */
function track2Fires(events) {
  return events.some((e) =>
    e['event.name'] === 'mcp.task.authorization' &&
    e['mcp.authz.decision'] === 'deny' &&
    e['mcp.authz.reason'] === 'principal_mismatch'
  );
}

/**
 * Mirrors: detections/kql/mcp_subscription_authorization_drift.kql and
 * detections/spl/mcp_subscription_authorization_drift.spl (the AUTHORITATIVE Track 3
 * implementations -- the Sigma correlation is explicitly documented as non-faithful and is
 * validated separately, not via this function).
 */
function track3PrimaryFires(events) {
  const v = computeTrack3Verdict(events);
  return v.fired && v.confidence === 'high';
}

/**
 * Row-level accessor for tests that need to compare actual alert rows (subscription_id,
 * principal_hash, notif_time, boundary, ...), not just a collapsed boolean -- required whenever
 * a fixture has more than one notification, boundary, or principal, since track3PrimaryFires
 * necessarily discards which/how-many rows fired.
 */
function track3PrimaryAlertRows(events) {
  return computeTrack3AlertRows(events).filter((r) => r.confidence === 'high');
}

/**
 * Mirrors: the Sigma correlation's ACTUAL (non-faithful, documented-limited) behavior --
 * temporal_ordered(authorization_change[authoritative] -> notification) grouped by
 * principal.id_hash, with NO check for an intervening close and NO expiry-only leg. Used only
 * to validate the honesty of the limitations documented in
 * detections/sigma/mcp_subscription_drift_correlation.yml, not as a track3 "detector" in its
 * own right.
 */
function track3SigmaCorrelationFires(events) {
  const change = events.find(
    (e) => e['event.name'] === 'mcp.subscription.authorization_change' && e['mcp.authz.change.timing_confidence'] === 'authoritative'
  );
  const notification = events.find((e) => e['event.name'] === 'mcp.subscription.notification');
  if (!change || !notification) return false;
  // temporal_ordered requires the referenced rules' events to appear in log-timestamp order:
  // change, then notification. It does NOT compare effective_at (a field value) against
  // notification.timestamp, and does NOT check for an intervening close.
  return change.timestamp <= notification.timestamp;
}

module.exports = {
  track1PrimaryFires, track1DiagnosticFires, track2Fires, track3PrimaryFires, track3PrimaryAlertRows, track3SigmaCorrelationFires
};
