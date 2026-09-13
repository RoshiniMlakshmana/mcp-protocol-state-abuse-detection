'use strict';
/**
 * Structural validation of the Sigma YAML rules against the specification requirements
 * verified in Block 5 research (SigmaHQ/sigma-specification, both the base detection-rule spec
 * and the correlation-rules spec).
 *
 * HONESTY NOTE: this is NOT the official Sigma CLI / pySigma validator. Python is not
 * available in this environment (verified: `python`/`pip` unresolved), so the official
 * tooling could not be run. This test instead independently re-checks the normative
 * requirements this project could verify from the specification text itself: required fields
 * present, enum values valid, UUID format, correlation type/rules/group-by/timespan shape, and
 * that every correlation rule's `rules:` reference resolves to a real component rule's `name:`.
 * See detections/README.md, "validation tooling used", for the full honest account.
 */
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const path = require('path');
const yaml = require('js-yaml');

const SIGMA_DIR = path.join(__dirname, '..', '..', 'detections', 'sigma');
const UUID_V4 = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const VALID_STATUS = new Set(['stable', 'test', 'experimental', 'deprecated', 'unsupported']);
const VALID_LEVEL = new Set(['informational', 'low', 'medium', 'high', 'critical']);
const VALID_CORRELATION_TYPE = new Set(['event_count', 'value_count', 'temporal', 'temporal_ordered', 'value_sum', 'value_avg', 'value_percentile']);
const TIMESPAN_RE = /^\d+[smhd]$/;

function loadAll() {
  const files = fs.readdirSync(SIGMA_DIR).filter((f) => f.endsWith('.yml'));
  return files.map((f) => ({ file: f, doc: yaml.load(fs.readFileSync(path.join(SIGMA_DIR, f), 'utf8')) }));
}

test('Every Sigma YAML file parses as valid YAML', () => {
  const all = loadAll();
  assert.ok(all.length >= 7, 'expected at least the 3 detection + 3 component + 1 correlation rules');
  for (const { file, doc } of all) {
    assert.ok(doc && typeof doc === 'object', `${file} did not parse to an object`);
  }
});

test('Every detection rule (non-correlation) has the required fields with valid enum values', () => {
  const all = loadAll().filter(({ doc }) => !doc.correlation);
  assert.ok(all.length >= 6);
  for (const { file, doc } of all) {
    assert.ok(doc.title, `${file}: missing title`);
    assert.ok(doc.id, `${file}: missing id`);
    assert.match(doc.id, UUID_V4, `${file}: id is not a valid UUID v4`);
    assert.ok(VALID_STATUS.has(doc.status), `${file}: invalid status ${doc.status}`);
    assert.ok(doc.logsource && doc.logsource.product, `${file}: missing logsource.product`);
    assert.ok(doc.detection && doc.detection.condition, `${file}: missing detection.condition`);
    if (doc.level) assert.ok(VALID_LEVEL.has(doc.level), `${file}: invalid level ${doc.level}`);
    assert.ok(doc.description, `${file}: missing description`);
    assert.ok(Array.isArray(doc.references) && doc.references.length > 0, `${file}: missing references`);
  }
});

test('Every correlation rule has valid type/rules/group-by/timespan and references real component rules', () => {
  const all = loadAll();
  const byName = new Map();
  for (const { doc } of all) {
    if (doc.name) byName.set(doc.name, doc);
  }
  const correlations = all.filter(({ doc }) => doc.correlation);
  assert.ok(correlations.length >= 1, 'expected at least one Sigma correlation rule');
  for (const { file, doc } of correlations) {
    const c = doc.correlation;
    assert.ok(VALID_CORRELATION_TYPE.has(c.type), `${file}: invalid correlation.type ${c.type}`);
    assert.ok(Array.isArray(c.rules) && c.rules.length >= 2, `${file}: correlation.rules must reference at least two rules`);
    for (const ref of c.rules) {
      assert.ok(byName.has(ref), `${file}: correlation references "${ref}", which is not any component rule's name:`);
    }
    assert.ok(Array.isArray(c['group-by']) && c['group-by'].length > 0, `${file}: missing group-by`);
    assert.match(c.timespan, TIMESPAN_RE, `${file}: timespan "${c.timespan}" does not match Sigma's number+unit format`);
    assert.ok(doc.title && doc.id && VALID_STATUS.has(doc.status), `${file}: correlation rule missing base metadata`);
    // This project's specific honesty requirement: the drift correlation's description must
    // document its own limitations, not present itself as a complete Track 3 implementation.
    if (file.includes('drift_correlation')) {
      assert.match(doc.description, /DOES NOT FAITHFULLY IMPLEMENT/, `${file}: must explicitly document its limitations`);
    }
  }
});

test('Track 1/2 primary rules select mcp.request.validation / mcp.task.authorization and only on "conflict"/"principal_mismatch"', () => {
  const all = loadAll();
  const track1 = all.find(({ file }) => file === 'mcp_task_routing_desynchronization.yml').doc;
  const flat1 = JSON.stringify(track1.detection);
  assert.match(flat1, /mcp\.request\.validation/);
  assert.match(flat1, /conflict/);
  assert.doesNotMatch(flat1, /missing/, 'primary Track 1 rule must not reference "missing"');

  const track2 = all.find(({ file }) => file === 'mcp_cross_principal_task_authorization.yml').doc;
  const flat2 = JSON.stringify(track2.detection);
  assert.match(flat2, /mcp\.task\.authorization/);
  assert.match(flat2, /principal_mismatch/);
  assert.doesNotMatch(flat2, /policy_denied|insufficient_scope|context_unbound/, 'Track 2 rule must not key on non-cross-principal deny reasons');
});
