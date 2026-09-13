'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const { readAllScenarioEvents } = require('./helpers');

// Enrichment-only fields must never, by themselves, correlate with an expected alert
// (docs/threat-model.md SS1/SS8; telemetry/schema.md section 4's explicit non-negotiable).

test('Large outputs (N10) do not become security failures', () => {
  const { byScenario } = readAllScenarioEvents();
  const n10 = byScenario.get('N10');
  assert.ok(n10);
  const state = n10.events.find((e) => e['event.name'] === 'mcp.task.state' && e['mcp.task.state'] === 'completed');
  assert.ok(state['mcp.output.bytes'] > 1_000_000, 'N10 must actually be large to be a meaningful test');
  assert.equal(n10.manifest.expected_detection_track_1, false);
  assert.equal(n10.manifest.expected_detection_track_2, false);
  assert.equal(n10.manifest.expected_detection_track_3, false);
  assert.equal(n10.manifest.expected_security_outcome, 'benign');
});

test('High token counts (N11) do not become security failures, and are explicitly marked synthetic', () => {
  const { byScenario } = readAllScenarioEvents();
  const n11 = byScenario.get('N11');
  assert.ok(n11);
  const state = n11.events.find((e) => e['event.name'] === 'mcp.task.state' && e['mcp.task.state'] === 'completed');
  assert.ok(state['gen_ai.usage.input_tokens'] + state['gen_ai.usage.output_tokens'] > 10_000);
  assert.equal(n11.manifest.provenance, 'synthetic_enrichment');
  assert.equal(n11.manifest.expected_detection_track_1, false);
  assert.equal(n11.manifest.expected_detection_track_2, false);
  assert.equal(n11.manifest.expected_detection_track_3, false);
});

test('Missing optional telemetry (N12) does not become a security failure', () => {
  const { byScenario } = readAllScenarioEvents();
  const n12 = byScenario.get('N12');
  assert.ok(n12);
  const hasTrace = n12.events.some((e) => 'trace_id' in e || 'span_id' in e);
  assert.equal(hasTrace, false, 'N12 must genuinely omit trace/span correlation');
  const authz = n12.events.find((e) => e['event.name'] === 'mcp.task.authorization');
  assert.equal(authz['mcp.task.authz_context_id_hash'], null);
  assert.equal(authz['mcp.authz.decision'], 'allow');
  const state = n12.events.find((e) => e['event.name'] === 'mcp.task.state' && e['mcp.task.state'] === 'completed');
  assert.equal('mcp.output.bytes' in state, false);
  assert.equal('gen_ai.usage.input_tokens' in state, false);
  assert.equal(n12.manifest.expected_detection_track_1, false);
  assert.equal(n12.manifest.expected_detection_track_2, false);
  assert.equal(n12.manifest.expected_detection_track_3, false);
});

test('No event in the normal corpus contains a raw bearer token, credential, or secret-shaped field', () => {
  const { allEvents } = readAllScenarioEvents();
  // gen_ai.usage.*_tokens is a legitimate, schema-defined enrichment count field (a number
  // of LLM tokens), not a credential -- explicitly allowed. Everything else matching these
  // patterns is forbidden per telemetry/schema.md section 6, rule 7.
  const allowlist = new Set(['gen_ai.usage.input_tokens', 'gen_ai.usage.output_tokens']);
  const forbidden = ['bearer', 'authorization_header', 'secret', 'password', 'api_key', 'access_token', 'refresh_token', 'client_secret'];
  for (const evt of allEvents) {
    for (const key of Object.keys(evt)) {
      if (allowlist.has(key)) continue;
      const lower = key.toLowerCase();
      for (const bad of forbidden) {
        assert.ok(!lower.includes(bad), `forbidden-looking field "${key}" found on ${evt['event.name']}`);
      }
    }
  }
});
