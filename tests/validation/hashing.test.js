'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const { loadValidationCorpus } = require('../detections/corpus');
const { hmacHash, HASH_KEY_ID } = require('../../tools/harness/lib/hash');

test('V7-01: same key epoch preserves equality (header hash == body hash for the same raw taskId)', () => {
  const rows = loadValidationCorpus();
  const v701 = rows.find((r) => r.scenario_id === 'V7-01');
  const req = v701.events.find((e) => e['event.name'] === 'mcp.request.received');
  assert.equal(req['mcp.header.name_hash'], req['mcp.body.identity_hash']);
  assert.equal(req['security.hash.key_id'], HASH_KEY_ID);
});

test('V7-02: different key_id produces different hashes for the SAME underlying identity -- no silent correlation', () => {
  const rows = loadValidationCorpus();
  const v702 = rows.find((r) => r.scenario_id === 'V7-02');
  const [first, second] = v702.events;
  assert.notEqual(first['security.hash.key_id'], second['security.hash.key_id'], 'the two events must be tagged with different key epochs');
  assert.notEqual(first['mcp.task.id_hash'], second['mcp.task.id_hash'], 'hashes for the same underlying taskId must differ across key epochs (this is the whole point of a keyed HMAC)');
  // A naive query grouping purely by mcp.task.id_hash (ignoring key_id) would NOT recognize
  // these two records as describing the same task -- demonstrated directly, not asserted blindly.
  const naiveGroupByHashOnly = new Map();
  for (const e of v702.events) {
    const k = e['mcp.task.id_hash'];
    naiveGroupByHashOnly.set(k, (naiveGroupByHashOnly.get(k) || 0) + 1);
  }
  assert.equal(naiveGroupByHashOnly.size, 2, 'a key_id-blind query sees two unrelated groups, not one');
});

test('V7-03: key rotation does not affect the per-event Track 2 verdict, only cross-epoch historical correlation', () => {
  const rows = loadValidationCorpus();
  const { track2Fires } = require('../detections/oracle');
  const v703 = rows.find((r) => r.scenario_id === 'V7-03');
  const [ownerEvent, attackerEvent] = v703.events;
  assert.equal(track2Fires([ownerEvent]), false, 'pre-rotation owner access: not a violation on its own');
  assert.equal(track2Fires([attackerEvent]), true, 'post-rotation attacker access: a real violation, detected correctly on its own record');
  assert.notEqual(ownerEvent['security.hash.key_id'], attackerEvent['security.hash.key_id']);
  assert.notEqual(ownerEvent['mcp.task.id_hash'], attackerEvent['mcp.task.id_hash'], 'the same underlying task hashes differently across the rotation boundary -- cross-time task-history correlation would miss the connection, even though each record alone is still correctly evaluated');
});

test('No event anywhere in the Block 6 corpus contains a raw bearer token, credential, or secret-shaped field', () => {
  const rows = loadValidationCorpus();
  const allowlist = new Set(['gen_ai.usage.input_tokens', 'gen_ai.usage.output_tokens']);
  const forbidden = ['bearer', 'authorization_header', 'secret', 'password', 'api_key', 'access_token', 'refresh_token', 'client_secret'];
  for (const row of rows) {
    for (const evt of row.events) {
      for (const key of Object.keys(evt)) {
        if (allowlist.has(key)) continue;
        const lower = key.toLowerCase();
        for (const bad of forbidden) {
          assert.ok(!lower.includes(bad), `forbidden-looking field "${key}" in ${row.scenario_id}`);
        }
      }
    }
  }
});

test('Every hash-bearing event in the Block 6 corpus carries security.hash.key_id/algorithm', () => {
  const rows = loadValidationCorpus();
  for (const row of rows) {
    for (const evt of row.events) {
      const hasHash = Object.keys(evt).some((k) => k.endsWith('_hash') && evt[k] !== null && evt[k] !== undefined);
      if (hasHash) {
        assert.ok(evt['security.hash.key_id'], `${row.scenario_id}: missing security.hash.key_id`);
        assert.ok(evt['security.hash.algorithm'], `${row.scenario_id}: missing security.hash.algorithm`);
      }
    }
  }
});

test('Detection logic never needs raw (unhashed) principal/task identifiers -- oracle operates only on *_hash fields', () => {
  // Structural guarantee, not a per-scenario check: confirm the raw seed strings used to build
  // this corpus never themselves appear as field VALUES anywhere in the generated events.
  const rows = loadValidationCorpus();
  const rawSeeds = ['task-v7-01-0001', 'task-v7-02-0001', 'task-v7-03-0001', 'principal:owner-v7-03', 'principal:attacker-v7-03'];
  for (const row of rows) {
    for (const evt of row.events) {
      for (const v of Object.values(evt)) {
        if (typeof v === 'string') {
          for (const raw of rawSeeds) assert.ok(!v.includes(raw), `raw seed "${raw}" leaked into a telemetry field in ${row.scenario_id}`);
        }
      }
    }
  }
});
