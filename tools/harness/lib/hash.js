'use strict';
const crypto = require('crypto');

// Test-only HMAC pepper for this reproducible corpus. Never a production secret;
// published deliberately so the corpus is independently regeneratable byte-for-byte.
// Per telemetry/schema.md section 6: never derived from bearer tokens/credentials,
// only from post-verification identity claims / opaque protocol identifiers.
const TEST_HMAC_KEY = Buffer.from('block3-normal-corpus-TEST-KEY-not-for-production-use', 'utf8');

const HASH_KEY_ID = 'block3-test-key-v1';
const HASH_ALGORITHM = 'HMAC-SHA-256-16B'; // HMAC-SHA-256, output truncated to 16 bytes / 32 hex chars

/**
 * Canonicalize + HMAC a raw identity value (taskId, principal subject, resource URI, etc.)
 * per telemetry/schema.md section 6, rule 5 (same scheme required for equality comparison).
 */
function hmacHash(rawValue) {
  if (rawValue === null || rawValue === undefined) return null;
  const canonical = String(rawValue).trim();
  const mac = crypto.createHmac('sha256', TEST_HMAC_KEY).update(canonical, 'utf8').digest();
  return 'h_' + mac.subarray(0, 16).toString('hex');
}

module.exports = { hmacHash, HASH_KEY_ID, HASH_ALGORITHM };
