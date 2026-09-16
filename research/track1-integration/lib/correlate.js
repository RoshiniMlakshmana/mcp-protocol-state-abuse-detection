'use strict';
/**
 * Request-instance correlation, deliberately independent of the client-chosen JSON-RPC `id`.
 * The gateway (the server-adjacent component in this lab's topology -- see README.md) generates
 * one instance ID per inbound HTTP request BEFORE looking at the JSON-RPC body at all, so two
 * concurrent requests that happen to reuse the same JSON-RPC id (bounded case 5) never collide
 * in the audit trail. This mirrors telemetry/schema.md's own instance-id pattern
 * (mcp.subscription.instance_id) applied to request/response correlation instead of subscriptions.
 */
const crypto = require('node:crypto');

function newRequestInstanceId() {
  return 'reqinst_' + crypto.randomUUID();
}

module.exports = { newRequestInstanceId };
