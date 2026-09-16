'use strict';
/**
 * ============================================================================
 * PROJECT-AUTHORED LAB INFRASTRUCTURE. NOT PART OF ANY MCP SDK.
 * ============================================================================
 *
 * Stands in for the "intermediary" in this project's own threat model
 * (README.md / detections/README.md: "an intermediary routing on the header and a server
 * executing the body can act on two different things"). A real client (@modelcontextprotocol/
 * client@2.0.0) ALWAYS sends genuinely-consistent Mcp-Method/Mcp-Name headers derived from its
 * own outgoing message body -- confirmed by reading the shipped client source
 * (node_modules/@modelcontextprotocol/client/dist/index.mjs, `_applyBodyDerivedHeaders`) before
 * writing this file: there is no client-side way to send a mismatched header. Any
 * header/body disagreement a downstream server sees, in a real deployment, was introduced (or
 * failed to be introduced) somewhere between the honest client and the server -- i.e. here, at
 * the gateway. This file makes that injection point explicit and inspectable instead of leaving
 * it implicit.
 *
 * Lab-only control: the client-runner sets a `X-Lab-Case` header naming which bounded case is
 * running. This header is a LAB ORCHESTRATION SIGNAL ONLY -- not part of MCP, not one of the
 * telemetry contract's fields, and is stripped before forwarding and before audit-event
 * generation so it can never be confused with real protocol data.
 *
 * For every inbound request, regardless of case, this gateway:
 *   1. Generates a request-instance ID BEFORE reading the JSON-RPC body (lib/correlate.js) --
 *      the correlation key used everywhere downstream, never the client-chosen JSON-RPC id.
 *   2. Records exactly what it observed on the wire (raw headers + body), unmodified.
 *   3. Applies the case-specific transformation described below (or none, for the normal case).
 *   4. Forwards to a target server and proxies its raw response back to the client unmodified.
 *   5. Persists a sanitized record of steps 2-4 to evidence/raw/<instance-id>.json.
 *
 * No hashing/canonicalization/detection logic lives here -- lib/audit.js derives telemetry
 * events from these raw records afterward, from what was ACTUALLY observed, not from what this
 * file expected to happen.
 */
const http = require('node:http');
const fs = require('node:fs');
const path = require('node:path');
const { newRequestInstanceId } = require('./lib/correlate');

const GATEWAY_PORT = Number(process.env.TRACK1_LAB_GATEWAY_PORT || 4000);
const REAL_SERVER_PORT = Number(process.env.TRACK1_LAB_SERVER_PORT || 4001);
const WEAKENED_SERVER_PORT = Number(process.env.TRACK1_LAB_WEAKENED_PORT || 4002);

const RAW_DIR = path.join(__dirname, 'evidence', 'raw');
fs.mkdirSync(RAW_DIR, { recursive: true });

const FICTIONAL_URIS = ['lab://demo/task-a-alpha', 'lab://demo/task-b-bravo'];
function theOtherFictionalUri(uri) {
  const other = FICTIONAL_URIS.find((u) => u !== uri);
  return other || FICTIONAL_URIS[0];
}
function encodeSentinel(value) {
  return `=?base64?${Buffer.from(value, 'utf8').toString('base64')}?=`;
}

function readBody(req) {
  return new Promise((resolve, reject) => {
    let raw = '';
    req.on('data', (c) => (raw += c));
    req.on('end', () => resolve(raw));
    req.on('error', reject);
  });
}

const httpServer = http.createServer(async (req, res) => {
  const instanceId = newRequestInstanceId();
  const labCase = req.headers['x-lab-case'] || 'normal';
  const receivedAt = new Date().toISOString();
  const rawBody = await readBody(req);

  let parsed;
  try {
    parsed = JSON.parse(rawBody || '{}');
  } catch {
    parsed = null;
  }

  const observedHeaders = {
    'mcp-method': req.headers['mcp-method'] ?? null,
    'mcp-name': req.headers['mcp-name'] ?? null,
    'mcp-protocol-version': req.headers['mcp-protocol-version'] ?? null,
  };
  const observedBody = {
    method: parsed?.method ?? null,
    id: parsed?.id ?? null,
    paramsUri: parsed?.params?.uri ?? null,
  };

  // --- Apply the case-specific gateway transformation ---
  let targetPort = REAL_SERVER_PORT;
  let outgoingMcpName = observedHeaders['mcp-name'];
  let transformNote = 'none (passthrough)';

  if (labCase === 'conflict' || labCase === 'weakened') {
    if (observedBody.paramsUri) {
      const conflicting = theOtherFictionalUri(observedBody.paramsUri);
      outgoingMcpName = conflicting; // deliberately names the OTHER fictional resource than the body
      transformNote = `gateway rewrote mcp-name to a CONFLICTING identity ("${conflicting}") not matching body params.uri ("${observedBody.paramsUri}")`;
    }
    if (labCase === 'weakened') {
      targetPort = WEAKENED_SERVER_PORT;
      transformNote += '; routed to the lab-only weakened stand-in (NOT the real SDK server) because the real server has no documented way to disable its header/body check';
    }
  } else if (labCase === 'encoding') {
    if (outgoingMcpName) {
      outgoingMcpName = encodeSentinel(outgoingMcpName);
      transformNote = `gateway re-encoded mcp-name into the =?base64?...?= sentinel form (same underlying identity, different wire representation)`;
    }
  }

  const outgoingHeaders = {
    'content-type': req.headers['content-type'] || 'application/json',
    accept: req.headers['accept'] || 'application/json, text/event-stream',
  };
  if (observedHeaders['mcp-method']) outgoingHeaders['mcp-method'] = observedHeaders['mcp-method'];
  if (outgoingMcpName) outgoingHeaders['mcp-name'] = outgoingMcpName;
  if (observedHeaders['mcp-protocol-version']) outgoingHeaders['mcp-protocol-version'] = observedHeaders['mcp-protocol-version'];

  const record = {
    requestInstanceId: instanceId,
    labCase,
    receivedAt,
    gatewayObserved: { headers: observedHeaders, body: observedBody },
    gatewayForwarded: { targetPort, headers: outgoingHeaders, transformNote },
    targetResponse: null, // filled in below
  };

  const proxyReq = http.request(
    { host: '127.0.0.1', port: targetPort, path: req.url, method: req.method, headers: outgoingHeaders },
    (proxyRes) => {
      let responseBody = '';
      proxyRes.on('data', (c) => (responseBody += c));
      proxyRes.on('end', () => {
        record.targetResponse = {
          statusCode: proxyRes.statusCode,
          headers: { 'content-type': proxyRes.headers['content-type'] || null },
          bodyRaw: responseBody,
          respondedAt: new Date().toISOString(),
        };
        fs.writeFileSync(path.join(RAW_DIR, `${instanceId}.json`), JSON.stringify(record, null, 2), 'utf8');
      });
      res.writeHead(proxyRes.statusCode, proxyRes.headers);
      proxyRes.pipe(res);
    }
  );
  proxyReq.on('error', (err) => {
    record.targetResponse = { statusCode: null, error: String(err && err.message || err), respondedAt: new Date().toISOString() };
    fs.writeFileSync(path.join(RAW_DIR, `${instanceId}.json`), JSON.stringify(record, null, 2), 'utf8');
    res.writeHead(502, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ jsonrpc: '2.0', id: observedBody.id, error: { code: -32000, message: 'Gateway: target unreachable' } }));
  });
  proxyReq.end(rawBody);
});

httpServer.listen(GATEWAY_PORT, '127.0.0.1', () => {
  console.log(`[gateway] lab intermediary listening on http://127.0.0.1:${GATEWAY_PORT} (real target :${REAL_SERVER_PORT}, weakened target :${WEAKENED_SERVER_PORT})`);
});

process.on('SIGTERM', () => httpServer.close(() => process.exit(0)));
