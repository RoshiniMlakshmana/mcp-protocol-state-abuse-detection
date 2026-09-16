'use strict';
/**
 * ============================================================================
 * NOT AN MCP SDK. NOT INDEPENDENT SDK VALIDATION. LAB-ONLY. DO NOT DEPLOY.
 * ============================================================================
 *
 * This is a hand-written, deliberately unprotected JSON-RPC stand-in used ONLY for bounded
 * case 3 (the explicitly weakened lab-only mode). It exists because the real, installed
 * @modelcontextprotocol/server@2.0.0 has NO documented or discoverable option to disable its
 * SEP-2243 standard-header validation -- confirmed by reading the shipped dist/ source before
 * writing this file: `validateStandardRequestHeaders` is called unconditionally from the
 * package's internal HTTP entry point (`serveModern`), with no exposed toggle.
 *
 * This file does NOT import or exercise @modelcontextprotocol/server or @modelcontextprotocol/client
 * in any way for its own request handling -- it is plain node:http with a hand-parsed JSON-RPC
 * body. It intentionally skips ANY Mcp-Method/Mcp-Name header check before acting on the body.
 * Its purpose is narrow: observe what a hypothetical unprotected implementation would do with a
 * header/body-conflicting request, for comparison against the real SDK's confirmed,
 * non-bypassable enforcement. It proves nothing about the real SDK, and nothing about
 * unauthorized access -- only whether request processing proceeds without SEP-2243 enforcement.
 */
const { createServer } = require('node:http');
const fs = require('node:fs');
const path = require('node:path');

const PORT = Number(process.env.TRACK1_LAB_WEAKENED_PORT || 4002);

const RESOURCES = {
  'lab://demo/task-a-alpha': 'lab-fixture: fictional Task A (alpha) content',
  'lab://demo/task-b-bravo': 'lab-fixture: fictional Task B (bravo) content',
};

// Independent, out-of-band execution evidence: a durable, on-disk record written by THIS
// process as a side effect of actually serving a resource read, separate from the HTTP response
// the gateway proxies back to the client. A response body alone only proves what bytes crossed
// the wire; this proves the server-side process itself took an action, correlated to the
// gateway-issued request-instance ID (forwarded via X-Lab-Request-Instance -- see gateway.js).
//
// Two forms, both checked by verify-case3.js:
//  1. An append-only execution log (one durable line per request, written before the response is
//     sent, so it exists independent of whether the response is ever successfully delivered).
//  2. An observable harmless state change: a per-resource read counter, persisted to disk and
//     re-read+incremented+rewritten synchronously for every successful read, so its value before
//     and after a specific request can be diffed.
const EVIDENCE_DIR = path.join(__dirname, 'evidence');
const EXECUTION_LOG_PATH = path.join(EVIDENCE_DIR, 'weakened-server-execution-log.jsonl');
const STATE_PATH = path.join(EVIDENCE_DIR, 'weakened-server-state.json');
fs.mkdirSync(EVIDENCE_DIR, { recursive: true });

function readState() {
  try {
    return JSON.parse(fs.readFileSync(STATE_PATH, 'utf8'));
  } catch {
    return { readCounts: {} };
  }
}

function recordExecution(entry) {
  fs.appendFileSync(EXECUTION_LOG_PATH, JSON.stringify({ pid: process.pid, loggedAt: new Date().toISOString(), ...entry }) + '\n', 'utf8');
}

function recordStateChangingRead(uri) {
  const state = readState();
  const before = state.readCounts[uri] || 0;
  const after = before + 1;
  state.readCounts[uri] = after;
  fs.writeFileSync(STATE_PATH, JSON.stringify(state, null, 2), 'utf8');
  return { before, after };
}

const httpServer = createServer((req, res) => {
  let raw = '';
  req.on('data', (c) => (raw += c));
  req.on('end', () => {
    let body;
    try {
      body = JSON.parse(raw);
    } catch {
      res.writeHead(400, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ jsonrpc: '2.0', id: null, error: { code: -32700, message: 'Parse error' } }));
      return;
    }
    // The real Client SDK, pinned to the modern (2026-07-28) era (required to exercise
    // Mcp-Method/Mcp-Name at all -- see client-runner.js), sends a `server/discover` probe
    // before ANY other request, regardless of target, and modern era uses a per-request `_meta`
    // envelope instead of a persistent initialize/notifications-initialized handshake (confirmed
    // empirically: the real server's own evidence/raw records show server/discover directly
    // followed by resources/read, no initialize in between). This stand-in must answer the probe
    // (minimally, correctly) or connect() itself throws before this file's actual point (skipping
    // the header/body check on resources/read) is ever reached.
    if (body.method === 'server/discover') {
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({
        jsonrpc: '2.0',
        id: body.id,
        result: {
          supportedVersions: ['2026-07-28'],
          capabilities: { resources: { listChanged: true } },
          resultType: 'complete',
          ttlMs: 0,
          cacheScope: 'private',
          _meta: { 'io.modelcontextprotocol/serverInfo': { name: 'track1-lab-weakened-stand-in', version: '2.0.0' } },
        },
      }));
      return;
    }
    if (body.method === 'initialize') {
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({
        jsonrpc: '2.0',
        id: body.id,
        result: {
          protocolVersion: body.params?.protocolVersion || '2026-07-28',
          capabilities: { resources: { listChanged: true } },
          serverInfo: { name: 'track1-lab-weakened-stand-in', version: '2.0.0' },
        },
      }));
      return;
    }
    if (body.method === 'notifications/initialized') {
      res.writeHead(202);
      res.end();
      return;
    }

    // NO header/body consistency check here -- that is the entire point of this file.
    if (body.method === 'resources/read') {
      const requestInstanceId = req.headers['x-lab-request-instance'] || null;
      const uri = body.params?.uri;
      const text = RESOURCES[uri];
      if (text === undefined) {
        recordExecution({ requestInstanceId, requestedUri: uri, action: 'read_failed_not_found' });
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ jsonrpc: '2.0', id: body.id, error: { code: -32002, message: 'Resource not found', data: { uri } } }));
        return;
      }
      // The state-changing action (the counter read+increment+write) happens BEFORE the response
      // is written, so the on-disk record exists independent of the response ever being sent.
      const { before, after } = recordStateChangingRead(uri);
      recordExecution({ requestInstanceId, requestedUri: uri, action: 'read_executed', readCountBefore: before, readCountAfter: after });
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ jsonrpc: '2.0', id: body.id, result: { contents: [{ uri, text }] } }));
      return;
    }
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ jsonrpc: '2.0', id: body.id, error: { code: -32601, message: 'Method not found' } }));
  });
});

httpServer.listen(PORT, '127.0.0.1', () => {
  console.log(`[weakened-lab-stand-in] NOT an MCP SDK -- listening on http://127.0.0.1:${PORT}`);
});

process.on('SIGTERM', () => httpServer.close(() => process.exit(0)));
