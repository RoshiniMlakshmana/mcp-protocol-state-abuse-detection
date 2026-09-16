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
 * package's internal HTTP entry point (`serveModern`), with no exposed toggle. See
 * evidence/case3-weakened-mode-notes.md for that verification.
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

const PORT = Number(process.env.TRACK1_LAB_WEAKENED_PORT || 4002);

const RESOURCES = {
  'lab://demo/task-a-alpha': 'lab-fixture: fictional Task A (alpha) content',
  'lab://demo/task-b-bravo': 'lab-fixture: fictional Task B (bravo) content',
};

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
      const uri = body.params?.uri;
      const text = RESOURCES[uri];
      res.writeHead(200, { 'Content-Type': 'application/json' });
      if (text === undefined) {
        res.end(JSON.stringify({ jsonrpc: '2.0', id: body.id, error: { code: -32002, message: 'Resource not found', data: { uri } } }));
      } else {
        res.end(JSON.stringify({ jsonrpc: '2.0', id: body.id, result: { contents: [{ uri, text }] } }));
      }
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
