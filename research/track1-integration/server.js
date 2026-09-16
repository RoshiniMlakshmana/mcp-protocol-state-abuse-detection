'use strict';
/**
 * REAL MCP server for the Track 1 integration lab -- @modelcontextprotocol/server@2.0.0,
 * genuinely installed and imported, not reimplemented. Uses its actual, unmodified
 * standard-header validation (SEP-2243 Mcp-Method/Mcp-Name vs body cross-check,
 * -32020 HeaderMismatch) -- confirmed by reading the shipped dist/ source
 * (node_modules/@modelcontextprotocol/server/dist/src-CX2iR2pK.mjs,
 * `validateStandardRequestHeaders`) before writing this file, not assumed from docs.
 *
 * Uses `resources/read` (a genuine 2026-07-28 core method), NOT `tasks/get`, because the
 * installed SDK's SEP-2663 Tasks extension has no runtime -- see docs/sdk-discrepancy.md.
 * `resources/read`'s `params.uri` is covered by the identical Mcp-Name/body cross-check
 * mechanism (confirmed in MCP_NAME_HEADER_SOURCE in the shipped source: tools/call -> name,
 * prompts/get -> name, resources/read -> uri) and is fully implemented in v2.
 *
 * Uses `createMcpHandler` + `toNodeHandler` (the package's documented HTTP entry point,
 * @modelcontextprotocol/server + @modelcontextprotocol/node), NOT a manually-paired persistent
 * `McpServer` + per-request `NodeStreamableHTTPServerTransport`. An earlier version of this file
 * used the manual pairing and correctly served the LEGACY (2025-11-25) era, but every attempt to
 * negotiate the MODERN (2026-07-28) era -- required for Mcp-Method/Mcp-Name at all -- failed the
 * client's pre-initialize `server/discover` probe with -32601 Method not found, even after
 * explicitly widening `supportedProtocolVersions` on both the server and the transport. Reading
 * `Protocol._onrequest` (src-CX2iR2pK.mjs ~6365-6403) showed why: the manually-constructed
 * transport's per-request codec negotiation never reaches a state where
 * `codec.hasRequestMethod('server/discover')` is true, because `server/discover` classification
 * and the modern-only handler install are documented as being the HTTP entry's job
 * ("installs the modern-only server/discover handler on an instance the HTTP entry has marked as
 * serving the 2026-07-28 era ... Hand-constructed instances are unaffected"). `createMcpHandler`
 * is that documented entry point -- switching to it resolved the probe with no further
 * workarounds needed.
 *
 * Two fictional resources stand in for "Task A" / "Task B" in the bounded test cases below.
 * No real task, principal, or credential is involved anywhere in this lab.
 */
const { createServer } = require('node:http');
const { createMcpHandler, McpServer } = require('@modelcontextprotocol/server');
const { toNodeHandler, localhostHostValidation, localhostOriginValidation } = require('@modelcontextprotocol/node');

const PORT = Number(process.env.TRACK1_LAB_SERVER_PORT || 4001);

function buildServer() {
  const server = new McpServer({ name: 'track1-lab-real-server', version: '2.0.0' });
  server.registerResource(
    'task-a-alpha',
    'lab://demo/task-a-alpha',
    { title: 'Fictional Task A (alpha)', mimeType: 'text/plain' },
    async (uri) => ({ contents: [{ uri: uri.href, text: 'lab-fixture: fictional Task A (alpha) content' }] })
  );
  server.registerResource(
    'task-b-bravo',
    'lab://demo/task-b-bravo',
    { title: 'Fictional Task B (bravo)', mimeType: 'text/plain' },
    async (uri) => ({ contents: [{ uri: uri.href, text: 'lab-fixture: fictional Task B (bravo) content' }] })
  );
  return server;
}

// One fresh McpServer instance per serving unit (one HTTP request under createMcpHandler's
// default 'stateless' legacy posture, or one modern per-request envelope exchange) -- this is
// the factory shape createMcpHandler's own type documents, not a lab-specific simplification.
const mcpHandler = createMcpHandler((_ctx) => buildServer());
const nodeHandler = toNodeHandler(mcpHandler);

const validateHost = localhostHostValidation();
const validateOrigin = localhostOriginValidation();

const httpServer = createServer(async (req, res) => {
  if (!validateHost(req, res) || !validateOrigin(req, res)) return;
  await nodeHandler(req, res);
});

httpServer.listen(PORT, '127.0.0.1', () => {
  console.log(`[real-server] @modelcontextprotocol/server@2.0.0 listening on http://127.0.0.1:${PORT}`);
});

process.on('SIGTERM', () => httpServer.close(() => process.exit(0)));
