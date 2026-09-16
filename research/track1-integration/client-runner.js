'use strict';
/**
 * REAL MCP client for the Track 1 integration lab -- @modelcontextprotocol/client@2.0.0,
 * genuinely installed and imported, issuing genuine `resources/read` requests over genuine
 * HTTP to the gateway (gateway.js), which forwards to either the real server (server.js) or
 * the clearly-labeled weakened stand-in (weakened-server.js). This file records the CLIENT'S
 * OWN observed outcome per case; gateway.js separately records what it observed/forwarded, and
 * lib/audit.js derives telemetry-contract events from both afterward.
 *
 * Fictional identities only: "Task A (alpha)" / "Task B (bravo)" are lab://demo/ resource URIs
 * with no real-world referent, per instruction.
 */
const fs = require('node:fs');
const path = require('node:path');
const { Client } = require('@modelcontextprotocol/client');
const { StreamableHTTPClientTransport } = require('@modelcontextprotocol/client');

const GATEWAY_URL = new URL(`http://127.0.0.1:${process.env.TRACK1_LAB_GATEWAY_PORT || 4000}/mcp`);
const TASK_A = 'lab://demo/task-a-alpha';
const TASK_B = 'lab://demo/task-b-bravo';

async function newClientForCase(labCase) {
  // Pin to the modern 2026-07-28 era explicitly. The client's own DEFAULT is
  // `mode: 'legacy'` (confirmed in the shipped .d.cts: "The default is 'legacy'":
  // connect() runs the plain 2025 sequence, no probe, NO new headers). Without this
  // pin, the client never sends Mcp-Method/Mcp-Name at all -- confirmed by a first
  // dry run where every case negotiated protocolVersion "2025-11-25" and the
  // gateway's raw evidence showed no mcp-method/mcp-name header on any request,
  // which silently made the "conflicting identifiers" case indistinguishable from
  // the normal case. Pinning is required for SEP-2243 to be exercised at all.
  const client = new Client(
    { name: `track1-lab-client-${labCase}`, version: '2.0.0' },
    { versionNegotiation: { mode: { pin: '2026-07-28' } } }
  );
  const transport = new StreamableHTTPClientTransport(GATEWAY_URL, {
    requestInit: { headers: { 'X-Lab-Case': labCase } },
  });
  await client.connect(transport);
  return { client, transport };
}

async function runReadResource(labCase, uri) {
  const { client, transport } = await newClientForCase(labCase);
  const startedAt = new Date().toISOString();
  let outcome, resultOrError;
  try {
    const result = await client.readResource({ uri });
    outcome = 'success';
    resultOrError = result;
  } catch (err) {
    outcome = 'error';
    resultOrError = { message: String(err && err.message || err), code: err && err.code };
  }
  await client.close();
  return { labCase, requestedUri: uri, startedAt, finishedAt: new Date().toISOString(), outcome, resultOrError };
}

async function runConcurrentPair(labCase, uriA, uriB) {
  // Two INDEPENDENT client/transport instances -- each is a fresh JSON-RPC "connection" whose
  // own request-id counter starts fresh, so both naturally issue id="1" for their first
  // request. This is the real SDK's own natural behavior, not something forced by this file.
  const startedAt = new Date().toISOString();
  const [a, b] = await Promise.all([newClientForCase(labCase), newClientForCase(labCase)]);
  const [resA, resB] = await Promise.allSettled([
    a.client.readResource({ uri: uriA }),
    b.client.readResource({ uri: uriB }),
  ]);
  await Promise.all([a.client.close(), b.client.close()]);
  return {
    labCase,
    startedAt,
    finishedAt: new Date().toISOString(),
    branchA: { requestedUri: uriA, outcome: resA.status === 'fulfilled' ? 'success' : 'error', resultOrError: resA.status === 'fulfilled' ? resA.value : { message: String(resA.reason && resA.reason.message || resA.reason) } },
    branchB: { requestedUri: uriB, outcome: resB.status === 'fulfilled' ? 'success' : 'error', resultOrError: resB.status === 'fulfilled' ? resB.value : { message: String(resB.reason && resB.reason.message || resB.reason) } },
  };
}

async function main() {
  const log = [];

  // Case 1: matching header/body -- normal operation.
  log.push({ case: 1, description: 'Matching header/body: normal operation', ...(await runReadResource('normal', TASK_A)) });

  // Case 2: conflicting identifiers -- gateway rewrites the header away from the body;
  // real server is expected to enforce SEP-2243 and reject. Observed, not assumed.
  log.push({ case: 2, description: 'Conflicting task identifiers: real server validation', ...(await runReadResource('conflict', TASK_A)) });

  // Case 3: the SAME conflict, explicitly weakened lab-only mode (routed to the clearly-labeled
  // non-SDK stand-in, since the real SDK has no documented way to disable its own check).
  log.push({ case: 3, description: 'Same conflict, explicitly weakened lab-only mode', ...(await runReadResource('weakened', TASK_A)) });

  // Case 4: encoded vs decoded representation of the SAME identity -- must not produce a false
  // mismatch. Gateway re-encodes the (already-correct) header into the Base64 sentinel form.
  log.push({ case: 4, description: 'Encoded/decoded representations of the same identity: no false mismatch', ...(await runReadResource('encoding', TASK_A)) });

  // Case 5: two concurrent requests, independently likely to reuse JSON-RPC id="1" (two fresh
  // connections), reading DIFFERENT resources -- correlation must not cross-contaminate.
  log.push({ case: 5, description: 'Concurrent requests with reused JSON-RPC IDs: no cross-request correlation errors', ...(await runConcurrentPair('normal', TASK_A, TASK_B)) });

  const outDir = path.join(__dirname, 'evidence');
  fs.mkdirSync(outDir, { recursive: true });
  fs.writeFileSync(path.join(outDir, 'client-observed-cases.json'), JSON.stringify(log, null, 2), 'utf8');
  console.log(`[client-runner] wrote evidence/client-observed-cases.json (${log.length} case records)`);
}

main().catch((err) => {
  console.error('[client-runner] fatal:', err);
  process.exit(1);
});
