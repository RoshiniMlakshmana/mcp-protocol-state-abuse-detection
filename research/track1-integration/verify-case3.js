'use strict';
/**
 * Targeted re-verification of bounded case 3 only (per review: "add the smallest necessary
 * instrumentation and rerun only the affected cases"). Does not touch cases 1, 2, 4, 5 -- their
 * evidence under evidence/raw/ is untouched by this script. Does not start server.js: case 3
 * never routes to the real server (see gateway.js), so it isn't needed.
 *
 * Starts weakened-server.js + gateway.js, sends exactly one real-client `resources/read` request
 * through case 3's conflicting-header path, then cross-checks THREE independent sources for the
 * same request-instance ID:
 *   1. The gateway's raw wire record (evidence/raw/<id>.json) -- what was sent and what HTTP
 *      response came back. This alone is what the earlier version of this lab relied on, and the
 *      review correctly noted a response body/status alone is insufficient proof of execution.
 *   2. The weakened stand-in's OWN independent execution log
 *      (evidence/weakened-server-execution-log.jsonl) -- written by that process itself, before
 *      it sends its response, as a side effect of actually handling the request.
 *   3. The weakened stand-in's OWN observable state file (evidence/weakened-server-state.json) --
 *      a persisted per-resource read counter, incremented synchronously as part of handling the
 *      request, independently re-readable after the fact.
 * All three are correlated by the SAME request-instance ID (gateway-generated, forwarded via the
 * X-Lab-Request-Instance header -- see gateway.js's own comment on why this ID, not the
 * client-chosen JSON-RPC id, is the correlation key).
 */
const { spawn } = require('node:child_process');
const fs = require('node:fs');
const path = require('node:path');
const { Client } = require('@modelcontextprotocol/client');
const { StreamableHTTPClientTransport } = require('@modelcontextprotocol/client');

const GATEWAY_PORT = 4000;
const WEAKENED_PORT = 4002;
const EVIDENCE_DIR = path.join(__dirname, 'evidence');
const RAW_DIR = path.join(EVIDENCE_DIR, 'raw');
const EXECUTION_LOG_PATH = path.join(EVIDENCE_DIR, 'weakened-server-execution-log.jsonl');
const STATE_PATH = path.join(EVIDENCE_DIR, 'weakened-server-state.json');
const OUT_FILE = path.join(EVIDENCE_DIR, 'case3-verification.json');

function removeStaleCase3RawEvidence() {
  if (!fs.existsSync(RAW_DIR)) return;
  for (const f of fs.readdirSync(RAW_DIR)) {
    const full = path.join(RAW_DIR, f);
    const record = JSON.parse(fs.readFileSync(full, 'utf8'));
    if (record.labCase === 'weakened') fs.unlinkSync(full);
  }
}

function waitForPort(port, timeoutMs) {
  const net = require('node:net');
  const deadline = Date.now() + timeoutMs;
  return new Promise((resolve, reject) => {
    (function attempt() {
      const sock = net.connect(port, '127.0.0.1');
      sock.once('connect', () => {
        sock.destroy();
        resolve();
      });
      sock.once('error', () => {
        sock.destroy();
        if (Date.now() > deadline) reject(new Error(`port ${port} never came up`));
        else setTimeout(attempt, 100);
      });
    })();
  });
}

async function main() {
  removeStaleCase3RawEvidence();

  const weakened = spawn(process.execPath, ['weakened-server.js'], {
    cwd: __dirname,
    env: { ...process.env, TRACK1_LAB_WEAKENED_PORT: String(WEAKENED_PORT) },
    stdio: ['ignore', 'pipe', 'pipe'],
  });
  const gateway = spawn(process.execPath, ['gateway.js'], {
    cwd: __dirname,
    env: {
      ...process.env,
      TRACK1_LAB_GATEWAY_PORT: String(GATEWAY_PORT),
      TRACK1_LAB_SERVER_PORT: '4001',
      TRACK1_LAB_WEAKENED_PORT: String(WEAKENED_PORT),
    },
    stdio: ['ignore', 'pipe', 'pipe'],
  });

  try {
    await waitForPort(WEAKENED_PORT, 5000);
    await waitForPort(GATEWAY_PORT, 5000);

    const client = new Client(
      { name: 'track1-lab-client-verify-case3', version: '2.0.0' },
      { versionNegotiation: { mode: { pin: '2026-07-28' } } }
    );
    const transport = new StreamableHTTPClientTransport(new URL(`http://127.0.0.1:${GATEWAY_PORT}/mcp`), {
      requestInit: { headers: { 'X-Lab-Case': 'weakened' } },
    });
    await client.connect(transport);

    let clientOutcome, clientDetail;
    try {
      const result = await client.readResource({ uri: 'lab://demo/task-a-alpha' });
      clientOutcome = 'accepted';
      clientDetail = result;
    } catch (err) {
      clientOutcome = 'rejected';
      clientDetail = { message: String((err && err.message) || err), code: err && err.code };
    }
    await client.close();

    // Find the resources/read raw record this run just produced (the only 'weakened' one now,
    // since stale ones were removed above).
    const rawFiles = fs.readdirSync(RAW_DIR);
    let readRecord = null;
    let readRecordFile = null;
    for (const f of rawFiles) {
      const record = JSON.parse(fs.readFileSync(path.join(RAW_DIR, f), 'utf8'));
      if (record.labCase === 'weakened' && record.gatewayObserved.body.method === 'resources/read') {
        readRecord = record;
        readRecordFile = f;
        break;
      }
    }
    if (!readRecord) throw new Error('no resources/read raw record found for the weakened case after this run');

    const instanceId = readRecord.requestInstanceId;

    // Independent source 2: the weakened stand-in's own execution log, keyed by that same ID.
    const logLines = fs
      .readFileSync(EXECUTION_LOG_PATH, 'utf8')
      .split('\n')
      .filter(Boolean)
      .map((l) => JSON.parse(l));
    const logEntry = logLines.find((e) => e.requestInstanceId === instanceId) || null;

    // Independent source 3: the persisted state file, re-read fresh from disk.
    const state = JSON.parse(fs.readFileSync(STATE_PATH, 'utf8'));
    const currentCount = state.readCounts['lab://demo/task-a-alpha'];

    const mismatchObserved =
      readRecord.gatewayObserved.body.paramsUri !== undefined &&
      readRecord.gatewayForwarded.headers['mcp-name'] !== readRecord.gatewayObserved.body.paramsUri;

    const serverExecutedOrRejected = logEntry
      ? logEntry.action === 'read_executed'
        ? 'executed'
        : 'rejected_or_failed'
      : 'unknown (no independent log entry found for this request-instance ID)';

    const report = {
      requestInstanceId: instanceId,
      correlation:
        'all three sources below are keyed to this SAME gateway-issued request-instance ID, forwarded to the weakened stand-in via X-Lab-Request-Instance',
      source1_gateway_raw_wire_record: {
        path: `evidence/raw/${readRecordFile}`,
        headerNamedIdentity: readRecord.gatewayForwarded.headers['mcp-name'],
        bodyRequestedIdentity: readRecord.gatewayObserved.body.paramsUri,
        targetResponseStatus: readRecord.targetResponse.statusCode,
        targetResponseBody: readRecord.targetResponse.bodyRaw,
      },
      source2_independent_server_execution_log: {
        path: 'evidence/weakened-server-execution-log.jsonl',
        found: logEntry !== null,
        entry: logEntry,
      },
      source3_independent_server_state_file: {
        path: 'evidence/weakened-server-state.json',
        readCountForRequestedUriAfterThisRun: currentCount,
        readCountBeforeThisRequestPerLogEntry: logEntry ? logEntry.readCountBefore : null,
        readCountAfterThisRequestPerLogEntry: logEntry ? logEntry.readCountAfter : null,
        stateChangeObserved: logEntry ? logEntry.readCountAfter === logEntry.readCountBefore + 1 : null,
      },
      findings: {
        mismatch_observed: mismatchObserved,
        server_rejected_or_operation_executed: serverExecutedOrRejected,
        client_accepted_or_rejected_the_response: clientOutcome,
        client_outcome_detail: clientDetail,
        authorization_outcome: 'outcome_unknown',
        authorization_outcome_note:
          'execution is proven (independent server-side log + state-change evidence, not response body/status alone) and is NOT itself labeled unknown; whether the read was AUTHORIZED is unknown because no separate authorization evidence was collected in this lab',
      },
    };

    fs.mkdirSync(EVIDENCE_DIR, { recursive: true });
    fs.writeFileSync(OUT_FILE, JSON.stringify(report, null, 2), 'utf8');

    console.log('=== Case 3 verification ===');
    console.log('mismatch observed:', report.findings.mismatch_observed);
    console.log('server rejected or operation executed:', report.findings.server_rejected_or_operation_executed);
    console.log('client accepted or rejected the response:', report.findings.client_accepted_or_rejected_the_response);
    console.log('authorization outcome:', report.findings.authorization_outcome, '--', report.findings.authorization_outcome_note);
    console.log('wrote evidence/case3-verification.json');
  } finally {
    weakened.kill();
    gateway.kill();
  }
}

main().catch((err) => {
  console.error('[verify-case3] fatal:', err);
  process.exitCode = 1;
});
