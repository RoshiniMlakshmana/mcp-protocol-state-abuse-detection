'use strict';
// Orchestrates native SPL validation once a permitted Splunk instance is running and reachable.
// NOT YET EXECUTED as of this file's creation -- see evidence/native-execution/splunk-prep/README.md
// for exactly why (Splunk was not started this pass, pending an explicit license/terms decision).
//
// What this does, in order:
//   1. Confirms the Splunk management REST endpoint answers and reports version/license info.
//   2. Creates the mcp_security_audit index if it doesn't already exist.
//   3. Installs props.conf's [mcp:audit:json] sourcetype definition (KV_MODE=json + time
//      extraction) via the REST configuration endpoint, if not already present.
//   4. Ingests each of the 25 prepared fixtures' RAW, UNMODIFIED JSONL files via the CLI
//      `oneshot` upload, tagged with source=<basename> so each fixture's events can be queried
//      in isolation without ever reshaping the source data.
//   5. Submits each fixture's prepared, source-scoped SPL search (queries/<id>.spl -- the real
//      detections/spl/*.spl query body, verbatim, only the base search's source= was added) via
//      the REST search-jobs API, polls to completion, and saves the raw JSON results.
//
// Credentials: read ONLY from environment variables (SPLUNK_HOST, SPLUNK_MGMT_PORT,
// SPLUNK_USER, SPLUNK_PASSWORD). Never written to any file, never printed, never included in
// saved evidence. If SPLUNK_PASSWORD is unset, this script refuses to run rather than prompting
// interactively or embedding a default.
//
// Usage (once Splunk is confirmed running and its license/terms decision has been made):
//   SPLUNK_HOST=localhost SPLUNK_MGMT_PORT=8089 SPLUNK_USER=admin SPLUNK_PASSWORD=*** \
//     node run_native_validation.js

const fs = require('fs');
const path = require('path');
const https = require('https');
const { execFileSync } = require('child_process');

const HOST = process.env.SPLUNK_HOST || 'localhost';
const MGMT_PORT = process.env.SPLUNK_MGMT_PORT || '8089';
const USER = process.env.SPLUNK_USER || 'admin';
const PASSWORD = process.env.SPLUNK_PASSWORD;
const CONTAINER_NAME = process.env.SPLUNK_CONTAINER || 'splunk';
const INDEX = 'mcp_security_audit';
const SOURCETYPE = 'mcp:audit:json';

if (!PASSWORD) {
  console.error('SPLUNK_PASSWORD is not set. Refusing to run rather than prompt or assume a default.');
  process.exit(1);
}

const repoRoot = path.resolve(__dirname, '..', '..', '..');
const outDir = path.join(__dirname, '..', 'runs-splunk');
fs.mkdirSync(outDir, { recursive: true });

function restRequest(method, urlPath, body) {
  return new Promise((resolve, reject) => {
    const data = body ? new URLSearchParams(body).toString() : undefined;
    const req = https.request(
      {
        host: HOST, port: MGMT_PORT, path: urlPath, method,
        auth: `${USER}:${PASSWORD}`,
        rejectUnauthorized: false, // local/self-signed instance only
        headers: data ? { 'Content-Type': 'application/x-www-form-urlencoded', 'Content-Length': Buffer.byteLength(data) } : {},
      },
      (res) => {
        let chunks = '';
        res.on('data', (c) => (chunks += c));
        res.on('end', () => resolve({ status: res.statusCode, body: chunks }));
      }
    );
    req.on('error', reject);
    if (data) req.write(data);
    req.end();
  });
}

async function ensureIndex() {
  const check = await restRequest('GET', `/services/data/indexes/${INDEX}?output_mode=json`);
  if (check.status === 200) { console.log(`Index ${INDEX} already exists.`); return; }
  const create = await restRequest('POST', '/services/data/indexes', { name: INDEX });
  if (create.status >= 200 && create.status < 300) console.log(`Created index ${INDEX}.`);
  else throw new Error(`Failed to create index ${INDEX}: HTTP ${create.status}`);
}

function ingestFixture(relFixturePath) {
  const abs = path.join(repoRoot, relFixturePath);
  const source = path.basename(relFixturePath);
  // `splunk add oneshot` runs inside the Splunk container against a path visible to it -- this
  // assumes the repo is bind-mounted into the container (see README.md for the exact `docker run`
  // invocation this expects). Password is passed via -auth from the same env var, never logged.
  execFileSync('docker', [
    'exec', CONTAINER_NAME, '/opt/splunk/bin/splunk', 'add', 'oneshot', abs,
    '-sourcetype', SOURCETYPE, '-index', INDEX, '-source', source,
    '-auth', `${USER}:${PASSWORD}`,
  ], { stdio: 'pipe' });
  console.log(`Ingested ${source} (source=${source}, index=${INDEX}, sourcetype=${SOURCETYPE})`);
}

async function runSearch(id, splFile) {
  const spl = fs.readFileSync(splFile, 'utf8');
  // Wide time bounds: fixtures use synthetic 2026-10-xx timestamps -- earliest=0 covers any
  // deterministic test date without needing per-fixture tuning.
  const create = await restRequest('POST', '/services/search/jobs?output_mode=json', {
    search: spl, earliest_time: '0', latest_time: 'now', exec_mode: 'blocking',
  });
  if (create.status !== 201 && create.status !== 200) {
    throw new Error(`${id}: search creation failed HTTP ${create.status}: ${create.body.slice(0, 500)}`);
  }
  const sid = JSON.parse(create.body).sid;
  const results = await restRequest('GET', `/services/search/jobs/${sid}/results?output_mode=json&count=0`);
  fs.writeFileSync(path.join(outDir, `${id}.response.json`), results.body, 'utf8');
  fs.writeFileSync(path.join(outDir, `${id}.spl`), spl, 'utf8');
  const parsed = JSON.parse(results.body);
  console.log(`${id}: ${parsed.results ? parsed.results.length : '?'} row(s)`);
}

async function main() {
  const version = await restRequest('GET', '/services/server/info?output_mode=json');
  if (version.status !== 200) throw new Error(`Cannot reach Splunk mgmt API at https://${HOST}:${MGMT_PORT}: HTTP ${version.status}`);
  const info = JSON.parse(version.body).entry[0].content;
  fs.mkdirSync(path.join(__dirname, '..', 'engine'), { recursive: true });
  fs.writeFileSync(path.join(__dirname, '..', 'engine', 'splunk-version.json'), JSON.stringify({
    version: info.version, build: info.build, licenseState: info.license_state || info.licenseState,
  }, null, 2));
  console.log(`Splunk reachable: version ${info.version} build ${info.build}`);

  await ensureIndex();

  const manifest = JSON.parse(fs.readFileSync(path.join(__dirname, 'fixtures-manifest.json'), 'utf8'));
  for (const { fixture_file } of manifest) ingestFixture(fixture_file);

  // Let ingestion settle before searching.
  await new Promise((r) => setTimeout(r, 5000));

  for (const { id } of manifest) {
    await runSearch(id, path.join(__dirname, 'queries', `${id}.spl`));
  }
  console.log('\nDone. Raw results in evidence/native-execution/runs-splunk/.');
}

main().catch((e) => { console.error(e); process.exit(1); });
