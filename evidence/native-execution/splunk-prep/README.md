# Native SPL validation — prepared, execution blocked pending a license/terms decision

Everything possible without a running Splunk instance has been prepared and is ready to run the
moment that decision is made. **Splunk has not been started, pulled, or licensed.** No product
terms have been accepted.

## The exact blocker

Splunk's official Docker image (`splunk/splunk`) requires **two mandatory acceptance flags** to
start at all, regardless of which license tier is chosen:

```
SPLUNK_START_ARGS=--accept-license
SPLUNK_GENERAL_TERMS=--accept-sgt-current-at-splunk-com
```

- `SPLUNK_START_ARGS=--accept-license` accepts the Splunk Software License Agreement. There is
  no way to start the container without it — confirmed against current official Splunk
  documentation (`help.splunk.com`, "Deploy and run Splunk Enterprise inside a Docker
  container", and `splunk/docker-splunk`'s own docs).
- `SPLUNK_GENERAL_TERMS=--accept-sgt-current-at-splunk-com` is a **separate** required
  acceptance (Splunk Enterprise 10.x+ images), confirming acceptance of Splunk's current General
  Terms document. This is not optional and not implied by the license flag above.
- **`SPLUNK_LICENSE_URI=Free` does NOT bypass either requirement.** It only changes which
  license file gets installed after startup — switching the *tier* from the default 60-day
  **Enterprise Trial** to the permanent (but 500 MB/day-capped) **Splunk Free** tier. Both flags
  above are still mandatory either way. (This is exactly the "Free doesn't bypass terms"
  possibility flagged in the task instructions — checked, and confirmed true.)
- No Splunk.com account, email signup, or payment is required for either tier — only these two
  environment-variable acceptances.

**This is exactly the kind of action the project's standing instructions require pausing on
before proceeding**: it means asserting acceptance of a third party's license and general terms
on the user's behalf. Nothing further has been done until that decision is made. See the parent
conversation for the exact recommended command (below) and the explicit pause request.

**Recommended command, ready to run on approval** (uses `SPLUNK_LICENSE_URI=Free` specifically
to get a permanent, non-expiring tier rather than a 60-day trial — but again, this still
requires the same two acceptance flags above, not fewer):

```
docker run -d -p 8000:8000 -p 8089:8089 \
  -v "C:/Users/roshi/Desktop/McpProtocol:/repo:ro" \
  -e "SPLUNK_START_ARGS=--accept-license" \
  -e "SPLUNK_GENERAL_TERMS=--accept-sgt-current-at-splunk-com" \
  -e "SPLUNK_LICENSE_URI=Free" \
  -e "SPLUNK_PASSWORD=<a password you choose, not committed anywhere>" \
  --name splunk splunk/splunk:latest
```

The `-v ...:/repo:ro` bind mount is required for `run_native_validation.js`'s `docker exec ...
splunk add oneshot` ingestion step to reach the fixture JSONL files read-only from inside the
container — adjust the host path if your checkout lives elsewhere. Ports 8000 (Splunk Web) and
8089 (management REST API, used by the automation below) are exposed to localhost only.

## What IS prepared and ready

- **`props.conf`** — the `[mcp:audit:json]` sourcetype definition (`KV_MODE=json` for automatic
  JSON field extraction, `TIME_PREFIX`/`TIME_FORMAT` so `_time` is extracted from each event's
  own `timestamp` field at ingestion time — matching every `*.spl` file's assumption that
  `_time` already reflects it, since none of them compute it themselves).
- **`build_spl_queries.js`** (already run, output committed under `queries/`) — for all 25
  fixtures, generates the exact SPL search to execute: the real, **completely unmodified**
  `detections/spl/*.spl` query body, with only the base search's `index=mcp_security_audit
  sourcetype=mcp:audit:json` line(s) extended with `source="<fixture-file>.jsonl"` so each
  fixture's ingested events can be queried in isolation. The header/footer documentation
  comments (which happen to also mention the base search in passing prose) are left untouched —
  only the four real search occurrences in Track 3's query (the primary search plus three
  subsearches) and the one occurrence each in Track 1/Track 2 are scoped. See
  `fixtures-manifest.json` for the exact per-fixture mapping.
- **`run_native_validation.js`** — syntax-checked, not yet executed. Reads Splunk connection
  details and credentials ONLY from environment variables (`SPLUNK_HOST`, `SPLUNK_MGMT_PORT`,
  `SPLUNK_USER`, `SPLUNK_PASSWORD`) — refuses to run if `SPLUNK_PASSWORD` is unset, never writes
  a credential to any file or log. Once run, it will: confirm the Splunk management API is
  reachable and record the exact version/build; create the `mcp_security_audit` index if
  missing; ingest each fixture's **raw, unmodified JSONL file** via `splunk add oneshot`
  (real JSON ingestion through the real KV_MODE=json extraction pipeline — not a synthetic
  literal, unlike the KQL evidence's `datatable(...)` approach, so this DOES test real dotted-
  field/multivalue/empty-vs-missing extraction behavior, not an assumption about it); submit
  each prepared, source-scoped search via the REST search-jobs API; save the raw JSON response
  per fixture under `evidence/native-execution/runs-splunk/`.

## The 25 fixtures prepared (same set already natively validated for KQL)

See `fixtures-manifest.json` for the exact mapping. Covers, per the task's stated priorities:
- All 8 `V14-01`..`V14-08` scope-intersection cases, **including `V14-06`/`V14-07`
  (missing-vs-explicitly-empty `required_scope`) — the one case where native SPL extraction
  behavior can actually confirm or correct the documented "SPL cannot distinguish explicitly-
  empty from absent" limitation, rather than leaving it as an assumption.**
- The 3 previously-duplicated no-violation cases (`V11-07`, `V14-04`, `V14-05`) — proving the
  Track 3 remediation pass, part 5 row-collapse fix natively for SPL, not just by code parallel.
- 5 distinct-notification controls (`V11-02`, `V12-01`, `V12-13`, `V13-01`, `V13-06`) — proving
  the same fix's collapse logic never merges two genuinely different notifications.
- Further Track 3 binding/timing regressions (`V11-01` out-of-order multi-change, `V11-03`
  revocation+expiry tie, `V13-03` unknown-scope ambiguity, `V13-05` malformed-timing detection).
- 7 representative Track 1/Track 2 fixtures (`A1`, `A6`, `A11`, `A17` for Track 1; `A7`, `A11`,
  `A17` for Track 2).

## Next step

Pull and run the Splunk container per the exact command above **only after an explicit go-ahead
on the license/general-terms acceptance**, then run:

```
SPLUNK_HOST=localhost SPLUNK_MGMT_PORT=8089 SPLUNK_USER=admin SPLUNK_PASSWORD=<your password> \
  node evidence/native-execution/splunk-prep/run_native_validation.js
```

Compare `evidence/native-execution/runs-splunk/*.response.json` against the same expected
outcomes already documented in `evidence/native-execution/manifest.jsonl` (the KQL evidence) and
`tests/validation/track3_row_regression.test.js`, and update `docs/validation-report.md`/
`README.md`/`evidence/native-execution/README.md` with the actual native SPL results —
including whether `V14-07`'s documented missing-vs-empty divergence is confirmed as a genuine,
unavoidable platform limitation or turns out to be an artifact of this specific `KV_MODE=json`
configuration (do not assume either answer before the evidence is in).
