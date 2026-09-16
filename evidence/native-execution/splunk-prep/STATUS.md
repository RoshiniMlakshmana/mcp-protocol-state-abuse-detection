# Native SPL validation attempt — blocked, closed out

**Status: attempted, blocked, not completed.** This is a factual record of what was tried and
where it stopped. It does not claim native SPL execution succeeded, and it should not be read as
superseding or extending the KQL evidence recorded elsewhere under `evidence/native-execution/`.

## What was verified

- A local Splunk Docker container (`splunk/splunk:latest`) was started with the authorized
  **Splunk Free** license (`SPLUNK_LICENSE_URI=Free`), after explicit user authorization to
  accept the required `SPLUNK_START_ARGS=--accept-license` and
  `SPLUNK_GENERAL_TERMS=--accept-sgt-current-at-splunk-com` flags.
- The license was confirmed genuinely Free — `splunk list licenses` showed `label:Splunk Free`,
  `status:VALID`, `expiration_time` at the maximum value (no expiry, not a trial).
- A harmless test search (`| makeresults | eval x=1`) executed successfully against this
  instance via the Splunk CLI, confirming the search pipeline itself worked under the Free
  license once a workaround was used for a genuine Free-tier constraint: **Splunk Free disables
  authenticated remote/REST API management by design** ("Remote login disabled because you are
  using a free license which does not provide authentication") — this is a structural product
  limitation, not a trial/payment gate, and it was worked around by running searches via the
  Splunk CLI inside the container instead of the REST API.

## What went wrong

- The detection queries assume dotted JSON fields are already extracted at search time
  (`KV_MODE=json`), which required installing a custom `props.conf` and restarting Splunk to
  load it (search-time extraction settings did not appear to take effect without a restart).
- An initial attempt to supply `props.conf` via a read-only bind mount at container startup
  conflicted with Splunk's own first-boot provisioning (a directory-ownership step stalled for
  several minutes, then the container exited). This approach was abandoned; `props.conf` was
  instead copied in after a clean startup.
- Triggering `splunk restart` from the CLI (required to load the new `props.conf`) caused
  Splunk's own internal logging to record a fragment of the admin password as part of an
  "interrupt signal received" diagnostic message tied to its internal restart/shutdown handling
  — this occurred on two separate restart attempts and appears to be a structural behavior of
  this Docker image's restart path, not something avoided by letting the command run
  uninterrupted in the background.
- After the second such restart, Splunk did not return to a responsive state within a bounded
  5-minute readiness check (repeated harmless test searches). The container was then stopped
  (not removed) per instruction, without a third restart attempt.

## Current disposition

- **Zero detection fixtures were ingested or tested.** No SPL query from `detections/spl/` was
  ever executed against real ingested data. `evidence/native-execution/runs-splunk/` does not
  exist — there is nothing to report there.
- **Native SPL validation remains entirely pending.** The Track 3 SPL fixes (parts 4 and 5),
  and Track 1/Track 2 SPL, remain verified only by code inspection and structural parallel to
  the natively-verified KQL, exactly as already disclosed in `README.md` and
  `docs/validation-report.md` before this attempt began.
- **The root cause of Splunk becoming unresponsive after the restart is not confirmed.** No
  explicit error, crash, or out-of-memory signal was found in the container's logs when
  filtered for such indicators; it simply did not return to a ready state within the observed
  window. This is recorded as unconfirmed, not diagnosed.
- **The affected container (name `splunk`, image `splunk/splunk:latest`) is stopped, not
  removed, and must not be restarted or reused.** Its admin credential was exposed (in
  truncated fragment form) in Splunk's own internal container logs on two occasions during this
  attempt and must be treated as compromised. If Splunk is attempted again in the future, it
  must be a **new** container with a **newly generated** password — never a resumption of this
  one.
- No credential value, full or fragmentary, appears anywhere in this file, in any other
  committed file, or in `evidence/native-execution/` generally. The exposure occurred only in
  this session's interactive tool output/logs, which are not part of the committed repository.

## What remains prepared and reusable

Everything under `evidence/native-execution/splunk-prep/` other than this status file was
prepared but is **not evidence of execution** — it is tooling and generated input, ready for a
future attempt with a fresh container and credential:

- `props.conf` — the sourcetype definition, unaffected by this attempt's failure mode (the
  problem was the delivery/reload mechanism, not the configuration content itself).
- `build_spl_queries.js` and `queries/*.spl` (already generated, committed) — the exact,
  unmodified SPL query bodies for all 25 previously-identified representative fixtures, each
  scoped to its own ingestion `source`. These were never executed.
- `run_native_validation.js` — the original REST-API-based orchestration script. **Superseded
  by the CLI-based approach used in this attempt** (REST management is blocked under Free); a
  future attempt should use `splunk search`/`splunk add oneshot` via the CLI instead, and should
  budget for the restart step's credential-logging behavior (e.g. by rotating the password
  immediately after any restart, before running further commands, rather than assuming it is
  safe to reuse).

## Distinguishing this from the KQL evidence

`evidence/native-execution/README.md`, `manifest.jsonl`, `runs/`, and `prefix-baseline/` document
**completed, successful native KQL execution** (25 fixtures, real Kusto engine, all passing) and
are unaffected by anything in this file. This `STATUS.md` and the rest of `splunk-prep/` document
a **separate, blocked SPL attempt** and must not be conflated with the KQL results.
