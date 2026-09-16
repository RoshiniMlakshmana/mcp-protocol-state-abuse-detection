# MCP Protocol-State Abuse Detection

Sigma/KQL/SPL detection rules, threat model, and a synthetic test corpus for three
protocol-state abuse patterns in the Model Context Protocol (MCP) Tasks extension
(SEP-2663) and long-lived subscriptions (`subscriptions/listen`, spec revision
`2026-07-28`). All metrics come from this project's own deterministic synthetic
corpus, not production telemetry.

## Detection tracks

| Track | Detects | Formats |
|---|---|---|
| 1. Task routing desynchronization | `Mcp-Method`/`Mcp-Name` header genuinely conflicts with the JSON-RPC body it should mirror | Sigma, KQL, SPL |
| 2. Cross-principal task authorization | A task request is denied specifically for a principal/task-context mismatch (`mcp.authz.reason = principal_mismatch`) | Sigma, KQL, SPL |
| 3. Long-lived subscription authorization drift | A `subscriptions/listen` notification is delivered after its authorization was revoked/expired, with no valid close in between | KQL, SPL (authoritative); Sigma (best-effort hunting only, see below) |

## Validation status

- **140/140 automated tests pass** as of the latest recorded run (re-run yourself to
  confirm; this figure is not re-verified on every README edit) — see
  `docs/validation-report.md` for the full breakdown and history.
- **Native KQL execution**: a representative sample of fixtures was run against
  Microsoft's local Kusto emulator (a Docker-hosted query engine), confirming the
  queries execute and produce the expected outcome. **This is not a deployed
  Microsoft Sentinel analytics rule, workspace, or alert pipeline** — no Sentinel
  environment has been used. See `evidence/native-execution/`.
- **Native SPL validation remains pending. Zero SPL detection fixtures have been
  executed** against a real Splunk instance. SPL is verified only by code review and
  structural parallel to the tested KQL. See `evidence/native-execution/splunk-prep/STATUS.md`.
- **Track 3's Sigma rule is best-effort hunting content only** — it is not
  semantically equivalent to the authoritative KQL/SPL implementations for that
  track (Sigma correlation cannot compare a field value to another event's own
  timestamp, or assert the absence of a closing event).

**Scope:**
- An alert from any of these rules does not, by itself, prove compromise or
  successful unauthorized access — see `docs/false-positive-analysis.md`.
- These rules do not detect prompt injection, jailbreaks, or LLM role confusion.
  They operate on MCP's protocol-state telemetry, not model/agent output content.

## Requirements

These detections depend on a **custom MCP security audit telemetry contract**
(`telemetry/schema.md`) that no platform (Sentinel, Splunk, OpenTelemetry) emits by
default. You must instrument your MCP server/gateway to produce it, map it to your
platform's field names (`telemetry/field-mapping.md`), and apply deployment-specific
tuning (e.g., grace-period allowlists for Track 3 — see `docs/false-positive-analysis.md`).

## Quick start

```bash
npm install
cd tools/harness && node generate.js && node generate_attacks.js && node generate_validation.js && cd ../..
node --test tests/normal/*.test.js tests/attack/*.test.js tests/detections/*.test.js tests/validation/*.test.js
```

Corpus generation is deterministic — reproduces every `.jsonl` file byte-for-byte.

## Documentation

- **Detection rules:** `detections/` (Sigma, KQL, SPL) — `detections/README.md`
- **Telemetry contract:** `telemetry/schema.md`, `telemetry/field-mapping.md`
- **Validation evidence:** `docs/validation-report.md`, `evidence/native-execution/`
- **Operational limitations:** `docs/false-positive-analysis.md`, `docs/evasion-limitations.md`
- **License:** Apache License 2.0 — `LICENSE`
