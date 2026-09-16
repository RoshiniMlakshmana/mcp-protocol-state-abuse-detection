# MCP Task Routing Header/Body Desynchronization Attempt

**Canonical source (keep in sync if either changes):**
`detections/sigma/mcp_task_routing_desynchronization.yml`,
`detections/kql/mcp_task_routing_desynchronization.kql`,
`detections/spl/mcp_task_routing_desynchronization.spl`

## Description

Detects a Streamable HTTP MCP request where the `Mcp-Method` or `Mcp-Name` routing header
(SEP-2243, MCP specification revision `2026-07-28`) carries a value that genuinely **conflicts**
with the corresponding JSON-RPC body field (`method`, or `params.taskId`/`name`/`uri`). Fires
only on an actual value disagreement — never on a missing or version-incompatible header, which
is legitimate compatibility traffic under an older, still-negotiable protocol version.

## Why it matters

The `2026-07-28` specification requires servers to validate these headers against the body
specifically because a load balancer, gateway, or rate limiter may route or police traffic using
the header alone while a downstream component executes on the JSON-RPC body. A genuine conflict
is the exact condition under which two components in the request path can disagree about which
method or task is actually being acted on.

## Data source

Project-defined MCP security audit telemetry (`telemetry/schema.md`). **These fields are not
assumed to exist by default in Sentinel, Splunk, or OpenTelemetry deployments** — see
`telemetry/field-mapping.md` and the "Data source disclosure" note below.

## Required fields

| Field | Source category |
|---|---|
| `event.name` | project-defined event taxonomy |
| `mcp.validation.method.result`, `mcp.validation.name.result` | project-defined (enum: `match`\|`conflict`\|`missing`\|`malformed`\|`version_incompatible`) |
| `mcp.header.method`, `mcp.body.method` | MCP wire values |
| `mcp.header.name_hash`, `mcp.body.identity_hash` | MCP wire values, pseudonymized |
| `mcp.validation.source` | project-defined (`server_native`\|`collector_derived`) — confidence context, never a filter gate |
| `jsonrpc.request.id` | standard (OTel JSON-RPC semantic convention) |

## Query — Sigma

```yaml
title: MCP Task Routing Header/Body Value Disagreement
id: cf8ac1f5-8911-4061-b3d5-435a6febdd44
status: experimental
description: |
    Detects a Streamable HTTP MCP request where the Mcp-Method or Mcp-Name routing header
    (SEP-2243, MCP specification revision 2026-07-28) carries a value that conflicts with the
    corresponding JSON-RPC body field (method, or params.taskId/name/uri). This rule fires
    ONLY on an actual value disagreement (mcp.validation.*.result = "conflict"). It
    deliberately does NOT fire on a missing header, which under an older, still-supported
    protocol negotiation is legitimate compatibility traffic rather than a routing violation.
references:
    - https://modelcontextprotocol.io/specification/2026-07-28/basic/transports/streamable-http
    - https://modelcontextprotocol.io/specification/2026-07-28/changelog
author: MCP Protocol-State Abuse Detection project
date: 2026-09-13
logsource:
    category: application
    product: mcp
    service: mcp_security_audit
detection:
    selection_event:
        event.name: mcp.request.validation
    selection_conflict:
        mcp.validation.method.result: conflict
    selection_conflict_alt:
        mcp.validation.name.result: conflict
    condition: selection_event and 1 of selection_conflict*
fields:
    - jsonrpc.request.id
    - mcp.header.method
    - mcp.body.method
    - mcp.header.name_hash
    - mcp.body.identity_hash
    - mcp.validation.method.result
    - mcp.validation.name.result
    - mcp.validation.source
    - mcp.validation.reason
falsepositives:
    - Client, SDK, or proxy implementation defects that mirror a stale header value while
      sending a different body value.
    - A migration-era client library that partially implements SEP-2243.
    - A malformed request from a non-compliant, in-development client.
level: high
tags:
    - detection.threat-hunting
```

A separate, lower-severity **diagnostic** rule
(`detections/sigma/mcp_task_routing_missing_header_diagnostic.yml`) covers `missing`/
`malformed` results and must never be conflated with this one.

## Query — KQL

`MCPSecurityAudit` is a **project/example table name — not a built-in Microsoft Sentinel
table.** A deployment must ingest the telemetry contract into a custom table with this name (or
edit the table name below) with Block 2 field names preserved verbatim as column names
(including dots), accessed via bracket-quoted identifiers. See `telemetry/field-mapping.md`.

```kql
MCPSecurityAudit
| where ['event.name'] == "mcp.request.validation"
| where ['mcp.validation.method.result'] == "conflict"
    or ['mcp.validation.name.result'] == "conflict"
| extend
    Severity = "High",
    DetectionTrack = "Track1_TaskRoutingDesynchronization",
    ConflictOnMethod = (['mcp.validation.method.result'] == "conflict"),
    ConflictOnIdentity = (['mcp.validation.name.result'] == "conflict")
| project
    ['timestamp'], Severity, DetectionTrack, ['jsonrpc.request.id'], ['mcp.protocol.version'],
    ['mcp.header.method'], ['mcp.body.method'], ['mcp.header.name_hash'], ['mcp.body.identity_hash'],
    ConflictOnMethod, ConflictOnIdentity, ['mcp.validation.method.result'],
    ['mcp.validation.name.result'], ['mcp.validation.source'], ['mcp.validation.reason']
| order by ['timestamp'] asc
```

Full file, including the commented-out low-confidence diagnostic query:
`detections/kql/mcp_task_routing_desynchronization.kql`.

## Query — SPL

`index=mcp_security_audit sourcetype=mcp:audit:json` is an **explicit placeholder — Splunk does
not natively emit MCP security audit events.** Create this index/sourcetype and ingest the
telemetry contract, or edit the index/sourcetype below to match your environment.

```spl
index=mcp_security_audit sourcetype=mcp:audit:json "event.name"="mcp.request.validation"
    ("mcp.validation.method.result"="conflict" OR "mcp.validation.name.result"="conflict")
| eval Severity="High"
| eval DetectionTrack="Track1_TaskRoutingDesynchronization"
| eval ConflictOnMethod=if('mcp.validation.method.result'="conflict", "true", "false")
| eval ConflictOnIdentity=if('mcp.validation.name.result'="conflict", "true", "false")
| table _time Severity DetectionTrack "jsonrpc.request.id" "mcp.protocol.version"
    "mcp.header.method" "mcp.body.method" "mcp.header.name_hash" "mcp.body.identity_hash"
    ConflictOnMethod ConflictOnIdentity "mcp.validation.method.result" "mcp.validation.name.result"
    "mcp.validation.source" "mcp.validation.reason"
| sort 0 _time
```

Full file, including the separate diagnostic search: `detections/spl/mcp_task_routing_desynchronization.spl`.

## False positives

- Client/proxy implementation defects that mirror a stale header value while the body carries
  current data.
- A migration-era client library partially implementing SEP-2243.
- A malformed request from a non-compliant, in-development client — a real protocol violation,
  not necessarily hostile.
- **Collector canonicalization defects (confirmed operational risk):** a collector that hashes a
  Base64-sentinel-encoded `Mcp-Name` header without decoding it first will manufacture an
  artificial conflict for an identical underlying value. Mechanically verified in this project's
  own validation corpus (`data/validation/track1/v1_canonicalization_instrumentation_gap.jsonl`,
  scenario V1-08). Treat `mcp.validation.source = collector_derived` conflicts as lower
  confidence pending `server_native` corroboration.

## Limitations

- Depends entirely on trustworthy upstream routing-field parsing/canonicalization; the rule has
  no access to raw header/body values to independently verify a collector's work.
- A protocol-version downgrade (forced or spoofed by a client) sheds the header requirement
  entirely and produces no evidence for this rule to act on.
- No MITRE ATT&CK technique is assigned — see below.

## Validation and native-execution disclosures

- **All validation data is synthetic**, generated by this project's own deterministic reference
  harness (`tools/harness/`) — never production telemetry, never captured from a real MCP
  deployment.
- **This detection requires custom MCP security audit instrumentation and field mapping** — see
  "Data source" above and `telemetry/field-mapping.md`. None of the required fields are emitted
  by Sentinel, Splunk, or any OpenTelemetry deployment by default.
- **An alert from this rule does not, by itself, prove compromise or successful unauthorized
  access.** See "False positives" above and `docs/false-positive-analysis.md` before treating a
  hit as confirmed malicious.
- **KQL and SPL are implemented counterparts of the Sigma logic above**, mechanically verified
  identical via three independently-written JS predicates comparing outcomes across the full
  stress corpus (`tests/validation/language_equivalence.test.js`) — this is JS-model comparison,
  not native execution of either language.
- **Native KQL execution:** 4 representative test cases for this track (A1, A6, A11, A17 —
  synthetic fixtures) were separately, and later, executed against a real Kusto query engine:
  Microsoft's local "Kusto emulator" Docker image
  (`mcr.microsoft.com/azuredataexplorer/kustainer-linux`). **This is native KQL query execution
  only — it is NOT a deployed Microsoft Sentinel analytics rule, workspace, or alert pipeline.**
  All 4 produced the expected outcome. Full record (part of a 25-fixture, 28-execution run
  spanning all three tracks): `evidence/native-execution/manifest.jsonl`.
- **Native SPL execution has not been performed for this detection. Zero SPL fixtures were
  executed.** An authorized attempt was made using a local Splunk Free instance (license
  verified genuinely Free, not a trial) but the instance became unresponsive after a required
  configuration restart before any fixture could be tested; the root cause is unconfirmed. See
  `evidence/native-execution/splunk-prep/STATUS.md`.

## Investigation fields

`jsonrpc.request.id`, `mcp.header.method`/`mcp.body.method`, `mcp.header.name_hash`/
`mcp.body.identity_hash`, `mcp.validation.source`, `mcp.validation.reason`, `mcp.protocol.version`,
`trace_id` (if present).

## References

- MCP specification `2026-07-28`, Streamable HTTP transport: https://modelcontextprotocol.io/specification/2026-07-28/basic/transports/streamable-http
- MCP specification `2026-07-28` changelog (SEP-2243): https://modelcontextprotocol.io/specification/2026-07-28/changelog
- MCP specification `2026-07-28` versioning: https://modelcontextprotocol.io/specification/2026-07-28/basic/versioning

## Severity recommendation

**High** for the primary (conflict) rule. **Low** for the separate diagnostic
(missing/malformed) rule — never promoted to the same severity, per the locked project
invariant that a missing header must not be treated as equivalent to a conflicting one.

## MITRE ATT&CK

`No precise ATT&CK technique assigned.` This detects a transport-envelope inconsistency
equally produced by a buggy client, a misconfigured intermediary, or a deliberate probe. No
current ATT&CK technique precisely describes MCP routing header/body desynchronization; forcing
a loosely related tag would misrepresent the finding.
