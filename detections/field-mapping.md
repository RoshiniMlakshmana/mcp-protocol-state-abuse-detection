# Detection Field Mapping

Every field referenced by every rule in `detections/` is taken **verbatim** from the locked
Block 2 telemetry contract (`telemetry/schema.md`, `telemetry/events.md`). No rule invents a
field name. Where a rule needs a placeholder table/index name (KQL, SPL), that name is
documented here as **hypothetical** — it does not exist in any product by default.

## Placeholder telemetry sources

| Language | Placeholder name | Status |
|---|---|---|
| Sigma | `logsource: category: application, product: mcp, service: mcp_security_audit` | A custom Sigma `logsource` for this project; not a SigmaHQ-registered product |
| KQL | Table `MCPSecurityAudit` | **Does not exist in Microsoft Sentinel by default.** A deployment must ingest the Block 2 event stream into a custom log table (e.g. via a custom table / DCR) named this, or update the table name in these queries to match. |
| SPL | `index=mcp_security_audit sourcetype=mcp:audit:json` | **Not a Splunk-shipped index.** A deployment must create this index and ingest Block 2 JSONL events into it (e.g. via HEC), or update the `index`/`sourcetype` in these searches. |

## Field reference (only fields actually used by a Block 5 rule)

| Block 2 field | Type | Used by | Notes |
|---|---|---|---|
| `event.name` | string | all rules | Selects the audit event type (`mcp.request.validation`, `mcp.task.authorization`, `mcp.subscription.*`) |
| `mcp.protocol.version` | string | Track 1 | Present for context; the primary/diagnostic split is driven by the pre-computed `mcp.validation.*.result` fields, not by re-deriving version-gating in the rule itself |
| `mcp.validation.method.result` | enum | Track 1 | `match`\|`conflict`\|`missing`\|`malformed`\|`version_incompatible` |
| `mcp.validation.name.result` | enum | Track 1 | Same enum |
| `mcp.validation.result` | enum | Track 1 (fields, not filter) | `valid`\|`invalid` roll-up, included for analyst context |
| `mcp.validation.source` | enum | Track 1 | `server_native`\|`collector_derived` — used to set confidence, never to gate whether the rule fires |
| `mcp.header.method`, `mcp.body.method` | string | Track 1 (fields) | Investigation context |
| `mcp.header.name_hash`, `mcp.body.identity_hash` | string (hash) | Track 1 (fields) | Investigation context — pseudonymized, per Block 2 §6 |
| `jsonrpc.request.id` | string | Track 1 (fields) | Correlates received/validation/response for one request |
| `principal.id_hash` | string (hash) | Track 2, Track 3 | Never the raw principal identity |
| `principal.authenticated` | boolean | Track 2 (fields) | Investigation context |
| `mcp.task.id_hash` | string (hash) | Track 2 (fields) | |
| `mcp.task.authz_context_id_hash` | string (hash) or null | Track 2 (fields only — never a filter condition) | Per the Block 2 patch: null must never gate or suppress the rule |
| `mcp.task.operation` | enum | Track 2 (fields) | `create`\|`get`\|`update`\|`cancel` |
| `mcp.authz.decision` | enum | Track 2 | `allow`\|`deny` |
| `mcp.authz.reason` | enum | Track 2 | Only `principal_mismatch` gates the primary rule; `policy_denied`/`insufficient_scope`/`context_unbound`/`unknown` never do |
| `mcp.subscription.id` | string | Track 3 | Join/group-by key |
| `mcp.subscription.state` | enum | Track 3 (fields) | |
| `mcp.subscription.notification_type` | string | Track 3 (fields) | |
| `mcp.subscription.close.reason` | enum | Track 3 | Used to detect a valid close before the notification |
| `mcp.authz.change.type` | enum | Track 3 (fields) | |
| `mcp.authz.change.source` | enum | Track 3 (fields) | |
| `mcp.authz.change.effective_at` | timestamp | Track 3 | Preferred boundary when authoritative |
| `mcp.authz.change.detected_at` | timestamp | Track 3 | Fallback only, never promoted to high confidence alone |
| `mcp.authz.change.timing_confidence` | enum | Track 3 | `authoritative`\|`detected_only` — gates which boundary field is trusted |
| `mcp.authz.valid_until` | timestamp | Track 3 | Expiry boundary, used when no authorization_change event exists at all |
| `mcp.subscription.notification.contains_inline_result` | boolean | none (explicitly excluded) | Experimental-only field (Block 4 A-EXP1); no Block 5 rule keys on it |
| `trace_id`, `mcp.output.bytes`, `mcp.output.item_count`, `gen_ai.usage.*`, `mcp.output.schema_valid` | various | enrichment only | Never appear in any rule's filter/condition logic — enrichment fields only, per the explicit non-negotiable in `telemetry/schema.md` §4 |

## Explicit non-use

No rule in `detections/` filters, thresholds, or scores on: `mcp.output.bytes`,
`mcp.output.item_count`, `gen_ai.usage.input_tokens`, `gen_ai.usage.output_tokens`,
`mcp.output.schema_valid`. They may appear only in a rule's `fields:` list (Sigma) or output
projection (KQL/SPL) for analyst context after a verdict is already reached on other grounds.
