# MCP Security Audit Events

Companion to `telemetry/schema.md`. These ten event names (`mcp.request.received` through
`mcp.response`) are **project-defined audit event identifiers** — they are not official
MCP protocol names, not OpenTelemetry span/event names, and must not be represented as such in
later blocks (Sigma/KQL/SPL, dashboards, detections.ai publication). Field-level provenance
(what's standard vs. MCP-wire vs. invented) is in `telemetry/field-mapping.md`.

Each example is minimal — it shows only the fields required for that event type per
`telemetry/schema.md`, plus one or two illustrative optional fields. Hash values below are
illustrative placeholders (`h_...`), not real HMAC output.

---

## 1. `mcp.request.received`

Emitted when the MCP server accepts an inbound JSON-RPC request (or notification) at the
transport layer, before any routing/authorization validation runs.

```json
{
  "timestamp": "2026-09-12T14:02:01.100Z",
  "event.name": "mcp.request.received",
  "event.category": "network",
  "mcp.protocol.version": "2026-07-28",
  "mcp.transport": "streamable-http",
  "rpc.system.name": "jsonrpc",
  "rpc.method": "tasks/cancel",
  "mcp.body.method": "tasks/cancel",
  "jsonrpc.request.id": "9",
  "mcp.header.method": "tasks/cancel",
  "mcp.header.name_hash": "h_9f21ac...",
  "mcp.body.identity_hash": "h_9f21ac...",
  "security.hash.key_id": "k2026-09",
  "security.hash.algorithm": "HMAC-SHA-256-16B",
  "http.request.method": "POST",
  "trace_id": "4bf92f3577b34da6a3ce929d0e0e4736"
}
```

## 2. `mcp.request.validation`

Emitted once per request, immediately after `mcp.request.received`, carrying the Track 1
routing-consistency verdict.

```json
{
  "timestamp": "2026-09-12T14:02:01.104Z",
  "event.name": "mcp.request.validation",
  "event.category": "network",
  "event.outcome": "success",
  "mcp.protocol.version": "2026-07-28",
  "mcp.transport": "streamable-http",
  "jsonrpc.request.id": "9",
  "mcp.body.method": "tasks/cancel",
  "mcp.header.method": "tasks/cancel",
  "mcp.header.name_hash": "h_9f21ac...",
  "mcp.body.identity_hash": "h_9f21ac...",
  "mcp.validation.method.result": "match",
  "mcp.validation.name.result": "match",
  "mcp.validation.result": "valid",
  "mcp.validation.source": "server_native",
  "security.hash.key_id": "k2026-09",
  "security.hash.algorithm": "HMAC-SHA-256-16B"
}
```

## 3. `mcp.task.authorization`

Emitted whenever a server performs (or is required by SEP-2663 to perform) an
authentication/authorization check on a task-related operation. This event exists specifically
so Track 2 does not have to be inferred from a `-32602` response (Block 1 §10).

```json
{
  "timestamp": "2026-09-12T14:02:01.110Z",
  "event.name": "mcp.task.authorization",
  "event.category": "iam",
  "event.outcome": "failure",
  "principal.id_hash": "h_bob_7ac3...",
  "principal.authenticated": true,
  "mcp.task.id_hash": "h_9f21ac...",
  "mcp.task.authz_context_id_hash": "h_alice_1e02...",
  "mcp.task.operation": "cancel",
  "mcp.authz.decision": "deny",
  "mcp.authz.allowed": false,
  "mcp.authz.reason": "principal_mismatch",
  "security.hash.key_id": "k2026-09",
  "security.hash.algorithm": "HMAC-SHA-256-16B"
}
```

`mcp.task.authz_context_id_hash` is present in this example, so it corroborates the denial. If
a server cannot expose that binding at all, this field is `null` — that null carries no meaning
of its own; the finding here would still stand purely on `mcp.authz.decision: deny` +
`mcp.authz.reason: principal_mismatch`. See `telemetry/correlation.md` for the full null-handling
rule.

## 4. `mcp.task.state`

Emitted on every observed task-state transition (from a `CreateTaskResult` seed, a `tasks/get`
poll, a `tasks/update`, or a terminal transition). Carries lifecycle and enrichment fields only
— never the task's actual result/error payload content.

```json
{
  "timestamp": "2026-09-12T14:02:03.500Z",
  "event.name": "mcp.task.state",
  "event.category": "process",
  "mcp.task.id_hash": "h_9f21ac...",
  "mcp.task.state": "completed",
  "mcp.task.previous_state": "working",
  "mcp.output.schema_valid": true,
  "mcp.output.bytes": 48213,
  "mcp.output.item_count": 12,
  "gen_ai.usage.input_tokens": 812,
  "gen_ai.usage.output_tokens": 340
}
```

## 5. `mcp.subscription.open`

Emitted when a `subscriptions/listen` request is received, before acknowledgment — captures
the authorization state that will need to stay valid for the life of the stream.

```json
{
  "timestamp": "2026-09-12T14:05:00.000Z",
  "event.name": "mcp.subscription.open",
  "event.category": "session",
  "mcp.protocol.version": "2026-07-28",
  "mcp.transport": "streamable-http",
  "jsonrpc.request.id": "42",
  "mcp.subscription.id": "42",
  "principal.id_hash": "h_alice_1e02...",
  "principal.authenticated": true,
  "mcp.authz.grant_snapshot_hash": "h_grant_c001...",
  "mcp.authz.grant_expiry": "2026-09-12T15:05:00Z",
  "mcp.authz.valid_until": "2026-09-12T15:05:00Z",
  "mcp.subscription.filter_types": { "resourcesListChanged": false, "toolsListChanged": false },
  "security.hash.key_id": "k2026-09",
  "security.hash.algorithm": "HMAC-SHA-256-16B"
}
```
At open time, `mcp.authz.valid_until` starts out equal to `mcp.authz.grant_expiry` (both read
from the token's `exp` claim). `mcp.authz.valid_until` may later be updated by a
`mcp.subscription.authorization_change` event (e.g., a renewal or a scope downgrade);
`mcp.authz.grant_expiry` never changes — it stays the historical snapshot from this event.

## 6. `mcp.subscription.acknowledged`

Emitted when the server sends `notifications/subscriptions/acknowledged`, entering the "active"
state.

```json
{
  "timestamp": "2026-09-12T14:05:00.050Z",
  "event.name": "mcp.subscription.acknowledged",
  "event.category": "session",
  "event.outcome": "success",
  "mcp.subscription.id": "42",
  "principal.id_hash": "h_alice_1e02...",
  "mcp.subscription.state": "acknowledged",
  "mcp.subscription.filter_hash": ["h_uri_a1b2..."]
}
```

## 7. `mcp.subscription.notification`

Emitted for each notification delivered on an active subscription's response stream.

```json
{
  "timestamp": "2026-09-12T14:20:00.000Z",
  "event.name": "mcp.subscription.notification",
  "event.category": "session",
  "mcp.subscription.id": "42",
  "principal.id_hash": "h_alice_1e02...",
  "mcp.subscription.state": "active",
  "mcp.subscription.notification_type": "notifications/resources/updated",
  "mcp.subscription.notification.resource_uri_hash": "h_uri_a1b2..."
}
```

## 8. `mcp.subscription.authorization_change`

Emitted when an external signal (authorization server, policy engine, or a locally computed
token-expiry) indicates a principal's authorization has changed. This event has **no MCP wire
representation** — it is sourced from outside the MCP protocol and correlated in by
`principal.id_hash`.

```json
{
  "timestamp": "2026-09-12T14:30:00.000Z",
  "event.name": "mcp.subscription.authorization_change",
  "event.category": "iam",
  "principal.id_hash": "h_alice_1e02...",
  "mcp.authz.change.type": "revoked",
  "mcp.authz.change.source": "authorization_server_event",
  "mcp.authz.change.effective_at": "2026-09-12T14:29:55.000Z",
  "mcp.authz.change.detected_at": "2026-09-12T14:30:00.000Z",
  "mcp.authz.change.timing_confidence": "authoritative"
}
```

**`detected_only` variant** (no push feed; the pipeline only learns of the change via a later
introspection call and cannot determine exactly when it took effect):

```json
{
  "timestamp": "2026-09-12T14:30:00.000Z",
  "event.name": "mcp.subscription.authorization_change",
  "event.category": "iam",
  "principal.id_hash": "h_alice_1e02...",
  "mcp.authz.change.type": "revoked",
  "mcp.authz.change.source": "policy_engine",
  "mcp.authz.change.detected_at": "2026-09-12T14:30:00.000Z",
  "mcp.authz.change.timing_confidence": "detected_only"
}
```
No `effective_at` is present, and `timing_confidence: "detected_only"` tells any consumer that
the real revocation could have happened at any point before `detected_at` — it must not be
treated as the precise revocation time.

## 9. `mcp.subscription.close`

Emitted when a subscription's stream ends, by any of the three (or four, including a
server-forced closure on detected authorization change) paths in Block 1 §7.

```json
{
  "timestamp": "2026-09-12T14:45:00.000Z",
  "event.name": "mcp.subscription.close",
  "event.category": "session",
  "event.outcome": "success",
  "mcp.subscription.id": "42",
  "principal.id_hash": "h_alice_1e02...",
  "mcp.subscription.state": "closed_abrupt",
  "mcp.subscription.close.reason": "transport_drop"
}
```

## 10. `mcp.response`

Emitted when the server sends the JSON-RPC response (or, for `subscriptions/listen`, the
graceful-closure result) correlated by `jsonrpc.request.id` back to the originating
`mcp.request.received`/`mcp.request.validation` pair.

```json
{
  "timestamp": "2026-09-12T14:02:01.150Z",
  "event.name": "mcp.response",
  "event.category": "network",
  "event.outcome": "failure",
  "jsonrpc.request.id": "9",
  "rpc.status_code": "-32602",
  "error.type": "InvalidParams",
  "http.response.status_code": 400
}
```
