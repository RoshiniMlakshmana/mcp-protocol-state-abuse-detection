# Field Provenance Mapping

This document exists to satisfy one explicit Block 2 constraint: **do not invent fields and
pretend they are standard OpenTelemetry attributes.** Every field in `telemetry/schema.md` is
placed in exactly one of three buckets below. Sourcing was verified against primary
specifications on 2026-09-12 (see citations); nothing here is asserted from memory alone.

## Bucket 1 — Standard / externally defined

Fields whose **name** (and, where noted, controlled vocabulary) is defined by an external
standard this project did not invent: OpenTelemetry semantic conventions, W3C standards, or
Elastic Common Schema (ECS, reused for SIEM/Sigma familiarity — ECS is not an MCP or OTel
standard, but it is external to this project and widely deployed).

| Field | Standard | Citation | Notes |
|---|---|---|---|
| `rpc.system.name` | OTel RPC semantic conventions | `open-telemetry/semantic-conventions` `docs/rpc/rpc-spans.md` | Required attribute; value fixed to `"jsonrpc"` |
| `rpc.method` | OTel JSON-RPC semantic conventions | `docs/rpc/json-rpc.md` | Upstream requirement level is "Opt-In"; this project treats it as Required for audit purposes — that elevation is our choice, not the standard's |
| `jsonrpc.request.id` | OTel JSON-RPC semantic conventions | `docs/rpc/json-rpc.md` | "Recommended"; string form of the JSON-RPC `id` |
| `jsonrpc.protocol.version` | OTel JSON-RPC semantic conventions | `docs/rpc/json-rpc.md` | Maps to the JSON-RPC envelope's `"jsonrpc"` field, not MCP's own protocol version |
| `rpc.status_code` | OTel JSON-RPC semantic conventions | `docs/rpc/json-rpc.md` | Value is the JSON-RPC `error.code`, carried as a string |
| `error.type` | OTel general error semantic conventions | referenced from both RPC and HTTP semconv pages | Generic error classification |
| `http.request.method` | OTel HTTP semantic conventions | `docs/http/http-spans.md` | Stable (2023+) naming, not the older `http.method` |
| `http.response.status_code` | OTel HTTP semantic conventions | `docs/http/http-spans.md` | Stable naming, not the older `http.status_code` |
| `http.route` | OTel HTTP semantic conventions | `docs/http/http-spans.md` | |
| `gen_ai.usage.input_tokens` | OTel GenAI semantic conventions | `open-telemetry/semantic-conventions-genai` `docs/gen-ai/gen-ai-spans.md` | **Stability: Development** (not yet stable) — flagged explicitly per Block 2's "verify every field category" instruction |
| `gen_ai.usage.output_tokens` | OTel GenAI semantic conventions | same as above | **Stability: Development** |
| `trace_id` | OTel (non-OTLP log-record compatibility naming) | `opentelemetry.io/docs/specs/otel/compatibility/logging_trace_context` | Lowercase hex, snake_case — **not** `trace.id` (that dotted form is ECS's naming, a different standard; do not mix the two spellings in one pipeline) |
| `span_id` | OTel (same source as `trace_id`) | same | Same caveat as `trace_id` |
| `traceparent` / `tracestate` / `baggage` (carried in MCP `_meta`, not a schema.md field name itself — see note) | W3C Trace Context / W3C Baggage, explicitly permitted on the MCP wire by SEP-414 | `github.com/modelcontextprotocol/modelcontextprotocol` PR #414 | MCP reserves these three un-prefixed `_meta` keys specifically so OTel SDKs can propagate trace context through MCP messages; propagation is optional, not mandated, by MCP |
| `event.name` (field name and general "classifies this record as an event" concept) | OTel Logs Data Model, top-level `EventName` field | `opentelemetry.io/docs/specs/otel/logs/data-model` | The **concept** is OTel-grounded; the **ten values** this project assigns to it (`mcp.request.received`, etc.) are project-defined — see Bucket 3 |
| `event.category` (field name + the specific values `network`/`iam`/`session`/`process` reused here) | ECS categorization fields | Elastic Common Schema reference, `event.category` allowed values | ECS does not define MCP-specific categories; this project picked the closest existing ECS values, which is a best-fit mapping, not a claim that ECS models MCP |
| `event.outcome` (field name + its 3-value enum) | ECS categorization fields | ECS reference, `event.outcome` allowed values (`success`/`failure`/`unknown`) | Full reuse, including the enum, because it fits without modification |

**Field the original Block 2 prompt suggested but which does not exist as stated:**
`rpc.response.status_code` is not a defined OTel attribute for RPC/JSON-RPC. The verified
standard name is `rpc.status_code` (application layer) — kept distinct here from
`http.response.status_code` (transport layer), since an MCP `HeaderMismatch` produces both at
once but they are not interchangeable.

## Bucket 2 — MCP wire values

Fields whose **value** genuinely appears on the MCP wire (an HTTP header, a JSON-RPC body
field, or a `_meta` key) per the current MCP core specification (`2026-07-28`) or the Tasks
extension (SEP-2663) — verified in Block 1 and re-confirmed for this block — but which are not
themselves OpenTelemetry- or ECS-standardized attribute names.

| Field | MCP source | Verified in |
|---|---|---|
| `mcp.protocol.version` | `MCP-Protocol-Version` HTTP header / `_meta."io.modelcontextprotocol/protocolVersion"` | Block 1, `basic/transports/streamable-http` |
| `mcp.header.method` | `Mcp-Method` HTTP header (SEP-2243) | Block 1 §6, threat-model.md |
| `mcp.body.method` | JSON-RPC `method` field | Core JSON-RPC 2.0 / MCP spec |
| `mcp.header.name_hash` (pre-hash raw value: `Mcp-Name` header) | `Mcp-Name` HTTP header (SEP-2243), mirroring `params.name`/`params.uri`, or (per SEP-2663) `params.taskId` | Block 1 §6 |
| `mcp.body.identity_hash` (pre-hash raw value: `params.name`/`params.uri`/`params.taskId`) | JSON-RPC body `params` | Block 1 §6 |
| `mcp.task.state` | SEP-2663 `TaskStatus` enum (`working`/`input_required`/`completed`/`failed`/`cancelled`) | Block 1 §6, verbatim from SEP-2663 |
| `mcp.subscription.id` | `_meta."io.modelcontextprotocol/subscriptionId"`, defined as the `subscriptions/listen` request's own JSON-RPC `id` | Block 1 §7, `basic/patterns/subscriptions` |
| `mcp.subscription.filter_types` | The `notifications` filter object's boolean fields on `subscriptions/listen`/its acknowledgment | Block 1 §7 |
| `mcp.subscription.notification_type` | The `method` field of the delivered notification (e.g. `notifications/resources/updated`, `notifications/tasks`) | Block 1 §7, §6 |

## Bucket 3 — Project-defined security audit fields

Fields invented for this audit contract because Block 1 identified real gaps the MCP wire does
not fill (no owner field, no authorization-changed event, no distinguishable
not-found-vs-unauthorized signal). **These must never be cited in later blocks as MCP or
OpenTelemetry standard fields.**

| Field | Why it had to be invented |
|---|---|
| `event.name` values (`mcp.request.received`, `mcp.request.validation`, `mcp.task.authorization`, `mcp.task.state`, `mcp.subscription.open`, `mcp.subscription.acknowledged`, `mcp.subscription.notification`, `mcp.subscription.authorization_change`, `mcp.subscription.close`, `mcp.response`) | MCP has no audit-event taxonomy at all; these ten names are this project's vocabulary only |
| `mcp.validation.method.result`, `mcp.validation.name.result`, `mcp.validation.result`, `mcp.validation.reason` | The spec's own `HeaderMismatch` error conflates "missing" and "conflicting" into one wire-level error code (Block 1); Track 1 needs the finer taxonomy the wire doesn't give us |
| `principal.id_hash`, `principal.authenticated`, `principal.auth_method` | MCP has no identity object; whatever "the caller" means is resolved by the server's own OAuth integration, not the protocol |
| `mcp.task.id_hash` | Pseudonymized form of the wire-visible `taskId` — the hashing itself is project policy |
| `mcp.task.authz_context_id_hash` | Corresponds to a concept ("who owns this task") that Block 1 §5 established has **no protocol-level field at all** — entirely a server-side/audit-pipeline construct. **Patch correction:** absence/`null` means *insufficient authorization-binding visibility*, not evidence of anything; it must never independently produce a Track 2 verdict, only reduce confidence or make a record unevaluable (`telemetry/schema.md`, `telemetry/correlation.md`) |
| `mcp.validation.source` (patch addition) | Distinguishes the MCP server's own spec-mandated equality check (higher trust) from a collector's independently-recomputed hash comparison (lower trust, vulnerable to canonicalization edge cases) — no external standard defines this distinction |
| `mcp.authz.valid_until` (patch addition) | Lets Track 3 correlate against silent token expiry without requiring a push-based revocation feed — MCP has no expiry-tracking concept and most authorization servers don't push revocation events at all |
| `mcp.authz.change.timing_confidence` (patch addition) | Makes explicit, in the data itself, whether a Track 3 finding's timing is authoritative (`effective_at` known) or only an observation lag (`detected_at` only) — prevents `detected_at` from being silently treated as the true revocation time |
| `security.hash.key_id`, `security.hash.algorithm` (patch addition) | Neither OTel nor ECS defines a field for "which pseudonymization key/algorithm produced this hash" — required so correlation logic can detect key rotation boundaries instead of silently joining incomparable hashes |
| `mcp.task.operation` | A naming convenience over the JSON-RPC method, at the semantic level Track 2 reasons about |
| `mcp.authz.decision`, `mcp.authz.allowed`, `mcp.authz.reason`, `mcp.authz.policy_version` | Exist specifically so Track 2 does not have to infer cross-principal abuse from the ambiguous `-32602` response (Block 1 §10) — SEP-2663 requires the *check*, not any particular *telemetry* about it |
| `mcp.task.previous_state` | Not observable from any single MCP message; the wire only ever shows current status (Block 1 §6) |
| `mcp.output.schema_valid`, `mcp.output.bytes`, `mcp.output.item_count` | Enrichment-only fields the Block 2 brief asked for; no MCP or OTel standard covers "is this tool output schema-valid" |
| `mcp.subscription.state` | MCP names the acknowledgment message and the closure mechanics, but never names the lifecycle as an enumerable state machine (Block 1 §7) |
| `mcp.subscription.id_hash`, `mcp.subscription.filter_hash` | Pseudonymized derivatives of wire values, invented for privacy policy, not present as such on the wire |
| `mcp.subscription.notification.resource_uri_hash` | Pseudonymized derivative of the notification's `uri` field |
| `mcp.subscription.notification.contains_inline_result` | Exists specifically to let a later block **test**, rather than assume, the unvalidated Block 1 §11/§17 hypothesis about `notifications/tasks` inlining results |
| `mcp.authz.grant_snapshot_hash`, `mcp.authz.grant_expiry` | Track 3 has no MCP-side representation of "what authorization justified this subscription" — this is entirely an audit-pipeline construct fed by the server's own token/grant state |
| `mcp.authz.change.type`, `mcp.authz.change.source`, `mcp.authz.change.detected_at`, `mcp.authz.change.effective_at` | MCP defines **no authorization-changed event whatsoever** (Block 1 §16, confirmed again in the Block 1 patch) — this is the single largest invented surface in this schema, built entirely from external (authorization-server/policy-engine) signals |
| `mcp.subscription.close.reason` | MCP describes closure *paths* (client/server/transport) but does not name them as an enum, and has no value at all for "server closed this because it detected a stale authorization" |
| `mcp.transport` | Needed to explain why `mcp.header.*` fields are legitimately absent on stdio, without that absence being mistaken for a Track 1 violation |

## Summary table

| Bucket | Field count in `telemetry/schema.md` | Representative examples |
|---|---|---|
| 1. Standard/external (OTel/W3C/ECS) | 15 | `rpc.method`, `jsonrpc.request.id`, `http.response.status_code`, `gen_ai.usage.*`, `trace_id`, `event.outcome` |
| 2. MCP wire values | 9 | `mcp.protocol.version`, `mcp.header.method`, `mcp.task.state`, `mcp.subscription.id` |
| 3. Project-defined | ~29 (patched) | `mcp.authz.decision`, `mcp.task.authz_context_id_hash`, `mcp.subscription.authorization_change.*`, `mcp.validation.*`, `security.hash.key_id`/`algorithm` |
