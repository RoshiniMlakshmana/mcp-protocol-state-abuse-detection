# MCP Security Audit Telemetry — Field Schema

Block 2 deliverable. Builds on the locked Block 1 threat model (`docs/threat-model.md`,
`docs/state-invariants.md`) — no detection tracks are added, removed, or redefined here.

**How to read the "Source" column:** every field is tagged as one of:
- **OTel** — an OpenTelemetry semantic-convention attribute, verified against
  `open-telemetry/semantic-conventions` (RPC/HTTP/general) or
  `open-telemetry/semantic-conventions-genai` (GenAI) on 2026-09-12. Stability status is noted
  where the convention itself is marked non-stable.
- **ECS** — an Elastic Common Schema field/allowed-value reused for its name and, where noted,
  its controlled vocabulary. ECS is not an MCP or OTel standard; it is reused here because Sigma
  and most SIEM ingest pipelines already understand it.
- **W3C** — a W3C standard (Trace Context, Baggage) that MCP explicitly permits propagating via
  reserved `_meta` keys per SEP-414.
- **MCP wire** — a value that genuinely appears on the MCP wire (a header, a JSON-RPC body
  field, a `_meta` key) per the `2026-07-28` core spec or SEP-2663, but is not itself an
  OTel/ECS-standardized attribute name.
- **Project-defined** — invented for this audit contract. Never represented elsewhere as
  "standard." See `telemetry/field-mapping.md` for the full three-way split.

No field in this document is asserted to be a verified standard without a citation trail back
to §17/§18 of `docs/threat-model.md` or the sources listed in `telemetry/field-mapping.md`.

---

## 1. Envelope fields (present on every event, unless noted)

| Field | Type | Req/Opt | Event types | Source | Security purpose | Privacy considerations |
|---|---|---|---|---|---|---|
| `timestamp` | string (RFC3339 UTC) | Required | all | OTel (`LogRecord.Timestamp` concept) / ECS `@timestamp` | Orders every correlation and grace-period computation in Tracks 1–3 | None |
| `event.name` | string | Required | all | Hybrid — grounded in OTel Logs Data Model's top-level `EventName` field concept; **the ten `mcp.*` values themselves are project-defined**, not an OTel- or ECS-standard vocabulary | Identifies which of the 10 audit event types this record is | None |
| `event.category` | string | Required | all | ECS field name + ECS controlled vocabulary, reused as the closest available fit (`network`, `iam`, `session`, `process`) — ECS does not define native MCP semantics, so this is a best-fit mapping, not a claim of ECS coverage | Coarse SIEM/Sigma triage grouping | None |
| `event.outcome` | enum: `success`\|`failure`\|`unknown` | Required where evaluable; omit on purely observational events (`mcp.request.received`, `mcp.task.state`, `mcp.subscription.open`, `mcp.subscription.notification`) | validation/authorization/response/close events | ECS field + ECS's own 3-value enum (reused verbatim) | Quick allow/deny/error triage | None |
| `mcp.protocol.version` | string | Required | all | MCP wire (`MCP-Protocol-Version` header, mirrored in `_meta.io.modelcontextprotocol/protocolVersion`) | Gates Track 1's missing-vs-conflicting-header logic (§9, threat-model.md) — headers are only mandatory under versions that define them | None |
| `mcp.transport` | enum: `streamable-http`\|`stdio` | Required | all | Project-defined | `Mcp-Method`/`Mcp-Name` headers are an HTTP-transport concept; stdio has no headers to compare, which must not be mistaken for a Track 1 violation | None |
| `trace_id` | string (32 lowercase hex) | Optional (recommended) | all | OTel (non-OTLP log-record compatibility field, exact name per `compatibility/logging_trace_context`) | Ties audit events to a W3C trace when the client propagates `traceparent` via MCP's `_meta` (SEP-414); without client propagation this is only as good as the server's own span | Trace IDs are not identity-bearing by design; safe to log as-is |
| `span_id` | string (16 lowercase hex) | Optional (recommended) | all | OTel (same source as `trace_id`) | Same as above, at span granularity | Same as above |
| `security.hash.key_id` | string (opaque key identifier, not the key itself) | Required whenever any `*_hash` field is present on the event (patch addition) | all events carrying `*_hash` fields | Project-defined | Identifies *which* HMAC key/pepper produced the event's hashed fields, without revealing the key — the mechanism for scoping correlation to a single key epoch (§6) | Must be an opaque label/version number, never the key or any value derived from it |
| `security.hash.algorithm` | string (e.g. `"HMAC-SHA-256-16B"`) | Required whenever any `*_hash` field is present on the event (patch addition) | all events carrying `*_hash` fields | Project-defined | Documents the exact hash function + output truncation used, so a later query knows how to interpret/compare hash values and can detect a scheme change even within the same `key_id` | None |

## 2. Track 1 fields — Task Routing Desynchronization

| Field | Type | Req/Opt | Event types | Source | Security purpose | Privacy considerations |
|---|---|---|---|---|---|---|
| `rpc.system.name` | string, constant `"jsonrpc"` | Required | `mcp.request.received` | OTel (`rpc.system.name`, RPC semconv, Required) | Fixes the RPC framework for cross-system correlation (a server may also front gRPC/etc.) | None |
| `rpc.method` | string | Required | `mcp.request.received`, `mcp.response` | OTel (`rpc.method`, JSON-RPC semconv — "Opt-In" level upstream; we make it Required for audit purposes) | Body-side method name for Track 1 comparison | Method names are generally low-sensitivity, but see `mcp.body.method` note below |
| `mcp.body.method` | string | Required | `mcp.request.received`, `mcp.request.validation` | MCP wire (JSON-RPC `method` field) | Explicit, audit-pipeline-owned capture of the same value as `rpc.method`, kept because `rpc.method` is only "Opt-In" upstream and general-purpose RPC instrumentation may suppress it | Same as `rpc.method` |
| `jsonrpc.request.id` | string | Required | `mcp.request.received`, `mcp.request.validation`, `mcp.response` | OTel (`jsonrpc.request.id`, JSON-RPC semconv, Recommended — string form of the body `id`) | Primary Track 1 join key: ties the received request, its validation verdict, and its response into one unit | Request IDs are client-chosen/opaque; not identity-bearing on their own |
| `jsonrpc.protocol.version` | string | Optional | `mcp.request.received` | OTel (`jsonrpc.protocol.version`, JSON-RPC semconv) | The JSON-RPC envelope version (body `"jsonrpc"`, normally `"2.0"`) — **not** the same concept as `mcp.protocol.version`; do not conflate | None |
| `mcp.header.method` | string or null | Required when `mcp.transport = streamable-http` and `mcp.protocol.version` mandates the header; null/absent otherwise | `mcp.request.received`, `mcp.request.validation` | MCP wire (`Mcp-Method` HTTP header, SEP-2243) | Header-side method value; the other half of the Track 1 comparison | None (method names) |
| `mcp.header.name_hash` | string (hash) or null | Required when `Mcp-Name` is applicable to `mcp.body.method` (tools/call, resources/read, prompts/get, tasks/get, tasks/update, tasks/cancel) and present; null when absent | `mcp.request.received`, `mcp.request.validation` | Project-defined (pseudonymized capture of `Mcp-Name`, decoded from the Base64 sentinel form first if used) | Header-side identity value for comparison, without persisting raw tool names/URIs/task IDs verbatim | Hashed per §5 hashing guidance below; raw value never stored by default |
| `mcp.body.identity_hash` | string (hash) or null | Required whenever `mcp.header.name_hash` is required | `mcp.request.received`, `mcp.request.validation` | Project-defined (pseudonymized capture of `params.name` / `params.uri` / `params.taskId`) | Body-side identity value; **must use the identical hash function/salt as `mcp.header.name_hash`** so the two can be compared for equality without ever decoding either back to plaintext | Same hashing guidance |
| `mcp.validation.method.result` | enum: `match`\|`conflict`\|`missing`\|`malformed`\|`version_incompatible` | Required | `mcp.request.validation` | Project-defined | Direct answer to "did `Mcp-Method` agree with the body method?" | None |
| `mcp.validation.name.result` | enum: `match`\|`conflict`\|`missing`\|`malformed`\|`version_incompatible`\|`not_applicable` | Required | `mcp.request.validation` | Project-defined | Direct answer to "did `Mcp-Name` agree with `params.taskId`/`params.name`/`params.uri`?"; `not_applicable` when the method has no identity field to mirror | None |
| `mcp.validation.result` | enum: `valid`\|`invalid` | Required | `mcp.request.validation` | Project-defined roll-up of the two fields above | Single boolean-like field for fast SIEM filtering | None |
| `mcp.validation.source` | enum: `server_native`\|`collector_derived` | Required (patch addition) | `mcp.request.validation` | Project-defined | States whether `mcp.validation.*.result` came from the MCP server's own plaintext header/body equality check (which the `2026-07-28` spec already requires it to perform for `HeaderMismatch`) or was independently recomputed by a collector comparing `mcp.header.name_hash`/`mcp.body.identity_hash`. **`server_native` is the preferred, higher-trust source** — it has plaintext access and is the spec-mandated check itself. `collector_derived` is a weaker, supplementary signal: it can diverge from the server's own verdict on canonicalization edge cases (e.g., Base64-sentinel decoding, case handling) that a hash-equality comparison cannot see through. Prefer `server_native` whenever the server exposes its own validation outcome; fall back to `collector_derived` only when it does not | None |
| `mcp.validation.reason` | string | Optional | `mcp.request.validation` | Project-defined free-text | Human-readable detail (e.g., which values conflicted) for triage | Should not embed raw task IDs/resource URIs — reference the hash fields instead |
| `error.type` | string | Optional (present on failed validation/requests) | `mcp.request.validation`, `mcp.response` | OTel (general error semconv, e.g. `"HeaderMismatch"`) | Standard error classification | None |
| `rpc.status_code` | string | Optional (present when the response is a JSON-RPC error) | `mcp.response` | OTel (`rpc.status_code`, JSON-RPC semconv — value is the body `error.code` as a string, e.g. `"-32020"`) | JSON-RPC application-layer status, distinct from HTTP status | None |
| `http.response.status_code` | int | Required on `mcp.response` when `mcp.transport = streamable-http` | `mcp.response` | OTel (HTTP semconv, Conditionally Required) | Transport-layer status (e.g., `400` for `HeaderMismatch`) | None |
| `http.request.method` | string | Optional | `mcp.request.received` | OTel (HTTP semconv) | Always `"POST"` for Streamable HTTP; kept for completeness/cross-checking | None |
| `http.route` | string | Optional | `mcp.request.received` | OTel (HTTP semconv) | The MCP endpoint path | Low sensitivity |

## 3. Track 2 fields — Cross-Principal Task Authorization Violation

| Field | Type | Req/Opt | Event types | Source | Security purpose | Privacy considerations |
|---|---|---|---|---|---|---|
| `principal.id_hash` | string (hash) | Required | `mcp.task.authorization`, `mcp.subscription.open`, `mcp.subscription.authorization_change` | Project-defined. Nearest OTel analogue is the deprecated `enduser.pseudo.id` / current `user.hash` — this project uses its own field to (a) stay stable across OTel's evolving user-identity naming and (b) cover non-human/agent callers that `user.*` doesn't cleanly describe | Identifies "who is asking" without persisting the raw subject/client_id | Hashed per §5; never derived from the raw bearer token itself (see §5) |
| `principal.authenticated` | boolean | Required | `mcp.task.authorization`, `mcp.subscription.open` | Project-defined | Distinguishes an authenticated-but-unauthorized principal from an unauthenticated caller | None |
| `principal.auth_method` | string | Optional | `mcp.task.authorization`, `mcp.subscription.open` | Project-defined (e.g., `"oauth2_bearer"`) | Context for the authorization decision | None |
| `mcp.task.id_hash` | string (hash) | Required | `mcp.task.authorization`, `mcp.task.state` | Project-defined (same hash function/salt as `mcp.body.identity_hash` when the identity being hashed is a `taskId` — they are the same underlying value and **should** produce the same hash for correlation) | Primary Track 2 join key across principals and over time for the same task | Hashed per §5 |
| `mcp.task.authz_context_id_hash` | string (hash) or null | Required-if-available | `mcp.task.authorization` | Project-defined — represents the server-side "authorization context" a task is bound to, a concept Block 1 §5 establishes has **no protocol-level field**; this is purely an audit-pipeline construct fed by the server's own bespoke binding | Enables "is `principal.id_hash` the same as (or explicitly granted against) the context this task is bound to?" **Corrected semantics (patch):** `null`/absent means *insufficient authorization-binding visibility* — the server could not or did not expose a binding — and by itself is **not** evidence of anything. It MUST NOT be treated as suspicious and MUST NOT independently produce a Track 2 finding. Its only effect is to lower confidence, or make a given `mcp.task.authorization` record unevaluable for Track 2, until corroborated by `mcp.authz.decision`/`mcp.authz.reason` (see `telemetry/correlation.md`) | Hashed per §5 when present |
| `mcp.task.operation` | enum: `create`\|`get`\|`update`\|`cancel` | Required | `mcp.task.authorization` | Project-defined (named at the task-operation level; corresponds to `tasks/get`/`tasks/update`/`tasks/cancel`, or task creation via an augmented request) | Which operation was attempted against the task | None |
| `mcp.authz.decision` | enum: `allow`\|`deny` | Required | `mcp.task.authorization` | Project-defined | The server's authorization decision itself — required so Track 2 does not have to be inferred from `-32602` (Block 1 §10) | None |
| `mcp.authz.allowed` | boolean | Required | `mcp.task.authorization` | Project-defined (boolean mirror of `mcp.authz.decision`, kept because it was explicitly requested and is convenient for SIEM boolean filters) | Same as above | None |
| `mcp.authz.reason` | enum: `authorized_owner`\|`authorized_grant`\|`principal_mismatch`\|`insufficient_scope`\|`context_unbound`\|`policy_denied`\|`unknown` | Required | `mcp.task.authorization` | Project-defined | Distinguishes a legitimate shared-access grant (`authorized_grant`) from a genuine violation (`principal_mismatch`), and flags when a server has no binding to reason about (`context_unbound`) | None |
| `mcp.authz.policy_version` | string | Optional (only if the server's authorization system exposes one) | `mcp.task.authorization` | Project-defined | Lets later blocks correlate a spike in denials/allows with a policy change | None |

## 4. Task lifecycle fields (supporting context — never a primary signal)

| Field | Type | Req/Opt | Event types | Source | Security purpose | Privacy considerations |
|---|---|---|---|---|---|---|
| `mcp.task.state` | enum: `working`\|`input_required`\|`completed`\|`failed`\|`cancelled` | Required | `mcp.task.state` | MCP wire (SEP-2663 `TaskStatus` enum, verbatim) | Lifecycle context for Track 2's terminal-state-finality invariant (state-invariants.md row 7) | None |
| `mcp.task.previous_state` | enum, same values, or null | Optional | `mcp.task.state` | Project-defined — **not** observable on the wire; MCP carries only current status (Block 1 §6), so this is computed by the audit pipeline's own state tracking, not read from any single request | Detects illegal transitions (e.g., mutation after a terminal state) | None |
| `mcp.output.schema_valid` | boolean | Optional | `mcp.task.state` (on `completed`) | Project-defined | Enrichment only — **must never by itself produce a Track 1/2/3 verdict** (Block 1 §1, §8) | None |
| `mcp.output.bytes` | int | Optional | `mcp.task.state` (on `completed`) | Project-defined | Enrichment only, same constraint | None |
| `mcp.output.item_count` | int | Optional | `mcp.task.state` (on `completed`) | Project-defined | Enrichment only, same constraint | None |
| `gen_ai.usage.input_tokens` | int | Optional | `mcp.task.state` (on `completed`) | OTel (GenAI semconv — status **Development**, not yet stable; verified 2026-09-12) | Enrichment only, same constraint | Never accompanied by prompt/completion text — counts only |
| `gen_ai.usage.output_tokens` | int | Optional | `mcp.task.state` (on `completed`) | OTel (GenAI semconv — status **Development**) | Enrichment only, same constraint | Counts only |

**Explicit non-negotiable, per Block 1 and the Block 2 brief:** a large value in any of the five
enrichment fields above, alone, MUST NOT set `event.outcome = failure` or otherwise imply a
Track 1/2/3 violation. They may only ever be joined to an *already-detected* Track 1/2/3 finding
as context.

## 5. Track 3 fields — Long-Lived Subscription Authorization Drift

| Field | Type | Req/Opt | Event types | Source | Security purpose | Privacy considerations |
|---|---|---|---|---|---|---|
| `mcp.subscription.id` | string (JSON-RPC id of the `subscriptions/listen` request) | Required | `mcp.subscription.open`, `.acknowledged`, `.notification`, `.authorization_change`, `.close` | MCP wire (`_meta.io.modelcontextprotocol/subscriptionId`, which the spec defines as literally the `listen` request's JSON-RPC `id`) | Primary Track 3 join key across the open/ack/notification/close sequence | This is a per-connection sequence-like value, not itself identity-bearing; logged in clear unless a deployment's IDs are predictable/reused across principals (see `mcp.subscription.id_hash`) |
| `mcp.subscription.id_hash` | string (hash) | Optional | same as above | Project-defined | For deployments where `mcp.subscription.id` values are reused or otherwise correlatable across principals in a way that would leak information if shared outside the owning system | Hashed per §5 |
| `mcp.subscription.filter_types` | object of booleans (`toolsListChanged`, `promptsListChanged`, `resourcesListChanged`) | Optional | `mcp.subscription.open`, `.acknowledged` | MCP wire (booleans from the `notifications` filter — non-sensitive, no URIs/IDs) | Confirms the acknowledged scope for invariant #9 (state-invariants.md) | None — booleans only |
| `mcp.subscription.filter_hash` | array of hashes | Optional | `mcp.subscription.open`, `.acknowledged` | Project-defined (pseudonymized `resourceSubscriptions`/`taskIds` array entries from the filter) | Same purpose as above for the identity-bearing parts of the filter | Hashed per §5 — these arrays can contain resource URIs and task IDs, which are exactly the values §5 requires pseudonymizing |
| `mcp.subscription.state` | enum: `requested`\|`acknowledged`\|`active`\|`closed_graceful`\|`closed_abrupt` | Required | `mcp.subscription.open`, `.acknowledged`, `.notification`, `.close` | Project-defined vocabulary for the lifecycle Block 1 §7 describes — MCP itself names the acknowledgment message and the closure paths but does not name these as enum values | Lets a query ask "was this subscription still active at time T?" | None |
| `mcp.subscription.notification_type` | string (JSON-RPC `method` of the delivered notification) | Required | `mcp.subscription.notification` | MCP wire (e.g. `notifications/resources/updated`, `notifications/tools/list_changed`, `notifications/tasks`) | Confirms the notification type stayed within the acknowledged filter (invariant #9) | None |
| `mcp.subscription.notification.resource_uri_hash` | string (hash) or null | Optional | `mcp.subscription.notification` | Project-defined | Correlates a specific resource's drifted-delivery events without logging the URI in clear | Hashed per §5 |
| `mcp.subscription.notification.contains_inline_result` | boolean | Required when `notification_type = notifications/tasks`; otherwise omitted | `mcp.subscription.notification` | Project-defined | Lets later blocks **empirically test**, rather than assume, the unvalidated Block 1 §11/§17 hypothesis that a drifted `notifications/tasks` delivery can leak inline result content | Deliberately does not capture the result content itself — presence/absence only |
| `mcp.authz.grant_snapshot_hash` | string (hash) | Required | `mcp.subscription.open` | Project-defined (a fingerprint of the token/grant valid at open time — e.g., a hash of `jti` + scope set + expiry, never the raw token) | Baseline for detecting later drift: what authorization state justified this subscription | Hashed per §5; never the raw token (see §5) |
| `mcp.authz.grant_expiry` | string (RFC3339) or null | Optional | `mcp.subscription.open` | Project-defined (the token's `exp` claim *as observed at open time*, if present) | A point-in-time snapshot of the originally-presented token's expiry — historical record of what was known when the subscription opened | None (a timestamp, not identity-bearing) |
| `mcp.authz.valid_until` | string (RFC3339) or null | Optional, but Required-if-derivable (patch addition) | `mcp.subscription.open`, `mcp.subscription.authorization_change` | Project-defined | The pipeline's **current** best-known point after which the authorization backing a subscription is no longer valid by expiry alone, independent of any explicit revocation signal. Unlike `mcp.authz.grant_expiry` (a fixed snapshot from open time), this MAY be updated by a later `mcp.subscription.authorization_change` (e.g., a scope downgrade that shortens validity, or a renewal that extends it). This is what makes expiry-based Track 3 correlation possible **even when no push-based revocation feed exists** — see `telemetry/correlation.md` | None |
| `mcp.authz.change.type` | enum: `revoked`\|`expired`\|`scope_downgraded`\|`scope_upgraded` | Required | `mcp.subscription.authorization_change` | Project-defined | Classifies the external authorization-state change that Track 3 hinges on | None |
| `mcp.authz.change.source` | enum: `authorization_server_event`\|`policy_engine`\|`manual_admin_action`\|`token_expiry_computed` | Required | `mcp.subscription.authorization_change` | Project-defined | Distinguishes an authoritative external signal from a locally-computed expiry inference — directly informs `timing_confidence` below | None |
| `mcp.authz.change.effective_at` | string (RFC3339) or null | Required-if-available | `mcp.subscription.authorization_change` | Project-defined | **When the authorization change actually became effective**, as reported by the authorization server or policy engine. This is the value Track 3 correlation should compare notification timestamps against **whenever it is present and its `source` is trustworthy** (`authorization_server_event`/`policy_engine`) | None |
| `mcp.authz.change.detected_at` | string (RFC3339) | Required | `mcp.subscription.authorization_change` | Project-defined | **When the MCP telemetry/instrumentation learned about the change** — not when the change actually happened. May lag `effective_at` by an unknown, potentially large amount (e.g., poll-based introspection). Needed for propagation-delay/grace-period math (state-invariants.md row 11) regardless of whether `effective_at` is also known | None |
| `mcp.authz.change.timing_confidence` | enum: `authoritative`\|`detected_only` (patch addition) | Required | `mcp.subscription.authorization_change` | Project-defined | `authoritative` when `effective_at` is present from a trustworthy `source`; `detected_only` when only `detected_at` is known. **Exists so downstream consumers never silently treat `detected_at` as if it were the true revocation time** — a `detected_only` finding carries an explicit, possibly wide blind window between the real change and its observation, and should be reported/scored with that caveat rather than as a precisely-timed violation | None |
| `mcp.subscription.close.reason` | enum: `client_closed`\|`server_graceful`\|`transport_drop`\|`server_forced_authz` | Required | `mcp.subscription.close` | Project-defined (maps to the three closure paths in Block 1 §7, plus a fourth value for a server that closes specifically *because* it detected an authorization change — a well-behaved response this schema should be able to distinguish from silent continuation) | Tells later blocks whether a drift window ever actually closed, and how | None |

---

## 6. Hashing / pseudonymization guidance (applies to every `*_hash` field above)

1. **Never hash the raw bearer token or any authorization/credential material.** Pseudonymized
   identity fields (`principal.id_hash`, `mcp.authz.grant_snapshot_hash`, etc.) are derived from
   *post-verification identity claims* (subject, `client_id`, `jti`, scope set, expiry) — never
   from the token string itself. A hash of a token is still a function of secret material and
   must not be logged even in hashed form.
2. **Use a keyed hash (HMAC-SHA-256), not a bare hash.** Task IDs, resource URIs, and similar
   values often have low-entropy or guessable structure; a bare SHA-256 is dictionary-attackable
   for such inputs. HMAC with a per-deployment secret key ("pepper") closes that gap.
3. **Use one stable key per deployment for the lifetime needed for correlation**, so the same
   underlying task ID, principal, or resource URI always hashes to the same value (required for
   Track 2's cross-principal grouping and Track 3's grant-snapshot comparison). Every event
   carrying a `*_hash` field MUST also carry `security.hash.key_id` and
   `security.hash.algorithm` (patch addition, §1) — **never the key or secret material itself**
   — so that correlation logic can tell which values are safe to compare.
4. **Truncate consistently** (e.g., first 16 bytes / 32 hex characters of the HMAC output) to
   keep records compact; document the truncation length in `security.hash.algorithm` so
   equality comparisons across events remain valid.
5. **The same canonicalization and HMAC scheme must be used for any two values that need to be
   compared for equality** (this is what lets `mcp.header.name_hash` be compared against
   `mcp.body.identity_hash`, or the same `taskId` hashed once in `mcp.body.identity_hash` and
   again in `mcp.task.id_hash`) — decode Base64-sentinel-encoded values to their canonical form
   *before* hashing, exactly as the MCP transport spec requires servers to do before comparing
   raw values (Block 1). Two values hashed under different `security.hash.key_id`s, or with
   different canonicalization, are **not** comparable even if they look superficially similar.
6. **Key rotation changes every pseudonymous value it touches.** Rotating the HMAC key/pepper is
   a legitimate, expected operational event — but it is not free: every hash produced under the
   old key becomes incomparable with hashes produced under the new key, because they are, by
   construction, different values for the same underlying identity. **Historical correlation
   across a key rotation boundary is not automatically valid.** Deployments have two supported
   options, and must pick one explicitly rather than assume continuity:
   - **Controlled overlap:** during a bounded transition window, emit hashes under both the old
     and new `key_id` (e.g., as parallel fields or a short-lived dual-write period) so
     correlation logic can bridge the boundary deliberately.
   - **Explicit epoch scoping:** treat each `key_id` as its own correlation epoch and scope
     Track 2/Track 3 queries to a single epoch at a time (using `security.hash.key_id` as the
     partition key), accepting that a query spanning a rotation will simply not join across it.
   Either way, `security.hash.key_id` is the field that makes the rotation boundary visible and
   queryable, instead of silently and invisibly breaking correlation.
7. **Never store raw values "just in case."** Fields explicitly excluded by design, per the
   Block 2 brief: raw credentials, bearer/authorization tokens, full prompts/completions by
   default, secrets, and complete sensitive task results. `mcp.task.state` records size/validity
   metadata about a completed task's output — never the output itself.
8. **Booleans and enums carrying no identity information are not hashed** (e.g.,
   `mcp.subscription.filter_types`, `mcp.task.state`, `mcp.authz.decision`) — over-hashing
   non-sensitive low-cardinality fields only harms detection usability for no privacy benefit.
