# Threat Model: MCP Protocol-State Abuse — Tasks, Authorization, and Long-Lived Subscription State

**Status:** Block 1 deliverable. Precise state/threat model only — no detection rules, queries, or attack code.

**Document currency:** Verified against primary sources on 2026-09-12. The core protocol
reference is MCP specification revision **2026-07-28** (GA). The Tasks extension reference is
**SEP-2663** ("Tasks Extension", status: Final). Where a claim could not be verified against a
normative document, it is explicitly marked `[UNVERIFIED]` or `[OUR ASSUMPTION]` rather than
stated as fact.

---

## 1. Project Scope

This block builds the state/threat model that later blocks (detection logic, telemetry
mapping, dashboards) will be built on. It covers exactly three detection tracks:

1. **Task routing desynchronization** — disagreement between HTTP routing headers and the
   JSON-RPC body they mirror, for task-related and task-augmentable requests.
2. **Cross-principal task authorization violation** — an authenticated principal operating on
   a task whose authorization context belongs to a different principal.
3. **Long-lived subscription authorization drift** — a `subscriptions/listen` stream that keeps
   delivering protected events after the authorization that justified opening it is no longer
   valid.

Output-schema validity, payload size, item counts, and token usage are **enrichment only** in
this project and must never independently drive a Track 1–3 classification.

Explicitly out of scope for this project (per the fixed 7-block plan): generic MCP firewalling,
prompt-injection detection, AI/LLM-based anomaly scoring, and any redesign of the block plan.

## 2. MCP Versions / Extensions Targeted

| Component | Version / identifier | Status |
|---|---|---|
| Core MCP specification | `2026-07-28` | GA (current at time of writing) |
| Streamable HTTP transport, header-based routing | SEP-2243 (folded into `2026-07-28`) | Active |
| Stateless core / `subscriptions/listen` | SEP-2575 (folded into `2026-07-28`) | Active |
| Multi Round-Trip Requests (MRTR), `resultType` | SEP-2322 (folded into `2026-07-28`) | Active |
| Tasks extension (`io.modelcontextprotocol/tasks`) | SEP-2663 | Final (extension, not core) |

**Important correction to the initial brief's assumptions:** `resources/subscribe` and
`resources/unsubscribe`, and the standalone HTTP GET SSE stream, are **removed** as of
`2026-07-28` and replaced by a single mechanism, `subscriptions/listen`, that also carries
list-changed notifications and (via the Tasks extension) task status notifications
(`notifications/tasks`). Any environment still running protocol version `2025-11-25` or earlier
uses the older `resources/subscribe` model; that is a **different, out-of-scope state machine**
and must not be conflated with `subscriptions/listen` in later blocks. See §13 for the
compatibility implications.

This model deliberately does **not** cover: the deprecated HTTP+SSE transport (`2024-11-05`),
Roots/Sampling/Logging (deprecated under SEP-2577), or the pre-`2025-06-18` session model
(`Mcp-Session-Id`), except where needed to describe legitimate backward-compatibility traffic.

## 3. Assets Being Protected

- **Task result/state confidentiality** — the contents of `CompletedTask`/`FailedTask`
  payloads and `input_required` prompts, which may embed tool outputs, elicitation/sampling
  content, or business data.
- **Task control integrity** — the ability to cancel or update someone else's in-flight work
  (`tasks/cancel`, `tasks/update`).
- **Subscription event confidentiality** — the change/activity metadata carried by
  `notifications/resources/updated` and list-changed notifications (which themselves carry no
  resource contents — see §11), the resource contents a client fetches as a result of acting on
  that signal (via a subsequent `resources/read`), and the task state — potentially including
  inlined result content — carried by `notifications/tasks`, all over a long-lived
  `subscriptions/listen` stream.
- **Routing integrity metadata** — the trustworthiness of `Mcp-Method`/`Mcp-Name` as a basis
  for intermediary decisions (rate limiting, tenant routing, load balancing) that assume
  header and body agree.
- **Authorization-decision correctness over time** — the guarantee that a decision made once
  (at `subscriptions/listen` time, or at task creation time) does not silently outlive the
  grant that produced it.

## 4. Trust Boundaries

1. **Client (host application) ↔ MCP server**, over Streamable HTTP. This is the primary
   boundary for all three tracks. Every JSON-RPC request is an independent HTTP POST; MCP is
   stateless at the protocol level as of `2026-07-28` — there is no `Mcp-Session-Id` and no
   `initialize` handshake. Bearer-token authorization is **per-request input, not connection
   state** (explicit spec language, `server/resources`).
2. **Client/server ↔ intermediary (gateway, load balancer, reverse proxy)**. Intermediaries are
   explicitly permitted by spec to route on `Mcp-Method`/`Mcp-Name` **without parsing the JSON
   body**. This is a trust boundary because an intermediary that trusts headers it has not
   validated against the body (or that talks to a server on an older protocol version that
   doesn't enforce validation) can be steered by a header/body mismatch.
3. **MCP server ↔ authorization server**, OAuth 2.1 resource-server relationship (token
   issuance, revocation, audience binding). The MCP server is the enforcement point; the
   authorization server is the source of truth for grant validity.
4. **MCP server ↔ per-caller task/subscription state store**. Because MCP has no server-level
   session concept post-SEP-2567, whatever binds a task or subscription to "the caller who is
   allowed to touch it" is **entirely a server-side implementation concern**, not something the
   core protocol defines. This is the boundary Track 2 and Track 3 actually live on.

## 5. Principals / Actors

- **Authenticated principal / caller** — the bearer-token holder making a request. MCP does not
  define a canonical "identity" object; the principal is whatever the server's OAuth
  integration resolves the presented access token to (subject, client_id, scope set).
- **Task's authorization context** — the permission state a server bound at task-creation time
  (or bespoke equivalent) to the task. Per SEP-2663, this binding is server-defined:
  *"Servers MUST perform authentication and authorization checks on each task-related request
  to ensure that the client has permission to access a task"* — but the SEP explicitly notes
  *"in many cases, it is not possible to perform this binding, in which case the task ID
  becomes the only line of defense."* There is **no protocol-level "owner" or "creator" field**
  on a `Task` object. Track 2's "Alice owns Task-123" framing is therefore a **server-side
  authorization-context concept we are naming for detection purposes**, not a wire-visible
  attribute — flagged explicitly per the "do not invent MCP requirements" rule.
- **Other authenticated principals** — any other bearer-token holder who can reach the same MCP
  endpoint (e.g., "Bob" in the Track 2 example).
- **MCP server** — resource server and authorization decision point; also the task/subscription
  state owner.
- **Intermediary** — load balancer / gateway that may route on `Mcp-Method`/`Mcp-Name` without
  itself being an authorization decision point (unless explicitly built to be one).
- **Authorization server** — issues/revokes OAuth 2.1 access tokens; canonical source of grant
  validity for Track 3.

## 6. Task Lifecycle / State Model

Using exact current terminology from SEP-2663 (no invented state names):

```
                 (request eligible for task augmentation, e.g. tools/call)
                                     │
                     server decides to return CreateTaskResult
                        (seed Task, typically status="working")
                                     │
                                     ▼
                         ┌────────────────────┐
                  ┌─────▶│      working       │◀─────┐
                  │      └──────────┬─────────┘      │
                  │                 │                 │ tasks/update
      more input  │                 ▼                 │ (inputResponses)
      required    │      ┌────────────────────┐       │
                  └──────│   input_required   │───────┘
                         └──────────┬─────────┘
                                     │
                 ┌───────────────────┼───────────────────┐
                 ▼                   ▼                   ▼
          ┌─────────────┐    ┌─────────────┐     ┌─────────────┐
          │  completed  │    │   failed    │     │  cancelled  │   (terminal states)
          └─────────────┘    └─────────────┘     └─────────────┘
```

- **Instantiation:** a request that is eligible for task augmentation (any request type the
  server chooses, at its own discretion — the client cannot force it) receives a
  `CreateTaskResult` (`resultType: "task"`) instead of its normal result. There is **no
  `"created"` status value** in the `TaskStatus` enum; the initial embedded `Task` is "typically
  (though not necessarily)" seeded at `status: "working"`. The brief's `created → working →
  terminal` phrasing is **not** current spec terminology and is corrected here per the
  instruction to use exact terms.
- **Statuses (exact enum):** `"working" | "input_required" | "completed" | "cancelled" |
  "failed"`. `completed`, `failed`, `cancelled` are terminal.
- **Operations:** `tasks/get` (poll current state), `tasks/update` (client supplies
  `inputResponses` while status is `input_required`), `tasks/cancel` (client requests
  cancellation). There is intentionally **no `tasks/list`** — this is a documented
  cross-caller-enumeration mitigation, not an oversight.
- **Task ID:** server-generated, carried as `params.taskId` on `tasks/get`/`tasks/update`/
  `tasks/cancel`. SEP-2663 explicitly treats it as security-relevant: *"a server MAY use task
  IDs as bearer tokens for a server's stored state. Servers MUST generate them with sufficient
  entropy that a third party cannot enumerate or guess them."*
- **Durability guarantee:** a server **MUST NOT** return `CreateTaskResult` until the task is
  durably created (a `tasks/get` for that `taskId` would resolve).
- **Error codes relevant to task operations:** `-32602` (Invalid params) for an
  invalid/nonexistent `taskId` — **MUST** be returned by `tasks/get`, **SHOULD** be returned by
  `tasks/update`/`tasks/cancel` (this is verbatim SEP-2663 text); `-32021` (Missing Required
  Client Capability) when the calling client hasn't declared the `io.modelcontextprotocol/tasks`
  extension; `-32603` for internal errors. Separately, and independently of those codes,
  SEP-2663's "Auth binding" security implication requires servers to perform an
  authentication/authorization check **on every** task-related request. **Correction from an
  earlier version of this document:** SEP-2663 does **not** state, anywhere, that an
  unauthorized-but-existing `taskId` must (or even should) return `-32602`; that was an
  unsupported inference and has been removed. What is accurate: a server **MAY** choose to
  respond identically for "doesn't exist" and "exists but you're not authorized," and the
  spec's stated rationale for omitting `tasks/list` (avoiding leakage of task existence across
  callers) gives a plausible motive for doing so — but nothing in SEP-2663 mandates it, and an
  implementation is equally free to distinguish the two cases. Because we cannot assume which
  choice a given server made, **Track 2 detection must rely on server-side
  authorization-decision telemetry, not on inferring cross-principal abuse from a JSON-RPC
  error code** (see §10).

## 7. Subscription Lifecycle / State Model

Using exact current terminology from the `2026-07-28` core spec (`basic/patterns/subscriptions`):

```
Client                                              Server
  │  subscriptions/listen (notifications filter)      │
  │ ─────────────────────────────────────────────────▶│
  │                                                     │  (request → not yet a stream)
  │◀───── notifications/subscriptions/acknowledged ────│  = ACTIVE (subscriptionId assigned)
  │        (subscriptionId in _meta, agreed filter)     │
  │                                                     │
  │◀───── notifications/{resources/updated |            │  events delivered on the same
  │        tools/list_changed | ... | tasks} ──────────│  long-lived response stream
  │                    ...                              │
  │                                                     │
  │  [authorization change: token expires/revoked] ─ ─ ─│  ← NOT a protocol-defined
  │                                                     │    transition (see §16)
  │                                                     │
  │  client closes stream / notifications/cancelled   │
  │  OR server graceful-closure result                 │
  │  OR transport drop (timeout/TCP/stdio exit)        │
  │ ═══════════════════════════════════════════════════│  CLOSED / TERMINATED
```

- **Request:** `subscriptions/listen` with a `notifications` filter object:
  `toolsListChanged`, `promptsListChanged`, `resourcesListChanged`,
  `resourceSubscriptions: string[]` (resource URIs), and, via the Tasks extension,
  `taskIds: string[]`.
- **Acknowledged (= entering "active"):** the server **MUST** send
  `notifications/subscriptions/acknowledged` as the first message on that subscription,
  carrying `io.modelcontextprotocol/subscriptionId` (the JSON-RPC `id` of the `listen`
  request) and the subset of the filter it actually agreed to honor. The server **MUST NOT**
  send any notification on the subscription before this acknowledgment.
- **Active:** the response stream stays open; every notification on it (list-changed,
  `notifications/resources/updated`, `notifications/tasks`) carries the same
  `subscriptionId` for demultiplexing. A client may hold multiple concurrent subscriptions.
- **Closed/terminated:** three defined paths — (a) client-initiated (close the SSE stream over
  HTTP, or send `notifications/cancelled` referencing the `listen` request ID on stdio);
  (b) server-initiated graceful closure (server sends a completion `result` — `resultType:
  "complete"` — correlated by the original request `id`, then closes the stream); (c) abrupt
  transport closure (HTTP timeout, TCP disconnect, stdio process exit) — carries no completion
  result and the client may treat it as a signal to reconnect. On stdio, reconnection requires
  re-issuing `subscriptions/listen`; the server holds no subscription state across
  reconnection.

**Gap directly relevant to Track 3 (verified absence, not an oversight we're inventing):** the
`2026-07-28` spec's subscriptions and authorization documents do not define an
"authorization change" transition on this state machine, and do not mandate that a server
re-validate the authorization behind an open `subscriptions/listen` stream before emitting each
notification. The spec's general authorization philosophy ("credentials are per-request input,
not connection state") is stated in the context of ordinary discrete requests
(`resources/list`), and `subscriptions/listen` is architecturally a single very-long-lived
request whose response never gets a fresh per-notification credential to re-check.

This is not only spec silence — it matches the documented architecture of the reference
**Python SDK**. Its authorization model validates the `Authorization` header at request entry
(the request is "stopped at the door" by resource-server middleware if the token is missing or
invalid), and its `subscriptions/listen` handler, once the stream is open, forwards matching
event-bus events onto that request's response stream until the client disconnects — a
design with no re-invocation of token validation per forwarded event. So, for that reference
implementation, **authorization is checked once when the stream is opened and can remain valid
for the lifetime of the stream without a per-event re-check.** The SDK's documentation does not
explicitly narrate this as a security property one way or the other, so this is drawn from how
its request-scoped middleware and event-forwarding path are described (see §18), not from an
explicit "no re-check" statement — but nothing in that documentation describes or implies a
re-check either. This architectural reality, on top of the spec's silence, is the basis for
Track 3 — see §16 (Limitations) for how this is treated, and §11 for the exact scope of what is
and isn't claimed about it.

## 8. Security Invariants

Full table in `docs/state-invariants.md`. Summarized here:

1. `Mcp-Method` header value equals the JSON-RPC `method` field (all requests).
2. `Mcp-Name` header value equals `params.name`/`params.uri` (`tools/call`, `resources/read`,
   `prompts/get`) or `params.taskId` (`tasks/get`, `tasks/update`, `tasks/cancel`).
3. A missing required routing header (legitimately absent only under an older negotiated
   protocol version) is a distinct condition from a present-but-conflicting header value.
4. The authenticated principal on a task-related request is authorized for the referenced
   `taskId`'s authorization context.
5. A `subscriptions/listen` stream's continued delivery of protected events remains consistent
   with the authorization state that justified opening it (or an explicit, documented grace
   period).
6. Notifications delivered on a subscription are limited to what the server acknowledged for
   that `subscriptionId`.
7. Output-schema size, item count, and token usage are never, by themselves, a violation of
   any invariant above.

## 9. Detection Track 1 Threat Scenario — Task Routing Desynchronization

**Normal:** A client sends `tasks/cancel` for `taskId = "T-123"`. Per SEP-2663 + SEP-2243, on
Streamable HTTP it sets `Mcp-Method: tasks/cancel` and `Mcp-Name: T-123`, both mirroring the
JSON-RPC body (`method: "tasks/cancel"`, `params.taskId: "T-123"`). A compliant server validates
header-vs-body equality and proceeds.

**Threat scenario:** A component in the path (a malicious or compromised client, a
misconfigured intermediary that rewrites one side, or a client exploiting an implementation
that under-validates) sends `Mcp-Name: T-123` while `params.taskId` in the JSON body is
`"T-456"` — or sets `Mcp-Method: tasks/get` while the body's `method` is `tasks/cancel`. If the
receiving component makes a decision (routing to the server instance holding `T-123`'s state,
rate-limiting, or a WAF/gateway policy) based on the header alone while a downstream component
acts on the body, the two ends of the pipeline disagree about which task/operation is actually
being performed. The spec's own rationale for requiring header/body equality is exactly to
close "a class of routing/security mismatches" between components with different sources of
truth.

**Distinguishing a real mismatch from a missing-header/compatibility issue (explicitly required
by the brief):** the spec ties header requirement to negotiated protocol version. A server that
supports pre-`2025-06-18` clients **MAY** treat a request with no `MCP-Protocol-Version` header
as version `2025-03-26`, a version that predates `Mcp-Method`/`Mcp-Name` entirely — such a
request has *no header to compare*, which is categorically different from a request that
declares `2026-07-28` (or any version requiring the headers) and supplies a header that
disagrees with the body. Track 1 must key off negotiated protocol version before ever treating
"header absent" as suspicious.

## 10. Detection Track 2 Threat Scenario — Cross-Principal Task Authorization Violation

**Normal:** Alice's client creates a task (e.g., via a long-running `tools/call` that the
server augments into `CreateTaskResult`), receives `taskId = "T-123"`, and the server binds
`T-123` to Alice's authorization context (bespoke, server-side — see §5). Alice's subsequent
`tasks/get`/`tasks/update`/`tasks/cancel` for `T-123`, authenticated as Alice, succeed.

**Threat scenario:** Bob — a different authenticated principal, not Alice, with no server-side
grant over `T-123` — sends a syntactically valid `tasks/get`, `tasks/update`, or `tasks/cancel`
for `taskId = "T-123"`. Every protocol-level field (headers, JSON-RPC shape, `Mcp-Name`
matching `params.taskId`) can be perfectly well-formed; the violation is purely in the
authorization dimension the protocol delegates to the server. This is modeled as an
authorization-state violation, **not** a routing violation (Track 1) — the two are
orthogonal and a request can violate one, the other, both, or neither.

**Do not claim novelty:** cross-principal task-ID access is explicitly anticipated by SEP-2663
itself — it treats task IDs as bearer tokens to server-held state, requires servers to generate
them with sufficient entropy precisely because a leaked or guessed ID functions as a credential,
and mandates an authentication/authorization check on every task-related request. This project
treats Track 2 as **operationalizing an already-known, spec-acknowledged risk class into
detection state modeling**, not discovering it.

**Key constraint for later blocks:** SEP-2663 only normatively specifies `-32602` for an
invalid or nonexistent `taskId`; it is silent on what an unauthorized request against an
*existing* `taskId` should return (see §6 for the correction to this document's earlier,
overstated claim). Because the spec neither requires nor rules out a server collapsing both
cases into the same response, a wire-level observer cannot safely assume the error code
distinguishes "Bob guessed a bad ID" from "Bob hit Alice's real task" — that assumption may be
true for a given server, or it may not. Reliable Track 2 detection therefore requires
**server-side telemetry that records the authorization decision itself** (who the authorization
context says is allowed, who actually asked, and the resulting allow/deny), independent of
whatever error code happened to go out on the wire.

## 11. Detection Track 3 Threat Scenario — Long-Lived Subscription Authorization Drift

**Primary security condition (exact scope):** authorization is valid at the moment
`subscriptions/listen` is opened → that authorization is later revoked or expires → the
subscription remains active (per §7, nothing in the spec or the reference SDK's documented
behavior forces closure) → a notification is delivered on that stream **after** the point of
revocation/expiry. This four-step condition is what Track 3 exists to detect — the paragraphs
below narrow what can and cannot be claimed about the *content* of that notification.

**Normal:** Principal is authorized (valid, unexpired, unrevoked access token with sufficient
scope) → sends `subscriptions/listen` → server validates the token as of that request and
sends `notifications/subscriptions/acknowledged` → subscription is active → server delivers
notifications consistent with that authorization → eventually the client or server closes the
stream per §7.

**Threat/drift scenario:** as above, but afterward the principal's authorization changes —
token expires, is revoked, or the principal's scope/role is reduced by an external policy
system — while the stream remains open. Per §7, the server **may continue emitting**
notifications on that stream after the justifying grant is gone.

**What is actually exposed by a drifted notification — scope correction.** An earlier version
of this document risked implying that a drifted notification necessarily discloses protected
resource *contents*. That is not established, and the verified `2026-07-28` schema points the
other way for ordinary subscriptions:

- `notifications/resources/updated` carries only `{ uri, _meta.subscriptionId }` — a
  change/activity signal, not the resource's contents (§7, `server/resources`). A client that
  acts on it normally issues a follow-up `resources/read`, which is itself a fresh,
  separately-authorized request under the "credentials are per-request input" model (§4) and
  can be independently denied if the server's per-request authorization is otherwise intact.
- List-changed notifications (`notifications/tools/list_changed`, etc.) carry no
  resource-specific payload at all.
- So, for ordinary resource/list subscriptions, the concrete exposure from drift is best stated
  as: **the stale subscriber learns that protected state changed and is prompted to refetch
  it** — a metadata/activity disclosure and a signal, not a content disclosure, unless the
  server's separate `resources/read` authorization is *also* broken.
- `notifications/tasks` (Tasks extension) is a distinct case worth flagging separately: a
  `DetailedTask` notification body *can* inline a terminal result (e.g. a `CompletedTask`'s
  `result` field) directly, which would be a genuine content disclosure rather than a metadata
  signal if delivered post-revocation. **This project has not experimentally validated that
  behavior against a running Tasks-extension implementation.** It should be tracked as a
  separate, higher-severity hypothesis to test in a later block, not assumed as an established
  fact of the current Track 3 model.

This is a state-consistency property between two independent systems (the MCP server's open
stream state, and the authorization server's/policy system's grant state) that the MCP core
specification does not itself reconcile — see §16.

## 12. Normal vs. Suspicious Examples

**Track 1 — normal:**
```
Mcp-Method: tasks/get
Mcp-Name: T-123
{"jsonrpc":"2.0","id":9,"method":"tasks/get","params":{"taskId":"T-123"}}
```

**Track 1 — suspicious (conflicting value, not missing):**
```
Mcp-Method: tasks/get
Mcp-Name: T-123
{"jsonrpc":"2.0","id":9,"method":"tasks/get","params":{"taskId":"T-456"}}
```
Protocol version declared requires the header; header present; value disagrees with body.

**Track 1 — benign/compatibility, not suspicious:**
```
(no MCP-Protocol-Version header; no Mcp-Method; no Mcp-Name)
{"jsonrpc":"2.0","id":1,"method":"initialize", ...}
```
A pre-`2025-06-18` client performing the legacy `initialize` handshake — headers are not part
of that era's contract at all.

**Track 2 — normal:**
`tasks/cancel` for `T-123`, authenticated principal = Alice, server authorization context for
`T-123` = Alice. Allowed.

**Track 2 — suspicious:**
`tasks/cancel` for `T-123`, authenticated principal = Bob, server authorization context for
`T-123` = Alice, no grant naming Bob. Denied by server logic (or, if the server fails to check,
silently succeeds — the worse case this model exists to catch).

**Track 3 — normal:**
`notifications/resources/updated` delivered at `t=00:05` on a subscription opened at `t=00:00`
by a principal whose token is valid through `t=01:00`.

**Track 3 — suspicious:**
`notifications/resources/updated` delivered at `t=00:45` on a subscription opened by a
principal whose token/grant was revoked at `t=00:10`, with no applicable grace-period policy
covering that gap.

## 13. Known Benign / Compatibility Conditions

- **Protocol-version-gated header absence.** Legitimate pre-`2025-06-18` and pre-`2026-07-28`
  clients do not send `Mcp-Method`/`Mcp-Name` at all, or use `Mcp-Session-Id`/`resources/subscribe`
  instead of `subscriptions/listen` — this is normal backward-compatible traffic, not evasion,
  as long as the negotiated protocol version matches.
- **Intermediary/legacy fallback probing.** The spec-sanctioned backward-compatibility flow has
  a client deliberately attempt a modern POST first and fall back to legacy `initialize` /
  HTTP+SSE on specific `400`/`404`/`405` responses. This produces what looks like a
  "malformed" or header-less modern-shaped request that is actually a documented negotiation
  probe, not an attack.
- **Eventually-consistent `tasks/update` acknowledgment.** The spec explicitly allows a server
  to acknowledge `tasks/update` before the task's observable status (via `tasks/get`/
  `notifications/tasks`) reflects the update. A brief window where polled state lags an
  accepted update is normal, not a routing or authorization anomaly.
- **Revocation propagation delay.** Real-world OAuth deployments (token introspection caching,
  distributed revocation lists) have non-zero propagation delay between "token revoked at the
  authorization server" and "MCP server's next check observes revocation." A short, bounded
  delay consistent with the deployment's known introspection/cache TTL is an operational
  reality, not by itself proof of a Track 3 violation.
- **Explicit grace periods.** Some deployments may intentionally allow an active subscription
  to keep delivering non-sensitive event types (e.g., `toolsListChanged`) for a bounded grace
  window after a scope downgrade, as a documented product/policy decision. This is a
  **deployment-specific policy**, not an MCP specification requirement — later blocks must be
  able to take a configured grace-period parameter rather than assuming zero tolerance.
- **Server-graceful subscription closure during deploys/shutdown.** A server ending
  subscriptions on its own initiative (with a proper `resultType: "complete"` closure) is
  normal operational behavior, not a client-directed attack.

## 14. Known Attacker Evasions

- **Protocol-version downgrade to shed header validation.** Because header enforcement is
  keyed to negotiated protocol version, a client that can get the server to negotiate (or that
  falsely claims) an older version may be able to omit or mismatch `Mcp-Method`/`Mcp-Name`
  without triggering `HeaderMismatch`. The spec itself flags this as a risk for intermediaries
  ("verify that `MCP-Protocol-Version` indicates a version that requires header–body
  validation... reject the request rather than trusting unvalidated header values") — meaning
  the spec authors already anticipated this evasion path at the intermediary layer.
- **Task-ID guessing/enumeration.** SEP-2663's countermeasure is entropy, not detection; a
  server that under-implements entropy (or that leaks IDs via logs, URLs, or error messages)
  gives an attacker a path to a valid-looking `taskId` belonging to another principal. Because
  `tasks/list` doesn't exist, an attacker cannot browse for targets — they can only try IDs
  they've obtained some other way (leakage, guessing, or social engineering), which narrows
  but does not eliminate the Track 2 attack surface.
- **Using the -32602 conflation as cover.** Since "task not found" and "task not yours" return
  the same code, an attacker probing many task IDs against Track 2 controls gets a uniform
  error response either way, resisting naive response-based detection (this is a deliberate
  anti-enumeration property, but it also blinds a purely client-side observer — see §10 and
  §16).
- **Subscribe, then let authorization lapse quietly.** An attacker (or an attacker who has
  compromised a legitimately-authorized session) opens a broad `subscriptions/listen` while
  still authorized, then relies on the fact that nothing in the protocol forces the server to
  re-check credentials against that open stream, effectively "banking" access that outlives the
  grant. This is the direct mechanism behind the Track 3 scenario in §11, not merely a
  hypothetical.
- **Reconnect-without-reauthorization on stdio.** The spec requires stdio clients to re-issue
  `subscriptions/listen` after a reconnect since the server holds no state across
  reconnections — but it does not mandate that the *re-issued* `listen` be checked against
  current (rather than cached) authorization state in every implementation. A poorly
  implemented server could treat reconnection as a rubber stamp.

## 15. Assumptions

- We assume "the authorization context bound to a task" is a real, server-side concept even
  though MCP defines no wire-level owner field — this is necessary to operationalize Track 2,
  and is explicitly `[OUR ASSUMPTION]`, layered on top of, not replacing, the SEP-2663 language
  quoted in §5/§6.
- We assume detection telemetry can access server-side authorization-decision logs (allow/deny
  plus the principal and task/subscription identifiers involved), not just wire captures —
  required because of the -32602 conflation and the lack of an "authorization changed" protocol
  event (§10, §16).
- We assume deployments will supply their own definition of an acceptable revocation-propagation
  delay / grace period for Track 3, since the spec does not define one — see §13.
- We assume "negotiated protocol version" is observable per request (via the
  `MCP-Protocol-Version` header / `io.modelcontextprotocol/protocolVersion` in `_meta`) and can
  be used to gate Track 1 logic, per §9.

## 16. Limitations

- **No normative "authorization changed" event exists in MCP.** Track 3 models a real,
  spec-acknowledged architectural gap (per-request auth philosophy vs. a request whose response
  stream lives indefinitely), but the spec itself provides no hook, notification, or required
  behavior for the server to detect or react to a mid-stream revocation. This is consistent
  with, not merely a theoretical risk on top of, the reference Python SDK's documented
  request-scoped authorization model and event-forwarding design, which likewise describe no
  re-validation step (§7). Any Track 3 design in later blocks is therefore necessarily built on
  **external** signals (an authorization-server revocation event, a policy-engine decision)
  correlated against **internal** MCP telemetry (subscription open time, `subscriptionId`,
  notification delivery timestamps) — it is not something derivable from the MCP wire protocol
  alone. Track 3's default assumption is that drifted delivery exposes change/activity metadata
  (prompting a refetch) rather than inline protected content, except for the separately-flagged,
  experimentally-unvalidated `notifications/tasks` inlining case (§11).
- **No normative "task owner" field exists in MCP.** Track 2 depends on whatever binding a
  given server implementation actually performs, which SEP-2663 explicitly says may not always
  be possible. A server that cannot bind tasks to an authorization context at all is, by the
  SEP's own admission, relying on task-ID secrecy as its only control — later blocks will need
  to treat "no server-side binding available" as a distinct, lower-confidence detection
  posture rather than assuming every deployment can supply ground truth.
- **Error-code ambiguity is a plausible-but-unconfirmed implementation pattern, not a spec
  mandate, and either way limits wire-only detection for Track 2** (§10). Confirmed via primary
  source: SEP-2663 specifies `-32602` only for an invalid/nonexistent `taskId` and is silent on
  the unauthorized-but-existing case. Not confirmed, and not claimed: whether real
  implementations actually collapse the two responses. Track 2's telemetry requirement (§10) is
  designed to hold regardless of which way a given server behaves.
- **This model is current as of the `2026-07-28` GA specification and SEP-2663 Final status.**
  MCP has an active SEP process. Later blocks should re-verify against the then-current spec
  before implementation, rather than treating this document as permanently authoritative.

## 17. Assumptions vs. Normative Requirements — Quick Reference

| Statement | Normative (spec-verified) | Our assumption / detection-design overlay |
|---|---|---|
| `Mcp-Method` must equal `method` on all requests (when protocol version requires it) | ✅ SEP-2243, `2026-07-28` transport spec | |
| `Mcp-Name` must equal `params.taskId` for `tasks/get`/`update`/`cancel` | ✅ SEP-2663 | |
| Header/body mismatch → `HeaderMismatch` (`-32020`), `400` | ✅ `2026-07-28` transport spec | |
| A "task owner" is a protocol-level field | ❌ does not exist | Modeled by us as a server-side concept |
| Servers must authz-check every task request | ✅ SEP-2663 "Auth binding" | |
| Task not-found and not-authorized are wire-distinguishable | Unspecified by SEP-2663 — only invalid/nonexistent → `-32602` is normative | We assume the two **may** be indistinguishable on the wire and require server-side authorization logs regardless |
| Subscriptions must be re-authorized on a fixed cadence | ❌ not specified | Track 3 detection design assumption |
| Subscription auth is checked once at listen-time, not per delivered event | Not stated by the core spec; consistent with the reference Python SDK's documented request-scoped middleware and event-forwarding design (§7, §18) — not an explicit "no re-check" guarantee | Track 3's core premise for why drift is possible at all |
| Ordinary `notifications/resources/updated`/list-changed payloads contain resource contents | ❌ they carry only URI/metadata (`server/resources`, `basic/patterns/subscriptions`) | We treat drift on these as metadata/activity disclosure, not content disclosure |
| `notifications/tasks` can inline a completed task's result content | ✅ schema-verified (`CompletedTask.result`) | Whether this is exploitable via drift is an **unvalidated hypothesis**, flagged for later experimental testing, not folded into the core Track 3 claim |
| A grace period after revocation is allowed | Neither required nor forbidden | Deployment policy input we must accept |
| `subscriptions/listen` replaces `resources/subscribe`/GET-SSE | ✅ SEP-2575, `2026-07-28` changelog | |
| Task states are `working/input_required/completed/failed/cancelled` | ✅ SEP-2663 | |

## 18. References

- MCP specification, revision `2026-07-28` — Changelog:
  https://modelcontextprotocol.io/specification/2026-07-28/changelog
- MCP specification, `2026-07-28` — Streamable HTTP transport (headers, `HeaderMismatch`,
  backward compatibility): https://modelcontextprotocol.io/specification/2026-07-28/basic/transports/streamable-http
- MCP specification, `2026-07-28` — Resources (subscribe capability, per-request authorization
  language): https://modelcontextprotocol.io/specification/2026-07-28/server/resources
- MCP specification, `2026-07-28` — Subscriptions pattern (acknowledgment, `subscriptionId`,
  cancellation, graceful closure): https://modelcontextprotocol.io/specification/2026-07-28/basic/patterns/subscriptions
- MCP specification, `2026-07-28` — Authorization: https://modelcontextprotocol.io/specification/2026-07-28/basic/authorization
- MCP specification, `2026-07-28` — Authorization Security Considerations: https://modelcontextprotocol.io/specification/2026-07-28/basic/authorization/security-considerations
- SEP-2663, Tasks Extension (Final; historical snapshot page):
  https://modelcontextprotocol.io/seps/2663-tasks-extension
- SEP-2663 source (raw markdown, used for exact state/error-code/security-implications text):
  https://github.com/modelcontextprotocol/modelcontextprotocol/blob/main/seps/2663-tasks-extension.md
- Live Tasks extension specification (draft channel):
  https://tasks.extensions.modelcontextprotocol.io/specification/draft/tasks
- SEP-2663 pull request discussion: https://github.com/modelcontextprotocol/modelcontextprotocol/pull/2663
- SEP-1686 (original Tasks proposal, predecessor to SEP-2663): https://github.com/modelcontextprotocol/modelcontextprotocol/issues/1686
- SEP-2243 (header-based routing) pull request: https://github.com/modelcontextprotocol/modelcontextprotocol/pull/2243
- SEP-2575 (stateless core / `subscriptions/listen`) pull request: https://github.com/modelcontextprotocol/modelcontextprotocol/pull/2575
- MCP Blog — "The 2026-07-28 Specification": https://blog.modelcontextprotocol.io/posts/2026-07-28/
- MCP Blog — "The 2026-07-28 MCP Specification Release Candidate": https://blog.modelcontextprotocol.io/posts/2026-07-28-release-candidate/
- Python SDK — Authorization guide (request-scoped token validation, "stopped at the door"):
  https://github.com/modelcontextprotocol/python-sdk/blob/main/docs/run/authorization.md
- Python SDK — `subscriptions` module documentation (event-bus forwarding onto the
  `subscriptions/listen` response stream): https://py.sdk.modelcontextprotocol.io/api/mcp/server/subscriptions/
