# Correlation Requirements and Example Event Sequences

Defines the exact correlation identifiers each detection track needs, then walks six concrete
event sequences (per the Block 2 validation requirement) using the event types from
`telemetry/events.md`. No Sigma/KQL/SPL logic is written here — this documents what a later
query would need to join on, not the query itself.

**Two Block 2 conclusions re-verified during this patch and retained unchanged:**
1. `mcp.subscription.id` is the `subscriptions/listen` request's own JSON-RPC `id`, reused
   directly as the subscription identifier (`_meta."io.modelcontextprotocol/subscriptionId"`,
   Block 1 §7) — still the correct, spec-grounded Track 3 join key; no change.
2. W3C trace context (`traceparent`/`tracestate`/`baggage` via MCP `_meta`, SEP-414) is
   optional for MCP clients to send. It remains a *nice-to-have* correlation aid (`trace_id`/
   `span_id` in `telemetry/schema.md`) and **cannot be relied upon as a required field for
   detection correctness** in any of the three tracks — every correlation path documented below
   works using only `jsonrpc.request.id`, `mcp.task.id_hash`, `principal.id_hash`, and
   `mcp.subscription.id`, none of which depend on trace-context propagation.

---

## Track 1 — "Did the routing header identify the same method/task as the JSON-RPC body?"

**Scope:** entirely within a single request/response cycle. No cross-event, cross-time
correlation is needed.

**Required correlation identifiers:**
- `jsonrpc.request.id` — ties `mcp.request.received`, `mcp.request.validation`, and
  `mcp.response` together as one unit (all three carry it).
- `mcp.transport` and `mcp.protocol.version` — must be read *before* judging any missing header,
  because a header is only "missing" (a possible finding) versus "not applicable" (compatibility
  traffic) depending on these two fields (Block 1 §9, state-invariants.md row 3).
- The four raw comparison values — `mcp.header.method`/`mcp.body.method` and
  `mcp.header.name_hash`/`mcp.body.identity_hash` — are compared *once*, by the server itself,
  at `mcp.request.validation` time, and the verdict is recorded in
  `mcp.validation.method.result`/`mcp.validation.name.result`. A later query does not need to
  redo the comparison; it needs to filter on the recorded verdict.

**Answering the question:** filter `mcp.request.validation` events where
`mcp.validation.method.result` or `mcp.validation.name.result` = `conflict` (not `missing`, not
`version_incompatible` — see the distinction Block 1 §9 requires). No join across events is
required beyond optionally pulling the matching `mcp.response` by `jsonrpc.request.id` to see
whether the server actually rejected the request (it should have, per `HeaderMismatch`).

**Source preference (patch addition):** always check `mcp.validation.source` first. When it is
`server_native`, the verdict came from the MCP server's own plaintext, spec-mandated equality
check and should be trusted directly. When it is `collector_derived` — the server didn't expose
its own validation outcome, so a collector recomputed `mcp.header.name_hash` vs.
`mcp.body.identity_hash` independently — treat the verdict as supplementary evidence, not a
ground truth, because a hash-equality comparison cannot see through canonicalization
differences (e.g., Base64-sentinel decoding) that plaintext comparison would. Prefer instrumenting
`server_native` capture wherever the server implementation allows it.

---

## Track 2 — "Was this authenticated principal authorized to perform this operation against this task?"

**Scope:** potentially spans many requests, over time, from different principals, against the
same task.

**Required correlation identifiers:**
- `mcp.task.id_hash` — the primary join key. All `mcp.task.authorization` events (from any
  principal, at any time) for the same task carry the same hash.
- `principal.id_hash` — identifies who made each attempt; grouping `mcp.task.authorization`
  events by `mcp.task.id_hash` and looking at the *distinct set* of `principal.id_hash` values
  is how a cross-principal pattern becomes visible.
- `mcp.task.authz_context_id_hash` — the server's own record of who the task is bound to; this
  is what turns "two different principals touched this task" (which may be entirely legitimate)
  into "a principal touched a task whose context doesn't name them" (Block 1 §5).
- `mcp.authz.reason` — the field that keeps this from being a false-positive machine: a second
  principal appearing against the same `mcp.task.id_hash` with `mcp.authz.reason =
  authorized_grant` is the legitimate shared-access case; the same pattern with
  `mcp.authz.reason = principal_mismatch` (and `mcp.authz.decision = deny`) is the violation.
  If `mcp.authz.decision = allow` ever co-occurs with a principal that does not match
  `mcp.task.authz_context_id_hash` and is not `authorized_grant`, that is the server-side bug
  Track 2 exists to catch (an authorization check that should have denied and didn't).

**Answering the question:** never from `mcp.response`/`rpc.status_code` alone (Block 1 §10 —
`-32602` is ambiguous between "not found" and "not yours"). Always from the recorded
`mcp.authz.decision`/`mcp.authz.reason` on `mcp.task.authorization`, joined to
`mcp.task.id_hash` and `principal.id_hash`.

**Handling a missing `mcp.task.authz_context_id_hash` (patch correction):** a `null`/absent
value on this field means the server did not expose (or does not maintain) a binding between
the task and an authorization context — it is a **visibility gap**, not a signal of any kind.
It must never, by itself, produce a Track 2 finding, contribute to a severity score, or be
treated as "suspicious." Its only correlation role is downstream: when it is `null`, a record
either (a) has reduced confidence if `mcp.authz.decision`/`mcp.authz.reason` are also absent or
inconclusive, or (b) remains fully evaluable if the server's own `mcp.authz.decision =
deny`/`mcp.authz.reason = principal_mismatch` (or equivalent) already establishes the violation
directly — in that case the missing context hash is irrelevant, because the alert is grounded in
the server's authorization decision, not in the context-binding field. **Track 2 alerts only on
sufficient server-side authorization evidence** (an explicit deny with a violation-shaped
reason, or an explicit allow that contradicts a known-authoritative context binding) — never on
the mere absence of `mcp.task.authz_context_id_hash`.

---

## Track 3 — "Was a notification delivered on a still-open subscription after the authorization state that justified it became invalid?"

**Scope:** the widest correlation surface in this schema — it must join MCP-internal events to
an external (authorization-server/policy-engine) signal that has no MCP wire representation at
all (Block 1 §16).

**Required correlation identifiers:**
- `mcp.subscription.id` (optionally `mcp.subscription.id_hash`) — ties `mcp.subscription.open`,
  `.acknowledged`, every `.notification`, and the eventual `.close` together as one stream.
- `principal.id_hash` — the **only** field that also appears on
  `mcp.subscription.authorization_change`, since that event is sourced externally and has no
  `mcp.subscription.id` of its own (a principal's authorization can change independent of any
  specific subscription). This is the join that bridges MCP-internal telemetry to the external
  authorization signal.
- The relevant "authorization became invalid at" timestamp, chosen by **strict preference order
  (patch addition)**:
  1. `mcp.authz.change.effective_at`, when present and `mcp.authz.change.source` is
     `authorization_server_event` or `policy_engine` (i.e., `timing_confidence = authoritative`)
     — this is the true revocation/change time and should be used whenever available.
  2. `mcp.authz.valid_until` (or, failing that, the open-time `mcp.authz.grant_expiry`), for the
     silent-expiry case where no explicit change event exists at all — this is always
     computable and does not depend on an external push feed.
  3. `mcp.authz.change.detected_at` alone, only when neither of the above is available
     (`timing_confidence = detected_only`) — used **with an explicit caveat carried into the
     finding** that the true change may have happened earlier and an unknown blind window
     exists between the real change and its observation. A finding built on `detected_at` alone
     must never be reported as if `detected_at` were the revocation time itself.
- `mcp.authz.grant_snapshot_hash` — lets a query confirm the notification's subscription was
  actually opened under the authorization that later changed (guards against comparing against
  the wrong grant if a principal has multiple overlapping sessions).

**Answering the question:** for each `principal.id_hash` with an
`mcp.subscription.authorization_change` event (or a computable `mcp.authz.valid_until`/
`grant_expiry` boundary, even with no explicit event), find every `mcp.subscription.id` opened
by that same `principal.id_hash` that is still `active` (no `.close` event, or a `.close` event
with a later timestamp) at the chosen timestamp from the preference order above, then check
whether any `mcp.subscription.notification` for that `mcp.subscription.id` has a timestamp
after it. Carry `timing_confidence` (or its absence, for the pure-expiry case) forward into the
finding so a `detected_only` result is never presented with the same certainty as an
`authoritative` one. If content sensitivity matters for triage, also read
`mcp.subscription.notification.contains_inline_result` and `notification_type` — per Block 1
§11, an ordinary `notifications/resources/updated` drift is a metadata/activity exposure, while
a `notifications/tasks` drift with `contains_inline_result = true` is the separately-flagged,
higher-severity, not-yet-experimentally-validated case.

---

## Example event sequences

Fields shown are trimmed to what matters for the scenario; see `telemetry/events.md` for full
minimal examples per event type.

### 1. Normal task request (no violation)

```
mcp.request.received      { jsonrpc.request.id: "9", mcp.header.method: "tasks/get", mcp.body.method: "tasks/get", mcp.header.name_hash: "hA", mcp.body.identity_hash: "hA" }
mcp.request.validation    { jsonrpc.request.id: "9", mcp.validation.method.result: "match", mcp.validation.name.result: "match", mcp.validation.result: "valid" }
mcp.task.authorization    { principal.id_hash: "h_alice", mcp.task.id_hash: "hA", mcp.task.authz_context_id_hash: "h_alice", mcp.task.operation: "get", mcp.authz.decision: "allow", mcp.authz.reason: "authorized_owner" }
mcp.task.state            { mcp.task.id_hash: "hA", mcp.task.state: "working", mcp.task.previous_state: "working" }
mcp.response               { jsonrpc.request.id: "9", http.response.status_code: 200 }
```

### 2. Routing desynchronization (Track 1 finding)

```
mcp.request.received      { jsonrpc.request.id: "9", mcp.header.method: "tasks/cancel", mcp.body.method: "tasks/cancel", mcp.header.name_hash: "hA", mcp.body.identity_hash: "hB" }
mcp.request.validation    { jsonrpc.request.id: "9", mcp.validation.method.result: "match", mcp.validation.name.result: "conflict", mcp.validation.result: "invalid", mcp.validation.reason: "Mcp-Name does not match params.taskId" }
mcp.response               { jsonrpc.request.id: "9", rpc.status_code: "-32020", error.type: "HeaderMismatch", http.response.status_code: 400 }
```
No `mcp.task.authorization` event is emitted — the request never reaches the authorization
check because it is rejected at validation.

### 3. Legitimate authorized cross-principal / shared access

Alice created Task-123; the server's application logic explicitly grants a delegate (Carol)
access — e.g., a shared workspace or an explicit "invite collaborator" action recorded server-
side as a grant, distinct from ownership.

```
mcp.task.authorization    { principal.id_hash: "h_alice", mcp.task.id_hash: "hA", mcp.task.authz_context_id_hash: "h_alice", mcp.task.operation: "get", mcp.authz.decision: "allow", mcp.authz.reason: "authorized_owner" }
mcp.task.authorization    { principal.id_hash: "h_carol", mcp.task.id_hash: "hA", mcp.task.authz_context_id_hash: "h_alice", mcp.task.operation: "get", mcp.authz.decision: "allow", mcp.authz.reason: "authorized_grant" }
```
Two distinct `principal.id_hash` values against the same `mcp.task.id_hash`, both `allow` — but
the second carries `authorized_grant`, not `authorized_owner`/`principal_mismatch`, which is
exactly the field that keeps this from being misclassified as scenario 4.

*(Note per Block 1 §5: whether a given deployment supports this shared-access model at all is a
server-side application decision — MCP itself defines no sharing mechanism for tasks. This
scenario is included because the Block 2 brief asked us to model it "if such a model exists";
its telemetry shape depends entirely on that server-side feature existing.)*

### 4. Unauthorized cross-principal task operation (Track 2 finding)

```
mcp.request.received      { jsonrpc.request.id: "17", mcp.header.method: "tasks/cancel", mcp.body.method: "tasks/cancel", mcp.header.name_hash: "hA", mcp.body.identity_hash: "hA" }
mcp.request.validation    { jsonrpc.request.id: "17", mcp.validation.result: "valid" }
mcp.task.authorization    { principal.id_hash: "h_bob", mcp.task.id_hash: "hA", mcp.task.authz_context_id_hash: "h_alice", mcp.task.operation: "cancel", mcp.authz.decision: "deny", mcp.authz.reason: "principal_mismatch" }
mcp.response               { jsonrpc.request.id: "17", rpc.status_code: "-32602", http.response.status_code: 400 }
```
Note the response error code (`-32602`) is identical in shape to an ordinary "task not found"
error (Block 1 §10) — this is exactly why the finding is drawn from `mcp.task.authorization`,
not from `mcp.response`.

**Variant — no context binding available (patch addition):** if the server cannot bind tasks to
an authorization context at all (Block 1 §5), the same event would instead read
`mcp.task.authz_context_id_hash: null`. If the server's own `mcp.authz.decision`/
`mcp.authz.reason` still independently show `deny`/`principal_mismatch` (or an equivalent
violation-shaped reason), the finding stands on that evidence alone — the null context field is
irrelevant to it. If, however, the server can only report `mcp.authz.decision: allow` (or omits
the authorization event entirely) with no context binding, Track 2 has **no evidence to alert
on** — the correct handling is reduced confidence / "unevaluable," never an inferred violation.

### 5. Normal subscription (open → active → closed, no drift)

```
mcp.subscription.open           { mcp.subscription.id: "42", principal.id_hash: "h_alice", mcp.authz.grant_snapshot_hash: "hG1", mcp.authz.grant_expiry: "2026-09-12T15:05:00Z" }
mcp.subscription.acknowledged   { mcp.subscription.id: "42", mcp.subscription.state: "acknowledged" }
mcp.subscription.notification   { mcp.subscription.id: "42", mcp.subscription.state: "active", mcp.subscription.notification_type: "notifications/resources/updated" }
mcp.subscription.close          { mcp.subscription.id: "42", mcp.subscription.state: "closed_graceful", mcp.subscription.close.reason: "client_closed" }
```
All notification timestamps fall before `mcp.authz.grant_expiry` and no
`mcp.subscription.authorization_change` event exists for `h_alice` — nothing to flag.

### 6. Subscription with later authorization revocation and post-revocation notification (Track 3 finding)

```
mcp.subscription.open                 { mcp.subscription.id: "42", principal.id_hash: "h_alice", mcp.authz.grant_snapshot_hash: "hG1", mcp.authz.grant_expiry: "2026-09-12T15:05:00Z", timestamp: "14:05:00.000Z" }
mcp.subscription.acknowledged         { mcp.subscription.id: "42", timestamp: "14:05:00.050Z" }
mcp.subscription.notification         { mcp.subscription.id: "42", mcp.subscription.notification_type: "notifications/resources/updated", timestamp: "14:20:00.000Z" }   -- before revocation: fine
mcp.subscription.authorization_change { principal.id_hash: "h_alice", mcp.authz.change.type: "revoked", mcp.authz.change.source: "authorization_server_event", mcp.authz.change.effective_at: "14:29:55.000Z", mcp.authz.change.detected_at: "14:30:00.000Z", mcp.authz.change.timing_confidence: "authoritative" }
mcp.subscription.notification         { mcp.subscription.id: "42", mcp.subscription.notification_type: "notifications/resources/updated", mcp.subscription.notification.resource_uri_hash: "hU1", timestamp: "14:45:00.000Z" }   -- AFTER revocation, no close in between: Track 3 finding
mcp.subscription.close                { mcp.subscription.id: "42", mcp.subscription.state: "closed_abrupt", mcp.subscription.close.reason: "transport_drop", timestamp: "15:00:00.000Z" }
```
The second `mcp.subscription.notification` at `14:45:00.000Z` is delivered after
`mcp.authz.change.effective_at` (`14:29:55.000Z`) with no intervening `mcp.subscription.close` —
this is the exact four-step condition from Block 1 §11 and `telemetry/schema.md`'s Track 3
section. Because `timing_confidence = authoritative` here, the finding can be reported with a
precise boundary (`14:29:55.000Z`). Because `notification_type = notifications/resources/updated`
(not `notifications/tasks`), the exposure is scoped, per Block 1 §11, to a change/activity
signal — not an assumed content disclosure.

**Variant — only `detected_at` available:** if the authorization server had not reported
`effective_at` (e.g., a poll-based introspection setup with no push feed), the same event would
instead read `mcp.authz.change.source: "token_expiry_computed"` or a plain revocation with no
`effective_at`, `mcp.authz.change.detected_at: "14:30:00.000Z"`, and
`mcp.authz.change.timing_confidence: "detected_only"`. The same notification at `14:45:00.000Z`
would still be flagged (it is after `detected_at`), but the finding must be reported with the
caveat that the true revocation could have happened any time before `14:30:00.000Z` — including,
in the worst case, before the `14:20:00.000Z` notification that this document otherwise treats as
"before revocation: fine." This is the blind window the Block 2 patch requires to be documented
rather than papered over.
