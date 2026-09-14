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

## Track 3 — "Was a notification delivered on a still-open subscription after the authorization binding that justified it became invalid?"

**Scope:** the widest correlation surface in this schema — it must join MCP-internal events to
an external (authorization-server/policy-engine) signal that has no MCP wire representation at
all (Block 1 §16), **and must resolve exactly which authorization binding(s) a given external
change affects before it can be joined to a specific stream at all.**

**Scope-aware correction (this revision).** The previous version of this section joined a
principal's `authorization_change` event to *every* subscription that same principal held,
implicitly treating "same principal" as "same authorization scope." Verified against current
MCP/OAuth documentation, that conflation does not hold in general: a principal may hold multiple
independent, independently-revocable bindings at once (RFC 7009 scopes revocation to "a
particular token," cascading only by explicit server policy); a scope downgrade removes specific
permissions, not blanket access (MCP's authorization page requires servers to reason about scope
per operation); the wire subscription id is connection-scoped, not globally unique (MCP's
subscriptions pattern: no state survives a reconnect); and a grant fingerprint is not a stable
identity across a token refresh (RFC 6749 §6). The corrected model below resolves scope
explicitly, using only evidence present in the telemetry — never a scenario label, never an
assumption of safety.

### Correlation identifiers

- `mcp.subscription.instance_id` — the authoritative join key for one continuous stream
  incarnation (ties `.open`, `.acknowledged`, every `.notification`, and the eventual `.close`
  together). Legacy events lacking it are treated as
  `instance_id = principal.id_hash + ":" + mcp.subscription.id` (compatibility fallback,
  principal-scoped so two different principals reusing the identical wire id never collide onto
  one instance — correct only for a single-server/tenant deployment where the same principal
  never reopens the identical wire id twice).
- `mcp.authz.binding_id` — the authorization binding backing an instance, set at `.open` and
  optionally overridden per-`.notification` (proof of rebinding, see "Validity intervals"
  below). Legacy `.open` events lacking it are treated as an internal-only pseudo-binding scoped
  to `(principal.id_hash, mcp.subscription.id)`.
- `principal.id_hash` — appears on `.open`, `.notification`, and `.authorization_change`. It is
  what lets a change event's `affected_scope = all_principal_bindings` be resolved (by checking
  every binding open, and not yet closed, at `effective_at` for that principal — see "Resolving
  affected bindings" below). It is **not**, by itself, sufficient to scope a `binding`-level
  change, and it is **not** used to guess a binding for `unknown`-scoped changes (see below).
- `mcp.authz.change.affected_scope` / `affected_binding_ids` — states which binding(s) a change
  affects. `binding` + a populated `affected_binding_ids` is the precise, no-ambiguity case.
  `all_principal_bindings` is the only case permitted to broaden past named bindings. `unknown`
  (or the field's absence, for legacy events) ALWAYS resolves to `insufficient_evidence` when
  timing would otherwise indicate a violation — **never** inferred from how many candidate
  bindings happen to be observed for the principal, even when there is exactly one (an earlier
  revision of this contract permitted that "sole-candidate" inference; it was found to be an
  unsupported inference, not evidence, and was removed — see "Resolving affected bindings" below
  and `docs/validation-report.md`, "Track 3 remediation pass, part 3").
- `mcp.subscription.required_scope` / `mcp.authz.change.removed_scope` — for
  `mcp.authz.change.type = scope_downgraded` specifically: even a change that correctly names an
  instance's own binding does not invalidate it unless the removed scope intersects the
  instance's required scope. Either side missing makes relevance unresolved.
- The relevant "authorization became invalid at" timestamp, chosen by **strict preference
  order**, unchanged from prior revisions:
  1. `mcp.authz.change.effective_at`, when present and `timing_confidence = authoritative`.
  2. `mcp.authz.valid_until` (open-time, or a later `.notification`-level value proving
     rebinding — see below), or the open-time `mcp.authz.grant_expiry` as a last resort — always
     computable, no external push feed required.
  3. `mcp.authz.change.detected_at` alone (`timing_confidence = detected_only`) is **no longer
     promoted to a scored finding of any confidence** — see "Three-outcome reporting" below.
- `security.hash.key_id` — must match across every event being compared by hashed field
  (`principal.id_hash`, and `mcp.authz.binding_id` if a deployment chooses to hash it). A
  mismatch between an instance's own open-time key epoch and a later event's key epoch makes
  that comparison unsafe and must be reported as insufficient evidence, not silently skipped or
  silently trusted.

### Resolving affected bindings (the reference algorithm)

For each `mcp.subscription.authorization_change` event:

1. If `affected_scope = binding`: the affected set is exactly `affected_binding_ids`.
2. If `affected_scope = all_principal_bindings`: the affected set is every `mcp.authz.binding_id`
   that was **already open, and not yet closed, at the moment `effective_at` occurred** — a
   PRECISE effective-time interval check, not "ever observed anywhere in the queried window" (an
   earlier revision of this contract used that looser approximation; a binding issued for the
   same principal *after* `effective_at` did not exist yet at the moment of the change and cannot
   be covered by it — see `docs/validation-report.md`, "Track 3 remediation pass, part 3",
   fixture V13-06). This is the only path allowed to broaden past a specific binding, and it
   requires the change event to say so explicitly — it is never the default.
3. If `affected_scope = unknown`, or the field is absent (legacy event): the affected set is
   **indeterminate, always** — report `insufficient_evidence` (`ambiguous_scope`) whenever timing
   would otherwise indicate a violation. This holds **regardless of how many candidate bindings
   happen to be observed for the principal, including exactly one** — a candidate count is not
   evidence of which binding a change applies to, and inferring one from it (an earlier revision
   of this contract permitted exactly this "sole-candidate fallback") was found to be an
   unsupported inference and removed (`docs/validation-report.md`, "Track 3 remediation pass,
   part 3", fixture V13-03). The only way an `unknown`-scoped change still produces a finding is
   if a `.notification`/`.close` event **explicitly** carries a matching `mcp.authz.binding_id` of
   its own (directly-scoped invalidation needs no retained open event and no scope inference at
   all); absent that, there is nothing to resolve and the change produces no finding for that
   instance (not insufficient evidence — there is simply no observed stream it could apply to).

For `mcp.authz.change.type = scope_downgraded` specifically, a binding in the affected set is
only actually invalidated for a given instance if `removed_scope` intersects that instance's
`required_scope`. If either is missing, that instance's relevance is unresolved
(`insufficient_evidence`), not defaulted to safe or unsafe.

### Validity intervals and proven reauthorization

Each binding has a validity interval, not a single point: valid from when it started backing an
instance until it is invalidated (by the algorithm above) or its own `valid_until`/`grant_expiry`
is reached. **A subscription instance's notifications are checked against the binding recorded on
that specific notification** (or, if absent, the instance's open-time binding) — never against
"whatever binding is currently valid for this principal elsewhere." Concretely:
- An old binding expiring or being revoked **after** a proven reauthorization (a later
  notification explicitly carrying a new, still-valid `binding_id`) does not affect that later
  notification — it is evaluated against the *new* binding's own interval.
- A **new, unrelated** binding becoming valid for the same principal does not retroactively clear
  an earlier violation on the old binding — the old notification is still evaluated against the
  binding it actually carried (or its instance's open-time binding).
- Token refresh alone is never assumed to reauthorize an existing stream — only an explicit
  `mcp.authz.binding_id` on a later `.notification` constitutes proof of rebinding.

### Three-outcome reporting (this revision)

Every evaluated notification produces exactly one of three outcomes, reported separately from
each other so reduced evaluability can never masquerade as clean detection:

- **`confirmed_drift`** — the notification's timestamp is strictly after the resolved,
  authoritative invalidation boundary of the binding that backs it, with no qualifying close at
  or before it, and scope resolution (above) was unambiguous.
- **`evaluated_no_violation`** — evidence was sufficient to reach a definitive answer, and no
  violation was found (before the boundary, a close intervened, a downgrade's removed scope did
  not intersect the instance's required scope, the change type does not invalidate, or the
  notification is proven-rebound to a separate, still-valid binding).
- **`insufficient_evidence`** — resolution could not be completed: `unknown`/legacy scope with
  timing that would otherwise indicate a violation, missing scope data needed for a
  downgrade-relevance check, conflicting evidence (two authoritative signals about the same
  binding that cannot both be true), an incompatible hash-key epoch between compared events, a
  self-contradictory record (authoritative timing claimed with no `effective_at`), or
  `detected_at`-only timing with no authoritative boundary available.

If content sensitivity matters for triage, also read
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
