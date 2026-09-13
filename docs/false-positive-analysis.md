# False Positive Analysis

Block 6 deliverable. Compiles known benign causes, environmental dependencies, and tuning
guidance for all three detection tracks, informed by the Block 6 stress-test corpus
(`data/validation/`, 48 scenarios) and its findings (`docs/validation-report.md`).

This document distinguishes three different things that are easy to conflate:
- A **rule defect** — the logic itself is wrong given correct inputs. Found once in Block 6
  (V5-03); fixed.
- An **instrumentation/environment dependency** — the rule is correct given its inputs, but the
  inputs can be wrong (bad canonicalization, clock skew, misreported timestamps). Not fixable
  at the rule layer.
- An **accepted, deployment-specific gap** — the locked telemetry schema has no field to
  represent a real, legitimate policy (grace periods, permanent exemptions). Not fixable
  without a schema change, which is out of scope for rule tuning.

---

## Track 1 — MCP Task Routing Header/Body Desynchronization

> **Applicability statement.** `mcp.validation.source = server_native` is the highest-confidence
> case: the server itself, with full plaintext access, performed the header/body comparison. A
> `collector_derived` verdict is only as trustworthy as the collector's own canonicalization
> (e.g., correctly decoding a Base64-sentinel-encoded header before hashing, per
> `telemetry/schema.md` §6 rule 5). **Collector instrumentation failure can manufacture a false
> conflict indistinguishable from a real one, and must never be silently treated as adversary
> activity** — it is a data-quality defect to fix in the collector, not evidence of an attack.
> See V1-08 below and `docs/validation-report.md` View 2 for the mechanically-verified case.

### Known benign causes
- A legacy client negotiating a protocol version that predates SEP-2243 (`< 2026-07-28`) has no
  `Mcp-Method`/`Mcp-Name` to compare at all — correctly resolves to `version_incompatible`, not
  a false positive (Block 3 N13, Block 4 A6, Block 6 V1-01).
- A client mid-migration to `2026-07-28` that has not yet implemented sending the headers
  produces a genuine `missing` result — the **primary** rule correctly does not fire on this
  (only the separate, low-severity diagnostic rule does). Block 6 V1-02 is the first fixture in
  this entire project to exercise this exact case.
- Parse failures (`-32700`), unsupported methods (`-32601`), and ordinary application errors
  (`-32603`) with fully matching routing never reach or involve the routing-validation logic
  meaningfully — confirmed not to false-positive (V1-05, V1-06, V1-07).
- Case-insensitive HTTP header **name** normalization by an intermediary proxy does not affect
  header **value** comparison (V1-04).
- `collector_derived` validation, when the collector performs canonicalization correctly, is
  just as reliable as `server_native` (V1-03).

### Environmental dependencies (instrumentation risk, not a rule defect)
- **Canonicalization correctness is entirely upstream of the rule.** If a collector hashes a
  Base64-sentinel-encoded `Mcp-Name` header value *without decoding it first* (a violation of
  `telemetry/schema.md` §6 rule 5), it will compute a hash that disagrees with the body's hash
  even though the true underlying identity is identical — producing an artifactual `conflict`
  that the primary rule will, correctly given its input, alert on (Block 6 V1-08, contrasted
  directly with the correctly-decoded control V1-09). **The rule cannot detect or correct this
  from the audit event alone** — `mcp.validation.source = collector_derived` is the only signal
  available to a downstream analyst that the evidence is weaker than a `server_native` verdict.
- **Tuning recommendation (not implemented in Block 5/6, flagged for a later block):** consider
  differentiating alert *confidence* (not the fire/no-fire boolean) by `mcp.validation.source`
  — e.g., `server_native` conflicts as High, `collector_derived` conflicts as Medium pending
  corroboration. This was identified during Block 6 as a reasonable enhancement but was
  deliberately **not implemented** this block, to keep the one confirmed correctness bug
  (V5-03) as the sole in-scope tuning change and avoid conflating an enhancement with a fix.

### Fields required to confirm the alert
`mcp.header.method`/`mcp.body.method`, `mcp.header.name_hash`/`mcp.body.identity_hash`,
`mcp.validation.source`, `mcp.validation.reason`, `mcp.protocol.version` (to independently
confirm the negotiated version genuinely requires the header).

### When to downgrade severity
- `mcp.validation.source = collector_derived` and no corroborating `server_native` signal
  exists for the same request — treat as Medium pending investigation, not High.
- The diagnostic rule (`missing`/`malformed`) is already Low by design; never promote it to
  High without independently confirming the header was genuinely required and genuinely absent
  on the wire (not just absent from what the collector captured).

### When not to alert
- `version_incompatible` results (by design, both the primary and diagnostic rules already
  exclude these).
- Any event where `event.name != mcp.request.validation` — there is nothing to evaluate.

### Known blind spots
- A protocol-version downgrade (forced or spoofed) sheds the header requirement entirely —
  documented in `docs/evasion-limitations.md`.

---

## Track 2 — MCP Cross-Principal Task Authorization Violation

### Known benign causes
- Explicit shared/delegated access (`mcp.authz.reason = authorized_grant`), including a service
  principal acting on behalf of a user (Block 6 V3-01) — the rule correctly does not care *why*
  a grant exists, only that it is a grant, not a mismatch.
- A policy change that legitimately expands access over time (V3-02): an earlier denial under
  an old `mcp.authz.policy_version` is a real historical Track 2 event and correctly still
  fires *at the time it occurred* — it does not retroactively become a false positive once
  policy is updated. The later, policy-updated allow correctly does not fire. Track 2 evaluates
  each authorization event on its own terms, not as an evolving relationship.
- Denials unrelated to cross-principal misuse: `policy_denied` (V3-03), `context_unbound`/
  nonexistent task (V3-04), authentication failure with no authorization event at all (V3-05).
- `mcp.task.authz_context_id_hash = null` alongside a definite `allow` decision (V3-06) — per
  the Block 2 patch, null context visibility must never gate the rule in either direction.
- Missing optional fields (`principal.auth_method`, `mcp.authz.policy_version`) alongside a
  clean decision/reason (V3-07).

### Environmental dependencies
- **Entirely dependent on the emitting server correctly implementing and labeling its own
  authorization decision.** A server that denies for the right reason but mislabels
  `mcp.authz.reason` (e.g., emits `unknown` instead of `principal_mismatch`) produces a false
  negative no wire-level signal could catch. This is an instrumentation trust boundary.
- If a deployment's authorization system is itself fooled (e.g., an attacker holding the
  victim's own valid, stolen credentials), the emitted telemetry is indistinguishable from a
  legitimate access (`allow`, `authorized_owner`) — see `docs/evasion-limitations.md`, V4-01.
  This is not a Track 2 false-negative in the rule-logic sense; it is a fundamental
  observability limit of authorization-decision telemetry.

### Fields required to confirm the alert
`principal.id_hash`, `mcp.task.id_hash`, `mcp.authz.decision`, `mcp.authz.reason`
(specifically `principal_mismatch`). `mcp.task.authz_context_id_hash` and
`mcp.authz.policy_version` are corroborating context, never required to confirm.

### When to downgrade severity
There is no lower-confidence variant of this rule (unlike Track 1 and Track 3) — Block 2's
`mcp.authz.reason` enum was specifically designed to remove wire-level ambiguity, so a
`principal_mismatch` denial is already unambiguous server-side evidence. If an environment's
`mcp.authz.reason` values are known to be unreliable (e.g., a server implementation still being
validated), treat the entire rule's output for that data source as lower confidence — this is a
data-source-level judgment, not something the query itself can express.

### When not to alert
Any `mcp.authz.reason` other than `principal_mismatch` (`policy_denied`, `insufficient_scope`,
`context_unbound`, `unknown`), and any `mcp.authz.decision = allow` regardless of reason.

### Known blind spots
- Identity/credential theft upstream of MCP authorization telemetry (V4-01) — not detectable.
- Audit instrumentation for `mcp.task.authorization` disabled or failing silently while the
  server still enforces real authorization correctly (V4-02) — the *rule* has nothing to fire
  on; a companion telemetry-completeness monitor (out of scope for the three locked tracks) is
  the recommended mitigation, not a Track 2 rule change.

---

## Track 3 — MCP Long-Lived Subscription Authorization Drift

> **Applicability statement / deployment prerequisite.** The high-confidence Track 3 rule is
> appropriate **only** where an authoritative `revoked`, `expired`, or `scope_downgraded`
> `effective_at` means the subscription is genuinely no longer authorized to receive relevant
> notifications at and after that instant. If an organization has grace periods,
> grandfathered/open-stream exemptions, or other policy semantics that legitimately allow
> delivery after that timestamp, **the rule requires environment-specific tuning or additional
> policy telemetry** (a query-level grace-period constant or exemption allowlist) before it can
> be deployed without generating known, expected operational false positives. **No new Block 2
> schema field is added to solve this** — see V5-02, V5-09, and
> `docs/validation-report.md` View 2 for the mechanically-verified operational-false-positive
> table.

### Known benign causes
- A notification legitimately preceding a later revocation (V5-01).
- A stream closing at the exact instant of revocation (V5-04), or a notification timestamped
  exactly equal to `effective_at` (V5-05) — this project's convention treats the boundary as
  exclusive (violation requires strictly *after*), which is a defensible but non-spec-mandated
  interpretive choice, documented here explicitly.
- A legitimate authorization **renewal** (`mcp.authz.change.type = scope_upgraded`) — **this
  was a real, confirmed false positive prior to the Block 6 fix**; see "Tuning performed"
  below.
- `detected_at` arriving long after `effective_at` (V5-07) does not affect correctness when
  timing is authoritative — the rule is correctly insensitive to how large this gap is.

### Environmental dependencies (not rule defects)
- **Clock skew between the authorization server and the MCP server** (V5-06): if the AS's
  clock runs fast, a reported `effective_at` can appear later than a notification that, in true
  wall-clock time, actually followed the real revocation — producing a **false negative** the
  rule cannot see through. Mitigation is operational (NTP-synchronized clocks across the
  authorization server and MCP server), not a query change.
- **Inaccurate `effective_at`** reported by the authorization server (garbage-in,
  garbage-out) — the rule trusts the value it is given.
- **Delayed/partial telemetry ingestion**: if the `mcp.subscription.authorization_change` event
  straggles in well after the notification it explains, a query with a narrow lookback window
  may transiently miss the correlation until re-run over a wider window. This is a latency
  concern, not a correctness one, as long as all relevant events eventually arrive before the
  query executes — but a deployment relying on a short rolling window should be aware of it.

### Operational false positives — accepted, deployment-specific gaps (documented, deliberately not suppressed; see `docs/validation-report.md` View 2 for the mechanically-computed table)
- **Grace periods** (V5-02): a notification delivered shortly after a scope downgrade, within a
  deployment-defined grace window, is mechanically indistinguishable from a real violation,
  because **no grace-period field exists in the locked Block 2 schema**. Tuning recommendation:
  apply a per-deployment grace-period constant in the query (`WHERE notif_time > boundary +
  grace_period`) rather than inventing a new telemetry field.
- **Permanent policy exemptions** (V5-09): a documented, deployment-specific decision to allow
  certain already-open streams to continue indefinitely after revocation is likewise invisible
  to the schema. Tuning recommendation: a deployment-side allowlist (by principal or
  `policy_version`) applied as a suppression rule downstream of this detection, not encoded
  into the base query.

### Tuning performed in Block 6 (the one confirmed rule defect this project has found)
**Finding (V5-03):** the original Track 3 logic (Sigma component rule, KQL, SPL, and the shared
JS test oracle) treated *any* authoritative `mcp.authz.change` event as an invalidating
boundary, without checking `mcp.authz.change.type`. A legitimate renewal (`scope_upgraded`,
which only expands access) was therefore indistinguishable from a revocation, producing a
confirmed false positive.

**Root cause:** the boundary-selection logic never consulted `mcp.authz.change.type` at all.

**Fix:** restricted the invalidating-boundary check to `mcp.authz.change.type` in
`{revoked, expired, scope_downgraded}`, explicitly excluding `scope_upgraded`. Applied
identically to `detections/sigma/mcp_subscription_authorization_change_authoritative.yml`,
`detections/kql/mcp_subscription_authorization_drift.kql`,
`detections/spl/mcp_subscription_authorization_drift.spl`, and
`tests/attack/track3util.js`.

**Regression verification:** all 101 tests across Blocks 3–6 pass after the fix; A12/A13/A14
(the three non-experimental true positives) are unaffected; V5-03 now correctly does not fire.
See `docs/validation-report.md` for the full before/after.

### Fields required to confirm the alert
`mcp.subscription.id`, `principal.id_hash`, `mcp.authz.change.effective_at` (preferred) or
`mcp.authz.valid_until` (when no change event exists), `mcp.authz.change.timing_confidence`,
`mcp.authz.change.type` (must be `revoked`/`expired`/`scope_downgraded`), the notification's own
timestamp, and confirmation that no `mcp.subscription.close` exists at or before it.

### When to downgrade severity / when not to alert
- Never promote a `timing_confidence = detected_only` finding to High confidence — it remains
  Low/informational by design (V5-15 analog: Block 4 A15, Block 6 uses the same convention).
- Do not alert when the only available change event's type is `scope_upgraded`.

### Known blind spots (see `docs/evasion-limitations.md` for the adversarial framing)
- No invalidity evidence at all (no `authorization_change` event, no `valid_until`) — not
  detectable by construction (V6-01).
- A notification missing `mcp.subscription.id` still correlates via the principal-scoped join
  used for the revocation leg (V6-02) — but this same principal-only join is a **known,
  currently unresolved precision risk**: a principal holding two or more concurrent
  subscriptions, one revoked and one still legitimately valid, could have the still-valid
  subscription's notifications incorrectly matched against the other's revocation boundary.
  Tightening the join to also require `mcp.subscription.id` would remove that risk but would
  reintroduce the V6-02 blind spot for malformed telemetry. **This tradeoff is reported, not
  resolved, in this block** — see `docs/validation-report.md`, "remaining risks."
