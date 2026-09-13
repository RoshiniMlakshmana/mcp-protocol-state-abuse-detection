# Block 5 — MCP Security Detection Logic

Production-quality Sigma, KQL, and SPL detection logic for the three locked detection tracks
(`docs/threat-model.md`), built strictly on the locked Block 2 telemetry contract
(`telemetry/schema.md`) and validated against the locked Block 3 normal corpus (106 events, 13
scenarios) and Block 4 attack/control corpus (94 events, 18 scenarios). No new attack class,
telemetry field, or detection track is introduced here.

## Repository layout

```
detections/
  README.md              (this file)
  field-mapping.md        (exact field/placeholder-source reference used by every rule)
  sigma/
    mcp_task_routing_desynchronization.yml            Track 1 primary (single event)
    mcp_task_routing_missing_header_diagnostic.yml    Track 1 diagnostic (single event, low severity)
    mcp_cross_principal_task_authorization.yml        Track 2 primary (single event)
    mcp_subscription_notification.yml                 Track 3 component rule
    mcp_subscription_authorization_change_authoritative.yml  Track 3 component rule
    mcp_subscription_close.yml                        Track 3 component/hunting rule
    mcp_subscription_drift_correlation.yml            Track 3 BEST-EFFORT correlation (documented non-faithful)
  kql/
    mcp_task_routing_desynchronization.kql            Track 1 (+ optional diagnostic section)
    mcp_cross_principal_task_authorization.kql        Track 2
    mcp_subscription_authorization_drift.kql          Track 3 -- AUTHORITATIVE implementation
  spl/
    mcp_task_routing_desynchronization.spl            Track 1 (+ optional diagnostic section)
    mcp_cross_principal_task_authorization.spl        Track 2
    mcp_subscription_authorization_drift.spl          Track 3 -- AUTHORITATIVE implementation

tests/detections/
  corpus.js, oracle.js, metrics.js                    shared validation infrastructure
  metrics.test.js                                     TP/FP/TN/FN + precision/recall per rule
  sigma_structure.test.js                              Sigma YAML structural validation
```

## How to validate

```
node --test tests/detections/*.test.js
```

11 tests: corpus sanity, per-track confusion matrices with required-behavior spot checks, a
dedicated test that the Sigma correlation's *documented* limitations are exactly reproducible
(not just claimed), the combined A17 scenario, and Sigma YAML structural validation.

---

## Detection 1 — MCP Task Routing Header/Body Desynchronization

**Deployment prerequisite / applicability.** `mcp.validation.source = server_native` is the
highest-confidence case — the server itself, with plaintext access, performed the comparison.
A `collector_derived` verdict depends entirely on the collector performing correct
canonicalization (e.g., decoding a Base64-sentinel-encoded header before hashing, per
`telemetry/schema.md` §6 rule 5) — **a collector instrumentation failure can manufacture a
false conflict, and this must never be silently treated as adversary activity.** Block 6
(`docs/validation-report.md`, `docs/false-positive-analysis.md`) confirmed this concretely
(fixture V1-08): treat a `collector_derived` conflict as lower-confidence pending
`server_native` corroboration when triaging.

**What it detects.** A Streamable HTTP MCP request where the `Mcp-Method` or `Mcp-Name`
routing header (SEP-2243, MCP `2026-07-28`) carries a value that genuinely conflicts with the
corresponding JSON-RPC body field.

**Why it matters.** The `2026-07-28` specification requires servers to validate these headers
against the body precisely because intermediaries (load balancers, gateways, rate limiters) may
route or police traffic using the header alone while a downstream component executes on the
body. A real conflict is the exact condition under which two components can act on different
targets (`docs/threat-model.md` §9).

**Required telemetry.** `mcp.request.validation` event; `mcp.validation.method.result`,
`mcp.validation.name.result` (must be `conflict`, not `missing`/`malformed`/
`version_incompatible`); `mcp.validation.source` (confidence context only, never a gate).

**Logic.** `event.name = "mcp.request.validation"` AND
(`mcp.validation.method.result = "conflict"` OR `mcp.validation.name.result = "conflict"`).
One single-event rule; the missing/malformed case is a **separate, lower-severity diagnostic
rule** with its own file, never unioned into the primary result.

**Confidence/severity.** High for the primary (conflict) rule. Low for the diagnostic
(missing/malformed) rule — deliberately never promoted to the same severity, per the locked
requirement that a missing header must not be treated as equivalent to a conflicting one.

**Expected false positives.**
- Client/proxy implementation defects that mirror a stale header while the body carries current
  data.
- A migration-era client library partially implementing SEP-2243.
- A malformed request from a non-compliant client under active development — a real protocol
  violation, but not necessarily hostile.

**Limitations.**
- The rule trusts the pipeline's own pre-computed `mcp.validation.*.result`; it does not
  re-derive protocol-version gating itself. An upstream classification bug (e.g., mislabeling a
  genuinely compatible legacy request as `missing` instead of `version_incompatible`) would
  surface as a diagnostic-rule false positive, not a primary-rule one — see
  `telemetry/schema.md`/`docs/state-invariants.md` row 3.
- Cannot distinguish a deliberate probe from an accidental client bug from the wire evidence
  alone; both produce identical telemetry.

**Evasion opportunities.** `docs/threat-model.md` §14 already documents the main one: a client
that negotiates (or falsely claims) a pre-`2026-07-28` protocol version sheds the header
requirement entirely, since header validation is gated on negotiated version. An attacker who
can force or spoof a protocol-version downgrade could route a mismatched request without
tripping this rule at all — detecting that downgrade itself is out of scope for Track 1 (it
would be a distinct, protocol-negotiation-integrity concern, not a routing-desync one).

**Investigation fields.** `jsonrpc.request.id`, `mcp.header.method`/`mcp.body.method`,
`mcp.header.name_hash`/`mcp.body.identity_hash`, `mcp.validation.source`,
`mcp.validation.reason`, `trace_id` (if present).

**References.**
- https://modelcontextprotocol.io/specification/2026-07-28/basic/transports/streamable-http
- https://modelcontextprotocol.io/specification/2026-07-28/changelog
- https://modelcontextprotocol.io/specification/2026-07-28/basic/versioning

**MITRE ATT&CK.** None assigned. This detects a transport-envelope inconsistency equally
produced by a buggy client, a misconfigured intermediary, or a deliberate probe; no current
ATT&CK technique precisely describes header/body routing desynchronization at this protocol
layer. Forcing a loosely related tag would misrepresent the finding.

**Tested scenarios.** True positives: A1, A2, A3, A4, A5, A17 (Block 4). True negatives: all 13
Block 3 normal scenarios, A6 (compatibility control), A11 (reused Block 3 N6), and every other
Block 4 scenario that does not specifically exercise routing desync. Diagnostic rule: verified
not to fire on A6 or on any of the primary rule's true positives (mechanically distinct value
spaces); the corpus does not currently contain a scenario that exercises a genuine "missing
under a required version" case, which is documented as a corpus gap, not a rule defect.

**Novelty.** No public equivalent found during this project's research phase for this specific
detection shape (header/body value-disagreement telemetry keyed on the `2026-07-28` SEP-2243
header contract, which itself only exists because of that recent specification revision). This
is a narrow, protocol-version-specific statement, not a claim that header/body consistency
checking is a novel security idea in general.

---

## Detection 2 — MCP Cross-Principal Task Authorization Violation

**What it detects.** A server-side authorization denial for a task operation
(`tasks/get`/`tasks/update`/`tasks/cancel`/creation) where the denial reason specifically
records a principal/task-context mismatch.

**Why it matters.** SEP-2663 treats MCP task IDs as bearer-token-like credentials to
server-held state and mandates a per-request authorization check specifically because of this
risk. **This project does not claim to have discovered this risk class** — SEP-2663 itself
documents it, and it has been part of MCP Tasks security discussion since that extension was
proposed (`docs/threat-model.md` §10). This detection operationalizes an already-known,
spec-acknowledged risk into concrete, testable telemetry logic.

**Required telemetry.** `mcp.task.authorization` event; `mcp.authz.decision` (`deny`);
`mcp.authz.reason` (`principal_mismatch` specifically). `principal.id_hash`, `mcp.task.id_hash`,
`mcp.task.operation` for correlation/context. **`mcp.task.authz_context_id_hash` is never part
of the filter condition, in either direction** — per the Block 2 patch, its absence must never
suppress or trigger this rule; the server's own `decision`/`reason` fields are authoritative.

**Logic.** `event.name = "mcp.task.authorization"` AND `mcp.authz.decision = "deny"` AND
`mcp.authz.reason = "principal_mismatch"`. Deliberately excludes `policy_denied`,
`insufficient_scope`, `context_unbound`, and `unknown` — these are real denials but not
cross-principal task misuse. **Never** filters on `rpc.status_code` or
`http.response.status_code`: per SEP-2663's anti-enumeration design, a denied
existing-but-unauthorized task and a nonexistent task both typically surface the same `-32602`,
so a status-code-based rule could not distinguish this violation from an ordinary not-found
error at all.

**Confidence/severity.** High. The evidence required to fire is already an explicit,
disambiguated server-side statement of the violation — there is no lower-confidence variant of
this rule in this project, unlike Track 1 and Track 3, because Block 2 deliberately designed
`mcp.authz.reason` to remove the ambiguity a wire-only observer would otherwise face.

**Expected false positives.**
- Incorrect server-side policy configuration that denies (and mislabels as
  `principal_mismatch`) an access that should have been an explicit shared grant. Compare
  against any `authorized_grant`-reasoned allow for the same `mcp.task.id_hash` to spot this.
- Shared/delegated access implemented at the application layer but not correctly reflected in
  the authorization telemetry (the audit pipeline emitting `principal_mismatch` when the
  server's own business logic actually permits the delegation).
- A stale authorization context evaluated mid-transfer, if a task or grant is reassigned between
  principals at the exact moment a request races it.

**Limitations.** Entirely dependent on the emitting server correctly implementing and labeling
its own authorization decision. A server that denies for the right reason but mislabels
`mcp.authz.reason` (e.g. reports `unknown` instead of `principal_mismatch`) will produce a false
negative here that no wire-level signal could otherwise catch — this is an instrumentation
trust boundary, not a logic gap in the rule itself.

**Evasion opportunities.** None at the protocol level once server-side evidence is correctly
emitted — Track 2 exists precisely because Track 1 (routing) is clean in this attack class
(Block 4 A10's docstring: "why Track 1 alone is insufficient"). The only evasion surface is
against the *telemetry emission* itself: a server or audit pipeline that fails to emit
`mcp.task.authorization` at all for a given denial (an instrumentation gap) produces a blind
spot no rule can see through.

**Investigation fields.** `principal.id_hash`, `mcp.task.id_hash`,
`mcp.task.authz_context_id_hash`, `mcp.task.operation`, `mcp.authz.policy_version`, `trace_id`.

**References.**
- https://modelcontextprotocol.io/specification/2026-07-28/schema#headermismatcherror
- https://github.com/modelcontextprotocol/modelcontextprotocol/blob/main/seps/2663-tasks-extension.md
- https://modelcontextprotocol.io/seps/2663-tasks-extension

**MITRE ATT&CK.** `No precise ATT&CK technique assigned.` **(Re-evaluated in Block 7 —
correction from an earlier draft.)** Block 5 originally proposed `T1550.001` (Use Alternate
Authentication Material: Application Access Token) on the reasoning that SEP-2663 frames task
IDs as bearer-token-like credentials. On closer review this was withdrawn: in every scenario
this rule actually detects, the caller authenticates with their **own** legitimate
credentials — the violation is an *authorization*-boundary failure (accessing an object
identifier the caller is not entitled to), not an *authentication*-material failure (using
someone else's token/credential to authenticate as them), which is specifically what T1550.001
describes. The behavior detected here is closer to an IDOR-style object-authorization issue,
for which ATT&CK — a taxonomy of adversary behavior, not of application-security vulnerability
classes — has no precise technique. Per the standing instruction not to assign a technique
merely because a behavior sounds generally like credential access, no tag is assigned.

**Tested scenarios.** True positives: A7, A8, A9, A10, A17. True negatives: all 13 Block 3
normal scenarios (including N7's three benign-denial sub-cases: policy, insufficient-scope,
nonexistent-task), A11 (reused Block 3 N6 legitimate shared access), and every other Block 4
scenario.

---

## Detection 3 — MCP Long-Lived Subscription Authorization Drift

**Deployment prerequisite / applicability.** This high-confidence rule is appropriate **only**
where an authoritative `revoked`, `expired`, or `scope_downgraded` `effective_at` means the
subscription is genuinely no longer authorized to receive relevant notifications at and after
that instant. If an organization has grace periods, grandfathered/open-stream exemptions, or
other policy semantics that legitimately permit delivery after that timestamp, **the rule as
written will fire on that legitimate traffic** — this requires environment-specific tuning (a
query-level grace-period constant or exemption allowlist) or additional policy telemetry that
the locked Block 2 schema does not define. **No such field was added to solve this.** Block 6
confirmed this concretely (fixtures V5-02, V5-09) and reports it as a known, mechanically
verified operational-false-positive class in `docs/validation-report.md` View 2 — do not deploy
this rule as a paging alert without first accounting for any grace-period/exemption policy your
environment actually has.

**What it detects.** A `subscriptions/listen` notification delivered after the authorization
that justified the subscription became invalid (authoritative revocation or expiry), with no
valid stream closure in between.

**Why it matters.** `2026-07-28` made MCP stateless at the protocol level and treats
credentials as per-request input — but `subscriptions/listen` is architecturally a single,
very-long-lived request whose response stream never gets a fresh per-notification credential
check. Nothing in the spec (or the current official SDK's implementation, per
`docs/sdk-discrepancy.md`) forces a server to notice a mid-stream authorization change and close
the stream. Per `docs/threat-model.md` §11, an ordinary drifted `notifications/resources/updated`
exposes a change/activity signal (a URI), not necessarily protected content — **this detection
does not assert content disclosure**, only continued event visibility past the point authorization
ceased to be valid.

**Required telemetry.** `mcp.subscription.notification`, `mcp.subscription.authorization_change`
(`mcp.authz.change.effective_at`, `mcp.authz.change.timing_confidence`), `mcp.authz.valid_until`
(from `mcp.subscription.open`), `mcp.subscription.close`. Join keys: `mcp.subscription.id` and
`principal.id_hash` (the only field common to both subscription-scoped events and the
externally-sourced `authorization_change` event — Block 1 §5/§16).

**Logic (KQL/SPL — the authoritative implementation).** For each notification, find the
applicable authorization-invalidity boundary in strict preference order: (1) an authoritative
`mcp.authz.change.effective_at` for the same principal, (2) `mcp.authz.valid_until` on the
subscription's own open event when no authorization-change event exists at all (silent expiry),
(3) never fall back to `detected_at` alone for a high-confidence verdict. A notification is a
violation only if its timestamp is strictly after the chosen boundary **and** no
`mcp.subscription.close` event for that `mcp.subscription.id` exists at or before that
notification's timestamp.

**Confidence/severity.** High when the boundary is authoritative `effective_at` or a computable
`valid_until`. **Never high when only `detected_at` is available** — that case is a separate,
explicitly low-confidence/informational query, never merged into the primary result set.

**Expected false positives.**
- An inaccurate revocation `effective_at` reported by the authorization server (garbage-in,
  garbage-out — this detection trusts the value it is given).
- A deliberate, policy-defined grace period that legitimately allows an already-open stream to
  keep delivering non-sensitive notification types for a bounded window after a scope
  downgrade (`docs/threat-model.md` §13) — this detection has no built-in grace-period
  parameter; a deployment that has one must incorporate it before alerting (e.g., by comparing
  against `boundary + grace_period` rather than `boundary` directly).
- Clock skew or timestamp-quality issues between the system that reports `effective_at`/
  `valid_until` and the system that timestamps notifications.

**Limitations.**
- **The Sigma correlation cannot faithfully implement this detection** — see
  `detections/sigma/mcp_subscription_drift_correlation.yml`'s description and "Sigma
  limitations" below. KQL and SPL are the authoritative implementations for Track 3.
- Depends on an authorization-server/policy-engine push feed for the `effective_at` path,
  which most real OAuth deployments do not have (`telemetry/schema.md` §5) — this is why the
  `valid_until`/silent-expiry path exists as a fully independent detection leg, not a fallback
  bolted onto the revocation leg.
- The experimental `notifications/tasks`-with-inlined-result hypothesis (Block 4 A-EXP1) is
  detected by the same logic (it is still a drift condition) but its content-severity framing
  remains unvalidated — see `docs/threat-model.md` §11/§17 row 11a.

**Evasion opportunities.** A server that never emits `mcp.subscription.close` even when it
genuinely does stop delivering notifications would not itself cause a false negative (the
absence of further notifications means nothing to flag), but a compromised or malicious
component that suppresses `mcp.subscription.authorization_change`/`open`/`close` audit events
entirely (while the underlying MCP traffic continues) blinds this detection the same way it
would blind any audit-log-dependent control — an availability/integrity attack on the telemetry
pipeline itself, not a logic weakness in the query.

**Investigation fields.** `mcp.subscription.id`, `principal.id_hash`,
`mcp.subscription.notification_type`, `mcp.authz.change.type`/`source`, boundary type/time,
`trace_id`.

**References.**
- https://modelcontextprotocol.io/specification/2026-07-28/basic/patterns/subscriptions
- https://modelcontextprotocol.io/specification/2026-07-28/basic/authorization
- https://modelcontextprotocol.io/specification/2026-07-28/basic/authorization/security-considerations

**MITRE ATT&CK.** None assigned. This models a systemic authorization-propagation-delay
exposure window (a control gap), not a distinct adversary technique — an attacker does not need
to *do* anything beyond passively continuing to receive already-established stream data, which
does not map cleanly onto any ATT&CK technique (ATT&CK models adversary behavior, not defensive
control gaps).

**Tested scenarios.** True positives: A12 (authoritative revocation drift), A13 (silent expiry
drift, no revocation event at all), A14 (delayed observation — notification logged before the
change event, still caught because `effective_at` is used, not log order). True negatives: A15
(detected-only timing, correctly kept at low/no confidence), A16 (correct, prompt closure), and
all 13 Block 3 normal scenarios. Experimental: A-EXP1 (same logic fires; content-severity claim
kept separate and unvalidated, per above).

### Sigma limitations for Track 3 (verified, not assumed)

The current official Sigma correlation specification (verified against
`SigmaHQ/sigma-specification`, 2026-09-13) supports `temporal`/`temporal_ordered` correlation —
ordering and time-windowing matched events, grouped by equal field values — but has **no
mechanism to compare one event's field value (e.g. `effective_at`) against another event's own
timestamp, and no mechanism to assert the absence of a third event type**. Consequently, the
best-effort Sigma correlation (`mcp_subscription_drift_correlation.yml`) built from
`temporal_ordered` on the two available component rules:
- **Cannot detect A13 at all** (no `authorization_change` event exists for the correlation's
  first leg to match against).
- **Produces a false negative on A14** (`temporal_ordered` orders by each event's own log
  timestamp; the notification is logged at 10:12, before the change event is logged at 10:14,
  even though the change event's `effective_at` field, 10:10, proves 10:12 was already a
  violation).
- **Cannot verify the "no valid close before the notification" condition at all** (no
  negation/absence construct exists in the specification).

Of the three non-experimental true positives, this Sigma correlation correctly matches **only
A12** (`tests/detections/metrics.test.js`, "Sigma correlation (documented limitation)" test,
which independently reproduces exactly this true/false/false/false/false pattern across
A12–A16). Per the explicit Block 5 instruction not to weaken a detection to fit a language, this
gap is documented rather than papered over: the Sigma correlation, its two feeding component
rules, and a third hunting-only component rule (`mcp_subscription_close.yml`) are retained
because they remain useful for cross-platform hunting and because the specification is capable
of expressing *part* of the condition — but **KQL and SPL are the authoritative Track 3
implementations**, not this Sigma rule.

---

## Validation tooling used (honest account)

- **Corpus-based logic validation:** `tests/detections/*.test.js` (Node's built-in test
  runner), re-implementing each rule's actual filter/correlation logic in JS from the rule
  files themselves and running it against all 200 events across all 31 Block 3 + Block 4
  scenarios. This is the primary evidence of correctness in this project.
- **Sigma YAML structural validation:** `js-yaml` (parsing) plus hand-written structural checks
  against the specification requirements this project verified directly from
  `SigmaHQ/sigma-specification` (required fields, UUID format, enum values, correlation
  `rules:`/`group-by`/`timespan` shape, and that correlation references resolve to real
  component rule names).
- **What was NOT run, and why:** the official Sigma CLI / `pySigma` (including any
  `pySigma`-based backend conversion to KQL or SPL) requires Python, which is not available in
  this environment (`python`/`pip` both unresolved — verified, not assumed). No live Microsoft
  Sentinel workspace or Splunk instance was available either, so the KQL and SPL queries were
  not executed against real backend software; they were hand-written and hand-reviewed against
  the documented query-language semantics and against this project's own event schema, and
  their logic was independently re-validated by the JS oracle described above. **This project
  did not, and could not, run an automated Sigma→KQL/SPL conversion to compare against the
  hand-written rules.** Per the explicit instruction not to replace hand-reviewed KQL/SPL with
  blind conversions, this is stated as a limitation rather than worked around by fabricating a
  conversion run.

## Controlled-corpus results are not real-world performance claims

Every precision/recall figure in this project (see `tests/detections/metrics.test.js` output)
is computed against a small, deterministic, self-authored corpus built specifically to exercise
these three tracks' locked invariants. **These numbers validate implementation correctness
against known-labeled fixtures. They are not, and must not be cited as, an estimate of
real-world detection rate, false-positive rate, or prevalence** — a real deployment's telemetry
will contain traffic shapes, instrumentation gaps, and edge cases this corpus does not, and was
never designed to, represent.
