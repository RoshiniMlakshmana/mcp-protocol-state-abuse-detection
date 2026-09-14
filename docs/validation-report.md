# Block 6 — Detection Quality / Validation Report

Stress-testing report for the three locked MCP detection tracks. The goal of this block was
explicitly **not** to preserve perfect metrics — it was to find where the Block 5 rules break
and document that honestly. Two real issues were found and fixed; one further, unresolved
tradeoff was surfaced and is reported rather than papered over.

**Track 3 remediation pass (applied to this document and the codebase):** a follow-up review of
Track 3 found four further issues — two genuine code defects in `detections/spl/...spl`
(a join-key inconsistency with KQL, and reliance on Splunk's `join` `max=1` default), one
vacuous test (`tests/validation/language_equivalence.test.js`'s Track 3 "equivalence" test
compared one function's output to itself), and several discrepancies between the JS test oracle
and the actual KQL/SPL query logic. See "Track 3 remediation pass (this document's second
revision)" below for the full account; the corpus-size table, View 1/2 metrics, mutation table,
and language-equivalence section further down have all been updated to reflect the fixes and 11
new regression fixtures (V11-01..V11-11).

**Track 3 remediation pass, part 2 — scope-aware correction (this document's third revision):**
a second follow-up review found that part 1's fix, while correcting the SPL/KQL divergence and
the oracle's join-key/multi-boundary bugs, still let the revocation leg treat "same
`principal.id_hash`" as sufficient to scope a revocation. Verified against current MCP/OAuth
documentation, that is a genuine category error, not a stylistic one: a principal can hold
multiple independent, independently-revocable authorization bindings at once, a scope downgrade
removes specific permissions rather than blanket access, the wire `mcp.subscription.id` is
connection-scoped rather than globally unique, and a grant fingerprint is not a stable identity
across a token refresh. See "Track 3 remediation pass, part 2 (scope-aware correction)" below —
a new section, not a further edit of part 1's section, so both remediation passes remain
separately auditable. `telemetry/schema.md` and `telemetry/correlation.md` carry the full
citation trail and the corrected reference algorithm; the corpus-size table, View 1/2 metrics,
and language-equivalence section have been updated again to reflect six new project-defined
fields, a three-outcome (`confirmed_drift`/`evaluated_no_violation`/`insufficient_evidence`)
reporting model, 13 new regression fixtures (V12-01..V12-13), and two deliberate reclassifications
(V5-02, V11-05, V11-11 — retained, not deleted, and now correctly reported as
`insufficient_evidence` rather than a confirmed or accepted-false-positive drift).

**Post-hoc audit correction (applied to this document):** an earlier version of this report
presented a single "full stress-test corpus" precision/recall table showing FP=0 across the
board, while separately describing V1-08, V5-02, and V5-09 in prose as benign-but-firing
cases. Presenting one clean number and a separate prose caveat let the two coexist without
being reconciled — a real reporting inconsistency, not a data error. This document now
separates two questions that were previously blurred together into one number:

1. **Does the rule correctly implement its own declared trigger condition, given trustworthy
   inputs and no unmodeled deployment policy?** ("Controlled in-scope correctness" below.)
2. **Does the rule mechanically fire on traffic that is, in an actual deployment, entirely
   benign, because a declared prerequisite for view (1) doesn't hold?** ("Operational stress /
   environmental false-positive accounting" below.)

V1-08, V5-02, and V5-09 answer "yes" to question 2. They were never hidden from this project —
they are in the manifest with `false_positive_test: true`, documented in
`docs/false-positive-analysis.md`, and printed in Block 6's own console output — but they were
not surfaced with enough structural separation from the headline correctness numbers. This
version fixes that.

## Corpus sizes

| Corpus | Scenarios | Events | Purpose |
|---|---|---|---|
| Block 3 (normal) | 13 | 106 | Negative-test baseline |
| Block 4 (attack/control) | 18 | 94 | Positive/negative attack-class proof |
| **Curated core (3+4)** | **31** | **200** | The metrics reported at the end of Block 5 |
| Block 6 (validation/stress) | 61 | 285 | Adversarial-but-benign + boundary + evasion fixtures, incl. 11 join-key/multi-boundary regression fixtures (V11-01..V11-11) and 13 scope-aware-correction fixtures (V12-01..V12-13) |
| **Full stress-test corpus (3+4+6)** | **92** | **485** | This block's metrics |

All four corpora are deterministic (fixed logical clocks, fixed identifiers, fixed HMAC test
key) and regenerate byte-for-byte identically. Block 6's corpus lives under `data/validation/`
and was never merged on disk with Block 3 or Block 4.

## Deployment prerequisites (read before interpreting either metrics view below)

Both views below assume the rules are asked to do only what they are actually designed to do.
Each track has explicit prerequisites; violating one moves a scenario from "correctness" into
"operational false-positive" territory, not into "rule defect" territory.

**Track 1 prerequisite:** the primary rule assumes trustworthy routing-field parsing and
canonicalization upstream of the audit event. `mcp.validation.source = server_native` is the
highest-confidence case — the server itself, with full plaintext access, performed the
comparison. A `collector_derived` verdict is only as good as the collector's own
canonicalization (e.g., correctly decoding a Base64-sentinel-encoded header before hashing,
per `telemetry/schema.md` §6 rule 5). **A collector instrumentation failure can manufacture an
artificial conflict that the rule cannot distinguish from a real one, and this must never be
silently treated as adversary activity** — it is a data-quality problem to fix in the
collector, not evidence of an attack. See V1-08.

**Track 3 prerequisite:** the high-confidence rule is appropriate **only** where an
authoritative `revoked`, `expired`, or `scope_downgraded` `effective_at` means the subscription
is genuinely no longer authorized to receive relevant notifications at and after that instant.
If an organization has grace periods, grandfathered/open-stream exemptions, or other policy
semantics that legitimately permit delivery after that timestamp, **the rule as written will
fire on that legitimate traffic** — this is expected given the prerequisite is violated, not a
logic defect. Such deployments require environment-specific tuning (a query-level grace-period
constant or exemption allowlist) or additional policy telemetry the locked Block 2 schema does
not currently define. **No new schema field is added to solve this now** — see "Rule tuning
NOT performed" below. See V5-02, V5-09.

**Track 2 prerequisite:** the rule assumes the emitting server correctly labels
`mcp.authz.reason`. No environmental false positives were found for Track 2 in this block — its
enum-based evidence (`principal_mismatch` specifically) has no equivalent "grace period" or
"canonicalization" ambiguity — but see `docs/false-positive-analysis.md` for its own
instrumentation-trust dependency.

## View 1 — Controlled in-scope correctness metrics

**What this measures:** whether each rule fires exactly when its own declared trigger
condition is met, *given* the prerequisites above hold (trustworthy parsing/canonicalization
for Track 1; no unmodeled grace period or exemption policy for Track 3). Under that framing,
V1-08, V5-02, and V5-09 are **correctly firing** — each is a scenario where the declared
trigger condition is genuinely present (a real hash disagreement was recorded; a real
authoritative revocation with a later, unclosed notification occurred) — the prerequisite
violation is what makes them benign in a deployment, not what makes the rule's own logic wrong.

**This view answers "is the rule logic correct?", not "will this deployment ever see a benign
alert?"** — that second question is View 2, below.

### Curated core (31 scenarios) — unchanged from Block 5, re-verified post-fix

| Track | TP | FP | TN | FN | n | Precision | Recall |
|---|---|---|---|---|---|---|---|
| 1 | 6 | 0 | 25 | 0 | 31 | 1.000 | 1.000 |
| 2 | 5 | 0 | 26 | 0 | 31 | 1.000 | 1.000 |
| 3 (excl. experimental A-EXP1) | 3 | 0 | 27 | 0 | 30 | 1.000 | 1.000 |

### Full stress-test corpus (92 scenarios) — after both Track 3 remediation passes

| Track | TP | FP | TN | FN | n | Precision | Recall |
|---|---|---|---|---|---|---|---|
| 1 | 8 | 0 | 84 | 0 | 92 | 1.000 | 1.000 |
| 2 | 9 | 0 | 83 | 0 | 92 | 1.000 | 1.000 |
| 3 (excl. experimental A-EXP1) | 20 | 0 | 71 | 0 | 91 | 1.000 | 1.000 |

**These per-scenario TP/FP/TN/FN numbers collapse `track3PrimaryFires` to a boolean (fired iff
at least one `confirmed_drift` row exists) — they do NOT show how many notifications were
evaluable at all.** A scenario counted as a correct "TN" (true negative, expected3=false) is
indistinguishable in this table from one where every notification came back
`insufficient_evidence` rather than a positively-confirmed clean result. See "Track 3 coverage
report" below for that breakdown, computed separately for exactly this reason.

### Track 3 coverage report (part 2 addition) — confirmed / clean / insufficient, reported separately

Computed mechanically by `tests/validation/metrics.test.js`'s coverage test, over every
notification in the full stress corpus (excluding the experimental A-EXP1 scenario):

| Outcome | Count | Share |
|---|---|---|
| `confirmed_drift` | 26 | 49.1% |
| `evaluated_no_violation` | 20 | 37.7% |
| `insufficient_evidence` | 7 | 13.2% |
| **Total evaluated notifications** | **53** | 100% |

`insufficient_evidence` breakdown by reason: `missing_scope_evidence` (2), `no_invalidity_evidence`
(2), `ambiguous_scope` (1), `conflicting_evidence` (1), `incompatible_hash_epoch` (1). **This
13.2% is not a defect to be minimized to zero** — it is the correction working as intended: every
one of these seven notifications previously either mechanically fired (a false positive risk) or
mechanically cleared (a false negative risk) under principal-only or scope-blind logic, and now
honestly reports that the telemetry available does not support a confident answer either way.

**These numbers are controlled-corpus implementation-correctness metrics, evaluated under the
declared prerequisites above. They are NOT real-world precision/recall and must never be cited
as an estimate of real-world detection rate, false-positive rate, or attacker prevalence.**
They confirm the rules behave as intended against a small, self-authored, deterministic set of
known-labeled fixtures — nothing more. Critically, **a perfect score in this view does not mean
zero benign alerts in a real deployment** — see View 2.

## View 2 — Operational stress / environmental false-positive accounting

**What this measures:** which benign scenarios cause a rule to mechanically fire once a
declared prerequisite is violated or unavailable — the false positives an actual deployment
could see, surfaced explicitly rather than folded into a clean precision number.

Computed mechanically, not asserted in prose, by
`tests/validation/operational_fp_accounting.test.js`: every Block 6 scenario flagged
`false_positive_test: true` in the manifest is checked against the actual rule output; any that
still fires is listed below.

| Scenario | Rule fires? | Benign? | Root cause | Rule defect? | Deployment prerequisite/tuning |
|---|---|---|---|---|---|
| V1-08 | Track 1 = true | Yes | Collector hashed the `Mcp-Name` header's raw Base64-sentinel string without decoding it first, producing an artificial hash mismatch for an identical underlying taskId | **No** — the rule correctly reacts to the (wrong) input it was given; the defect is in the collector's canonicalization step, not the rule | Fix the collector to decode before hashing (`telemetry/schema.md` §6 rule 5); until fixed, treat `collector_derived` conflicts as lower-confidence pending `server_native` corroboration |
| V5-02 | Track 3 = true | Yes | Notification delivered 3 minutes after an authoritative `scope_downgraded` change, inside a hypothetical deployment-defined 5-minute grace period | **No** — a genuine authoritative revocation with a later, unclosed notification is exactly the rule's declared trigger; no grace-period field exists in the locked schema for the rule to consult | Add a deployment-side grace-period constant to the query (`WHERE notif_time > boundary + grace_period`); do not add a schema field for this |
| V5-09 | Track 3 = true | Yes | Deployment has a permanent policy exemption allowing an already-open stream to continue after revocation (e.g., a legacy compatibility mode) | **No** — same reasoning as V5-02; no exemption/allowlist field exists in the locked schema | Maintain a deployment-side allowlist (by principal or `policy_version`) as a suppression rule downstream of this detection |

**Excluded from this table on purpose: V3-02.** It also carries `false_positive_test: true` and
also mechanically fires (`Track 2 = true`), but for a different reason: the file contains a
**genuine historical violation event** (denied under `policy-v1`) alongside a later, unrelated
benign allow (`policy-v2`) in the same fixture. The fire is correct because a real violation
genuinely occurred at that time — it is not an artifact of a violated prerequisite, and
including it in the operational-false-positive table would misrepresent a true positive as a
false one. `tests/validation/operational_fp_accounting.test.js` asserts this distinction
per-event, not just in prose.

**Why V1-08/V5-02/V5-09 are not folded into View 1's precision calculation:** the locked Block 2
schema cannot currently model "this collector's canonicalization is untrustworthy" or "this
deployment has a grace period / exemption policy" as first-class telemetry the rule could
consult. Counting them as false positives in View 1 would conflate "the rule's own logic is
wrong" with "the rule was asked a question its available telemetry cannot answer" — two
different problems requiring different fixes (rule tuning vs. collector fix vs. deployment
configuration). View 2 exists specifically so this distinction is never lost, and so these
three scenarios remain visible as **known operational false-positive risks** rather than
disappearing into a clean number.

## False positives discovered

This section gives the narrative/root-cause detail behind each finding; the operational-impact
table for the three that remain live risks is View 2 above, not repeated here.

### 1. V5-03 — Track 3 misclassified a legitimate renewal as a revocation (FIXED — a genuine rule defect, distinct from the operational false positives in View 2)

- **Symptom:** a subscription's authorization was legitimately *renewed*
  (`mcp.authz.change.type = scope_upgraded`, `timing_confidence = authoritative`) before
  expiry, followed by a normal notification. The Track 3 rules fired anyway.
- **Root cause:** none of the Track 3 implementations (Sigma component rule, KQL, SPL, or the
  shared JS test oracle `tests/attack/track3util.js`) ever inspected `mcp.authz.change.type`.
  Any authoritative change event was treated as an invalidating boundary, regardless of whether
  it represented a revocation or an expansion of access.
- **Decision:** tuned. This does not touch any locked Block 1/2 telemetry field or invariant —
  it only restricts which *existing* enum value (`mcp.authz.change.type`) the query treats as
  meaningful, which is squarely a Block 5 rule-logic decision.
- **Fix:** restrict the invalidating-boundary check to
  `mcp.authz.change.type ∈ {revoked, expired, scope_downgraded}`, explicitly excluding
  `scope_upgraded`. Applied identically to all four artifacts (Sigma component rule's
  `detection.selection`, KQL's `AuthoritativeChanges`/`DetectedOnlyChanges` filters, SPL's
  equivalent `search` filters, and the JS oracle).
- **Before/after:** pre-fix, V5-03's oracle result was `{fired: true, confidence: "high"}`
  (wrong). Post-fix: `{fired: false, confidence: "high", boundaryUsed: "valid_until"}` (correct
  — it falls through to the non-violating expiry check, since the notification is well before
  `valid_until`).
- **Regression check:** all 101 tests across Blocks 3–6 pass post-fix; A12/A13/A14 (the three
  non-experimental curated-core true positives) are unaffected.

### 2. V5-02 (grace period) and V5-09 (permanent policy exemption) — operational false positives, NOT fixed

Both mechanically fire under the current rules (`fired: true`), and both manifest rows record
`expected_detection_track_3: true` (View 1's "correctness" ground truth — the rule is doing
exactly what it declares it will do). **In View 2 terms, both are true operational false
positives**: benign traffic that fires because the Track 3 prerequisite ("no unmodeled grace
period or exemption policy") is violated. The locked Block 2 schema has no field for a
grace-period duration or a permanent-exemption allowlist. Per the explicit instruction not to
alter a locked invariant or fabricate a field to chase a perfect scorecard, these remain
**known, reported operational false-positive risks requiring deployment-side suppression** (a
query-level constant or allowlist applied downstream of this detection), not defects in the
shared rule logic. See `docs/false-positive-analysis.md` and View 2's table above.

### 3. V1-08 — collector canonicalization gap (operational false positive; not a rule defect)

A collector that hashes a Base64-sentinel-encoded `Mcp-Name` header without decoding it first
(violating `telemetry/schema.md` §6 rule 5) produces an artifactual `conflict` for two values
that are actually identical. The Track 1 rule correctly reacts to the (wrong) input it is
given; there is no rule-layer fix, since the rule has no access to the raw values to redo
canonicalization. A true operational false positive per View 2 above; documented as an
instrumentation dependency in `docs/false-positive-analysis.md`, not counted as a rule tuning
item.

## False negatives discovered

None in the final (post-fix) full stress-test corpus. Two *documented, expected* blind spots
were confirmed to behave exactly as designed rather than accidentally over-fire:
- **V5-06** (clock skew): the rule correctly does not fire, because the (skewed) `effective_at`
  it is given is after the notification — this is a real, honest limitation of timestamp-based
  detection across unsynchronized clocks, not a logic bug (`docs/evasion-limitations.md`).
- **A15 / V5-15-equivalent detected-only cases**: correctly never promoted to a high-confidence
  finding, by design (locked timing-confidence model).

## Telemetry gaps identified (schema-level, not fixed — out of scope for rule tuning)

1. No field represents a grace-period duration or policy-defined exemption (drives the V5-02
   and V5-09 operational false positives in View 2 above).
2. No field distinguishes "collector observed and correctly canonicalized" from "collector
   observed but may have mis-canonicalized" beyond the existing `mcp.validation.source`
   (server_native/collector_derived) — a finer confidence gradient was considered but not
   implemented (see "Rule tuning NOT performed" below).
3. Block 2's own controlled-overlap key-rotation guidance (`telemetry/schema.md` §6) has no
   corresponding schema mechanism (e.g., a "previous-epoch hash" field) — a deployment wanting
   to implement controlled overlap during rotation would need to define such a field itself.
   Documented, not fixed (would require a schema change, out of scope).

## Rule tuning NOT performed (considered, deliberately deferred)

- **Severity differentiation by `mcp.validation.source`** for Track 1 (server_native vs.
  collector_derived). Identified as a reasonable future enhancement during the V1-08 analysis,
  but it is an enhancement to alert *confidence*, not a correctness bug — implementing it was
  deliberately deferred to keep this block's one in-scope fix (V5-03) isolated and clearly
  attributable, per the instruction to tune only what a validation failure actually justifies.
- **Tightening the Track 3 authoritative-change join to also require `mcp.subscription.id`**
  (would remove the multi-subscription cross-correlation risk found via V6-02, but would
  reintroduce the V6-02 blind spot for malformed telemetry). This is a genuine, currently
  unresolved precision/recall tradeoff — reported below under "remaining risks," not resolved
  by picking a side unilaterally in this block.

## Mutation-testing results (V10)

Seven deliberate, in-memory-only mutations (`tests/validation/mutation.test.js`) were run
against the full stress corpus. No rule file under `detections/` was ever modified — each
mutation is a standalone JS predicate. All seven were caught (each introduced at least one new
FP or FN relative to the correct implementation):

| Mutation | Correct FP/FN | Mutated FP/FN | Caught? |
|---|---|---|---|
| Track 1: `==` instead of `!=` (fires on match, not conflict) | 0 / 0 | 34 / 1 | Yes |
| Track 1: missing headers alert as mismatch | 0 / — | 1 / — | Yes |
| Track 2: any `deny` fires (drops reason check) | 0 / — | 3 / — | Yes |
| Track 2: any `mcp.task.authorization` event fires (drops decision check) | 0 / — | 19 / — | Yes |
| Track 3: `detected_at` used instead of `effective_at` | — / 0 | — / 5 | Yes |
| Track 3: close-suppression check removed | 0 / — | 58 / — | Yes |
| Track 3: `mcp.authz.change.type` filter removed (reintroduces V5-03) | 0 / — | 59 / — | Yes |

(Counts grew alongside the corpus after the two Track 3 remediation passes added 11 + 13 regression
fixtures; re-run `node --test tests/validation/mutation.test.js` rather than assuming these
exact numbers stay fixed across future corpus changes.)

The last row is a direct, mechanical demonstration that this validation suite would have caught
the V5-03 regression had it not already been fixed — the mutation test literally reconstructs
the pre-fix logic and confirms it produces exactly the class of false positive V5-03 exposed.

## Language-equivalence findings (V9)

**Correction (Track 3 remediation pass):** the Track 3 "KQL and SPL are mutually equivalent"
test in a prior revision of this suite called `track3PrimaryFires` twice on the same input and
asserted the result equal to itself — a tautology that could never fail and verified nothing.
It has been replaced with two **independently-coded JS models**, `kqlModelResults` and
`splModelResults`, each implementing the CORRECTED, scope-aware binding-resolution algorithm
independently (different data structures, different code shape — see the file's own header
comment), compared by **outcome per notification** (`confirmed_drift`/`evaluated_no_violation`/
`insufficient_evidence`, not just a fired/not-fired boolean) across the full stress corpus.
**This disclaimer applies throughout this section: neither model executes actual KQL or SPL, and
neither runs against a real Sentinel/Splunk backend — "equivalent" means "these two
independently-authored models of each language's documented semantics agree," which is the
strongest claim achievable without native execution (still pending; see README.md).** Both
models share the same documented simplification as the real KQL/SPL queries: binding-candidate
membership is approximated as "ever observed for this principal," not precisely
interval-bounded — see the KQL file's header comment for the full rationale.

A third model, `preCorrectionModelResults`, reconstructs the **pre-scope-correction** behavior
(principal-only join, no binding/scope awareness at all — this is part 1's corrected-but-still-
principal-scoped model) purely to prove the new regression corpus actually exercises the
scope-aware correction — it must, and does, diverge from the corrected model on V11-11 and the
V12 fixtures designed to expose exactly this gap.

| Track | Sigma vs. KQL vs. SPL | Verified how |
|---|---|---|
| 1 | Fully equivalent across all 92 stress-corpus scenarios | `tests/validation/language_equivalence.test.js` — three independently-written JS predicates mirroring each language's literal filter, zero disagreements |
| 2 | Fully equivalent across all 92 stress-corpus scenarios | Same method, zero disagreements |
| 3 | **The independently-coded KQL-model and SPL-model outcomes agree on every notification across all 92 stress-corpus scenarios. Sigma is NOT equivalent — retained only as a documented, deliberately incomplete correlation.** | Per-notification outcome comparison, not a boolean; see matrix below for the Sigma comparison |

### Track 3 Sigma-vs-authoritative comparison matrix (curated core, non-experimental)

| Scenario | KQL/SPL (authoritative) | Sigma correlation | Agree? |
|---|---|---|---|
| A12 | true | true | yes |
| A13 | true | **false** | **NO** |
| A14 | true | **false** | **NO** |
| A15 | false | false | yes |
| A16 | false | false | yes |

Sigma's `temporal_ordered` correlation type has no mechanism to compare a field value
(`effective_at`) against another event's own log timestamp, and no mechanism to assert the
absence of a third event type (a valid close) — confirmed against the current official Sigma
correlation specification (`SigmaHQ/sigma-specification`) during Block 5 and re-verified here
by mechanically reproducing exactly this true/false/false/false/false pattern
(`tests/validation/language_equivalence.test.js`). This is unchanged by the Block 6 type-filter
fix (the fix corrected a *value-comparison* bug present identically in all three languages'
authoritative-change component logic; it does not touch the ordering/absence limitations that
are specific to Sigma's correlation model).

## Deployment assumptions (carried forward, reaffirmed)

- The MCP server/audit pipeline correctly implements Block 2's `mcp.validation.*`,
  `mcp.authz.*`, and `mcp.subscription.*` semantics as documented — every finding in this
  report assumes correct instrumentation except where the finding is specifically *about* an
  instrumentation gap (V1-08, V6-02).
- Clocks across the authorization server and MCP server are reasonably synchronized (NTP or
  equivalent) — Track 3 has no compensation mechanism for skew (V5-06).
- A deployment wanting grace periods or permanent exemptions implements them as query-layer
  constants/allowlists downstream of these rules, not by expecting the base rules to know about
  deployment-specific policy.

## Track 3 remediation pass (this document's second revision)

A follow-up review of Track 3 (after the original Block 6 pass above) found four further issues
and requested regression coverage for eleven specific scenarios. Applied directly to this
repository — no ZIP/patch workflow, Tracks 1 and 2 untouched, original Block 3/Block 4 corpora
byte-identical on regeneration.

### Code defects fixed

1. **SPL expiry-leg join key inconsistent with KQL.** `detections/spl/mcp_subscription_authorization_drift.spl`'s
   silent-expiry leg previously joined `Notifications` to the open-event subsearch on
   `subscription_id` alone; KQL's equivalent (`ExpiryBoundaries`) already correctly joined on
   `subscription_id, principal_hash`. Fixed by retaining `principal.id_hash` through the SPL
   open-event subsearch (renamed to `principal_hash`) and changing the join to
   `join type=inner max=0 subscription_id principal_hash [...]`. Classification: **code defect**
   (SPL/KQL divergence, not a design choice). Proven by fixture V11-02 (see below).
2. **SPL inner joins relied on Splunk's `join` `max=1` default.** Every `join type=inner`
   subsearch in the SPL file (authoritative-revocation leg, silent-expiry leg, and the
   informational detected_only search) now explicitly sets `max=0`, so every applicable matching
   row is preserved instead of silently keeping only the first. The aggregated close-suppression
   joins (`join type=left ... [stats min(close_time) ... by subscription_id, principal_hash]`)
   are deliberately left at the default, per instruction, since the `stats min(...)` subsearch
   already collapses to at most one row per key — there is nothing for `max=0` to preserve there.
   Classification: **code defect**. Proven by fixture V11-01 (see below).
3. **Close-suppression join scoped by `subscription_id` alone (KQL and SPL, and the JS oracle).**
   `mcp.subscription.id` is only a per-connection JSON-RPC request id (Block 1 SS7) and is not
   guaranteed globally unique across different principals' connections. Fixed by requiring
   `principal.id_hash` in addition to `subscription_id` on the close-suppression join in
   `detections/kql/mcp_subscription_authorization_drift.kql`,
   `detections/spl/mcp_subscription_authorization_drift.spl`, and
   `tests/attack/track3util.js`. `principal.id_hash` is a required field on
   `mcp.subscription.close` (`telemetry/schema.md`) and confirmed present in real generated
   fixtures — this uses existing telemetry, it does not invent a new field. Classification:
   **code defect**. Proven by fixture V11-02.
4. **JS test oracle discrepancies vs. the actual KQL/SPL queries** (`tests/attack/track3util.js`):
   the oracle required an `mcp.subscription.open` event to exist even though the revocation
   leg's real KQL/SPL join never depends on one; used `.find()` (first match only) instead of
   iterating every applicable `authorization_change`/`open` event; and evaluated the revocation
   and expiry legs as an if/else-if chain that stopped at the first non-empty leg instead of two
   independent legs unioned together (matching KQL's `union` / SPL's `append`). All three fixed;
   `computeTrack3Verdict` is now a backward-compatible scalar wrapper over a new
   `computeTrack3AlertRows(events)` that returns every independent alert row, enabling row-level
   (not just boolean) test assertions. Classification: **code defect**. Proven by fixtures
   V11-01, V11-03, V11-04, V11-05.

### Validation gap withdrawn

5. **Vacuous Track 3 "language equivalence" test.** See "Language-equivalence findings (V9)"
   above — the test called one function twice and asserted the tautology. Replaced with two
   independently-coded models compared row-for-row, with an explicit disclaimer that neither
   executes native KQL/SPL. Classification: **validation gap**, now closed to the extent
   achievable without native execution (still pending).

### New regression fixtures (V11-01..V11-11, `data/validation/track3/v11_*.jsonl`)

| ID | Scenario | Fires? | What it proves |
|---|---|---|---|
| V11-01 | Multiple authorization changes, future boundary emitted before an earlier valid one | Yes (3 rows total) | Iterates every applicable change by field value, not stream order or first-match |
| V11-02 | Same subscription_id, different principals (+ one closes their own subscription) | Yes (1 row, Alice only) | Revocation-leg principal-only join is correct; close-suppression correctly requires principal_hash too |
| V11-03 | Revocation and expiry both applicable to one notification | Yes (2 rows) | Both legs evaluated independently and unioned, not short-circuited |
| V11-04 | Expiry precedes a later-recorded, future revocation | Yes (1 then 2 rows) | Leg independence holds regardless of which boundary is chronologically or causally "discovered" first |
| V11-05 | Revocation with no retained open event | Yes (1 row) | Revocation leg does not require an `open` event to exist |
| V11-06 | Close on another subscription (same principal) | Yes (1 row) | Close-suppression correctly requires subscription_id too (opposite direction from V11-02) |
| V11-07 | Close exactly at notification time | No | Inclusive close-boundary convention (`close_time <= notif_time` suppresses) |
| V11-08 | Notification exactly at valid_until | No | Exclusive invalidation-boundary convention, expiry-leg variant of V5-05 |
| V11-09 | Scope upgrade, no expiry reached | No | `scope_upgraded` never leaks into either leg |
| V11-10 | Multiple (duplicate) close events | Yes (1 row, before the closes) | Close suppression is an "any close at/before" check, robust to duplicate close rows |
| V11-11 | Same-principal cross-subscription correlation risk | Yes (1 row, mechanically) | Documents the KNOWN, UNRESOLVED scope boundary below — not silently fixed |

Row-level assertions (exact expected rows, not just fired/not-fired booleans) are in
`tests/validation/track3_row_regression.test.js`. That file also includes two
"RESTORED-BUG PROOF" tests that reconstruct the pre-fix buggy behavior independently and show it
would have produced a different (wrong) result on V11-01 and V11-02 — direct evidence that this
regression suite would catch a reintroduction of either the join-key bug or the one-match bug.

### Scope boundary confirmed in this pass, then ACTUALLY FIXED in part 2 below

**Same-principal, multiple concurrent subscriptions on the revocation leg** (previously listed
as "remaining risks" item 1 below, based on reasoning alone) was **empirically demonstrated** by
fixture V11-11 in this pass: a principal with two concurrent subscriptions, one revoked, had the
*other, still-valid* subscription's notification mechanically fire, because
`mcp.subscription.authorization_change` carries no subscription id to disambiguate. At the time,
this was reported as an unresolved scope boundary, correctly not "fixed" by tightening the join
to `subscription_id` (which would have reintroduced the V6-02 blind spot) or by inventing a
subscription-id field that does not exist. **This limitation is superseded by "Track 3
remediation pass, part 2" immediately below**, which adds `mcp.authz.binding_id` and
`mcp.authz.change.affected_scope`/`affected_binding_ids` — fields that resolve the SAME
ambiguity without requiring a subscription-id field on `authorization_change` events at all. See
fixture V12-13 for the corrected counterpart. V11-11 itself is retained, unmodified, as a
worked example of what a deployment emitting only pre-correction telemetry still cannot resolve.

## Track 3 remediation pass, part 2 (scope-aware correction)

A second follow-up review of Track 3 found that part 1's fix — while correcting the SPL/KQL
join-key divergence and the oracle's multi-boundary bugs — left the revocation leg's fundamental
design unchanged: "same `principal.id_hash`" was still being treated as sufficient to scope a
revocation to a subscription. This section documents the fix. Applied directly to this
repository, no ZIP/patch workflow, Tracks 1 and 2 untouched.

### The four verified gaps

Each claim below was checked against current, official MCP and OAuth documentation before
implementation (not assumed):

1. **Principal identity alone does not establish revocation scope.** OAuth token revocation
   (RFC 7009) scopes revocation to "a particular token"; cascading to related tokens/grants is
   explicitly a **server-policy choice**, never automatic. A principal can hold multiple
   independent, independently-revocable bindings at once.
2. **A scope downgrade does not necessarily remove permission for a given subscription.** MCP's
   authorization page (`.../basic/authorization`) requires servers to reason about scope
   hierarchies **per operation** — scope is a set of independent permission strings, not a single
   on/off switch for an entire grant.
3. **A wire subscription/request ID is not a globally unique stream incarnation.** MCP's
   subscriptions pattern (`.../basic/patterns/subscriptions`) defines `mcp.subscription.id` as
   literally the `subscriptions/listen` request's own JSON-RPC `id` — connection-scoped, and
   explicitly NOT preserved across a reconnect ("the server holds no subscription state across
   reconnections").
4. **An authorization snapshot hash is not automatically a stable grant identifier.** OAuth token
   refresh (RFC 6749 §6) issues a new token value for what is conventionally the same
   grant/session — a content fingerprint (`mcp.authz.grant_snapshot_hash`) changes whenever any
   attribute changes and cannot serve as an identity/join key across a legitimate refresh, scope
   change, or renewal.

### New project-defined telemetry fields (minimum necessary, see `telemetry/schema.md` §5)

| Field | Event types | Purpose |
|---|---|---|
| `mcp.subscription.instance_id` | `.open`, `.acknowledged`, `.notification`, `.close` | The authoritative Track 3 join key — a globally unique stream incarnation, not the connection-scoped wire `mcp.subscription.id` |
| `mcp.authz.binding_id` | `.open` (required); `.notification` (optional — proof of rebinding) | The stable authorization binding backing an instance, issued by the authorization system itself — never a content fingerprint |
| `mcp.subscription.required_scope` | `.open` | The scope tag(s) this instance's continued delivery actually depends on |
| `mcp.authz.change.affected_scope` | `.authorization_change` | `binding` \| `all_principal_bindings` \| `unknown` — the RESOLVED scope of a change; `all_principal_bindings` is the only value permitted to broaden past named bindings |
| `mcp.authz.change.affected_binding_ids` | `.authorization_change` | The specific binding(s) a `binding`-scoped change invalidates |
| `mcp.authz.change.removed_scope` | `.authorization_change` | The specific scope tag(s) a `scope_downgraded` change removes, compared against `required_scope` for relevance |

**A pre-existing documentation defect was also fixed**: `telemetry/schema.md` previously listed
`.authorization_change` among the event types carrying `mcp.subscription.id`, while
`telemetry/correlation.md` and every actual generator/rule/oracle correctly modeled that event
as carrying no subscription reference at all. The field table now matches the (always correct)
implementation.

**Legacy-compatibility fallbacks** (a deployment need not emit all-new fields on day one; see
`telemetry/schema.md`/`telemetry/correlation.md` for the precise rules): missing `instance_id` →
`principal_hash + ":" + subscription_id` (principal-scoped, not bare subscription_id — see the
V11-02 fix below); missing `binding_id` on `.open` → an internal pseudo-binding scoped to
`(principal_hash, subscription_id)`, usable only when it is the *sole* candidate for that
principal; missing `affected_scope` → `"unknown"` (sole-candidate fallback only, **never** a
blanket principal-wide assumption).

### The reference algorithm and three-outcome reporting

Implemented identically (by design — the SPL file is a direct structural port of the KQL file
for this pass, not an independent re-derivation) in `detections/kql/mcp_subscription_authorization_drift.kql`
and `detections/spl/mcp_subscription_authorization_drift.spl`, and independently re-implemented
in `tests/attack/track3util.js` (`computeTrack3Resolution`). Full description:
`telemetry/correlation.md` "Resolving affected bindings" / "Three-outcome reporting". Summary:

- A `binding`-scoped change applies only to its named `affected_binding_ids`.
- An `all_principal_bindings`-scoped change applies to every binding observed for that principal
  — the only path allowed to broaden past a specific binding, and it must be explicit.
- An `unknown`/legacy change applies via the **sole-candidate fallback**: if exactly one binding
  is known for that principal, resolve to it (elimination, not a guess); if more than one, report
  `insufficient_evidence` for all of them; if none, the change produces no finding unless a
  notification directly and explicitly proves its own matching binding.
- A `scope_downgraded` change additionally requires `removed_scope` to intersect the instance's
  `required_scope`; either missing is `insufficient_evidence`, never a default in either
  direction.
- Every evaluated notification is checked against the binding it actually carries (or its
  instance's open-time binding) — never "whatever is currently valid for this principal
  elsewhere" — so a proven rebinding (a later notification with a new, valid `binding_id`)
  correctly escapes an old binding's later expiry, while an unrelated new binding existing
  elsewhere never retroactively clears an old binding's real violation.
- Every result is exactly one of `confirmed_drift` / `evaluated_no_violation` /
  `insufficient_evidence` (see "Track 3 coverage report" above).

**Documented KQL/SPL-only simplification**: the "was this binding open as of the change's
`effective_at`" temporal restriction is approximated as "this binding is ever observed for this
principal in the queried window," not precisely interval-bounded — expressing arbitrary
as-of-timestamp interval membership per change event in one set-based query is impractical
without per-row scalar subqueries. The JS oracle remains the precise authority; this is a KNOWN,
DOCUMENTED gap, analogous to the pre-existing, documented Sigma limitations for this track.

### A real bug the new regression corpus caught before merge

Building `tests/validation/language_equivalence.test.js`'s two independently-coded KQL/SPL
models surfaced a genuine defect in the FIRST draft of the `instance_id` legacy fallback: it
defaulted to the bare `mcp.subscription.id`, which let fixture V11-02 (two different principals
legitimately reusing the identical wire id) collide onto one synthetic instance, silently
borrowing one principal's open record for the other's notification. Fixed by scoping the
fallback to `principal_hash + ":" + subscription_id` in the JS oracle, the KQL file, the SPL
file, and both schema documents, before this pass was committed — exactly the kind of defect the
"two independent models must agree" methodology (`docs/validation-report.md`'s own stated
purpose for Block 6) exists to catch.

### New regression fixtures (V12-01..V12-13)

| ID | Scenario | Outcome |
|---|---|---|
| V12-01 | Same principal, A revoked / B allowed | A: `confirmed_drift`; B: `evaluated_no_violation` |
| V12-02 | Explicit shared-grant revocation, two instances one binding | Both `confirmed_drift` |
| V12-03 | Unrelated scope removed | `evaluated_no_violation` |
| V12-04 | Required scope removed | `confirmed_drift` |
| V12-05 | Same wire id across tenants/reconnects | Revoked tenant: `confirmed_drift`; other: `evaluated_no_violation` |
| V12-06 | Old binding expires after proven valid replacement | `evaluated_no_violation` |
| V12-07 | New unrelated authorization doesn't suppress old-binding violation | `confirmed_drift` |
| V12-08 | Out-of-order arrival, trustworthy effective-time evidence | `confirmed_drift` |
| V12-09 | Missing scope evidence (downgrade) | `insufficient_evidence` |
| V12-10 | Conflicting evidence (revoked + scope_upgraded, same binding) | `insufficient_evidence` |
| V12-11 | Incompatible hash epoch | `insufficient_evidence` |
| V12-12 | Directly scoped invalidation, no retained open event | `confirmed_drift` |
| V12-13 | Corrected counterpart to V11-11 | Named binding: `confirmed_drift`; other: `evaluated_no_violation` |

Row-level assertions: `tests/validation/track3_row_regression.test.js`. Two prior fixtures were
deliberately reclassified rather than deleted or silently excluded:

- **V5-02** (scope-downgrade grace period): previously an "accepted false positive" (mechanically
  fired, `confirmed_drift`). Now `insufficient_evidence` — no `required_scope`/`removed_scope`
  evidence exists in this legacy-shaped fixture to establish relevance, so the honest answer is
  "cannot determine," not "fires but we forgive it."
- **V11-05** and **V11-11**: retained, event content unmodified, both reclassified from
  `confirmed_drift` (via the old principal-only join) to `insufficient_evidence` (ambiguous or no
  known binding). Both remain in the manifest and in every metrics/coverage count — see
  `tests/validation/metrics.test.js` and the coverage report above.

## Remaining risks (unresolved, explicitly not decided in this block)

1. **RESOLVED in "Track 3 remediation pass, part 2" above.** Track 3's principal-only join for
   the authoritative/detected_only legs (required to keep V6-02-style malformed telemetry
   detectable) could, for a principal holding two or more concurrent subscriptions where only one
   is revoked, cross-correlate the still-valid subscription's notifications against the other's
   revocation boundary — empirically demonstrated by fixture V11-11. This is fixed via
   `mcp.authz.binding_id` and `mcp.authz.change.affected_scope`/`affected_binding_ids`, which
   resolve scope without requiring a subscription-id field on `authorization_change` events
   (V11-11's own shape, which lacks these new fields, correctly remains `insufficient_evidence`
   rather than either a false confirm or a silently-invented fix — see fixture V12-13 for the
   resolvable counterpart). **New residual risk introduced by the fix itself**: a deployment that
   never upgrades its instrumentation to emit the new binding/scope fields gets no benefit from
   this correction and will continue to see ambiguous-scope notifications reported as
   `insufficient_evidence` rather than a resolved answer — a deployment prerequisite, not a
   rule defect (see "Track 3 coverage report").
2. **Collector canonicalization dependency (V1-08)** has no rule-layer mitigation; only
   upstream instrumentation correctness prevents it.
3. **Severity-by-`mcp.validation.source` differentiation** for Track 1 remains an open,
   reasonable enhancement, deliberately not implemented this block.
4. **KQL/SPL binding-candidate temporal approximation** ("Track 3 remediation pass, part 2"
   above): the sole-candidate fallback and `all_principal_bindings` broadening approximate
   "was this binding open as of the change's effective_at" as "ever observed for this principal,"
   not precisely interval-bounded, in the query languages (not in the JS oracle). A deployment
   relying on native KQL/SPL execution in a scenario with many short-lived, non-overlapping
   bindings per principal could see this simplification matter; the JS oracle remains the precise
   reference.

## Whether Block 1–5 assumptions changed

No Block 1 or Block 2 invariant, telemetry field, or detection track definition changed. The
one substantive change (Block 6 fix, V5-03) is a Block 5 rule-logic refinement — it narrows
which existing `mcp.authz.change.type` enum value a rule already reads counts as invalidating.
Nothing was added to, removed from, or reinterpreted in the locked telemetry contract.

The Track 3 remediation pass (above) likewise adds no new telemetry field and changes no locked
invariant. It (a) fixes SPL to match KQL's already-correct join keys, (b) fixes SPL's `join`
semantics to preserve every applicable match, (c) tightens the close-suppression join to use an
already-existing, already-required field (`principal.id_hash` on `mcp.subscription.close`), and
(d) fixes the JS test oracle to faithfully mirror the corrected queries. Detection scope was not
silently narrowed or widened — the one scope-relevant fact (item (c)) uses telemetry the schema
already mandates, and the one scope boundary confirmed as unresolved (multi-subscription
cross-correlation, V11-11) is reported, not quietly patched over with an invented field or grace
period.

**Track 3 remediation pass, part 2 (scope-aware correction) is a genuine, disclosed telemetry
contract change** — unlike part 1, it is not scope-neutral. Six new project-defined fields are
added (`mcp.subscription.instance_id`, `mcp.authz.binding_id`, `mcp.subscription.required_scope`,
`mcp.authz.change.affected_scope`/`affected_binding_ids`/`removed_scope`), all clearly marked as
new and project-defined in `telemetry/schema.md`, none claimed as MCP wire values or OTel/ECS
standards (`telemetry/field-mapping.md` Bucket 3). No Block 1/2 invariant is removed or
reinterpreted; every new field is additive, with a documented legacy-compatibility fallback for
events that predate it, so existing (non-upgraded) instrumentation continues to be evaluated —
just with `insufficient_evidence` in place of the previous pass's unsound principal-only
confirms, wherever genuine ambiguity exists. The one documentation defect fixed (removing
`.authorization_change` from `mcp.subscription.id`'s required-event list in `telemetry/schema.md`)
corrects the schema to match behavior every implementation already had; it does not change any
implementation's behavior.
