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

**Track 3 remediation pass, part 3 — example-driven regression pass (this document's fourth
revision):** a third follow-up review found that part 2's own fix still carried an unsound
shortcut: a "sole-candidate fallback" that resolved an `affected_scope = unknown` change to a
confirmed finding whenever exactly one binding was observed for a principal. That is still an
inference, not evidence (fixture V13-03 proves candidate count must never substitute for scope
evidence, even when the count is exactly one), so it is removed in this revision. This pass also
replaces an "ever observed anywhere in the queried window" approximation for
`affected_scope = all_principal_bindings` with a PRECISE effective-time interval check (fixture
V13-06), detects a genuinely self-contradictory record shape (authoritative timing claimed with
no `effective_at`, fixture V13-05), and adds ten independently-specified examples with their own
expected outcomes as the starting point for the whole pass (see "Track 3 remediation pass, part
3" below for the full account and the example table). Six prior fixtures needed real scope
evidence added to preserve their original timing-correctness test intent under the stricter
model (A12, A14, A-EXP1, V5-07, V5-09, V11-01 through V11-04 and V11-10); one fixture (V6-02) is
reclassified from a claimed "partially detectable" finding to `insufficient_evidence`, matching
example #6 exactly.

**Track 3 remediation pass, part 4 — exact multivalue scope intersection (this document's fifth
revision):** while checking the ONE remaining documented SPL-only approximation named in part
3's "remaining risks" item 5, a fourth follow-up review found that the language-equivalence
JS model claiming to represent the real SPL query had silently been implementing the CORRECT,
exact intersection all along — meaning the "SPL is fully equivalent to KQL" claims in this
document and in `tests/validation/language_equivalence.test.js` never actually exercised the
real query's first-scope-tag-only approximation, because no multi-tag fixture existed to expose
the gap and the model itself did not reproduce the bug it was supposed to mirror. The real SPL
query (`detections/spl/mcp_subscription_authorization_drift.spl`) is now fixed to compute an
exact, order-independent, anchored-literal-quoted multivalue intersection via `mvmap()`/
`mvfind()` (syntax verified against Splunk's documented Multivalue eval functions reference for
Splunk Enterprise 9.x/Splunk Cloud), and the JS model's missing-vs-empty-evidence check was
corrected to honestly reflect a genuine SPL/Splunk platform constraint the fix could not remove
(fixture V14-07 — see "Track 3 remediation pass, part 4" below for the full account, including
the one exact unresolved case this pass could not fix in SPL, named rather than approximated
away).

**Track 3 remediation pass, part 5 — native KQL execution; duplicate-row fix (this document's
sixth revision):** a fifth pass moved from JS-model comparison to actual native execution against
a real Kusto engine (Microsoft's local, free, perpetual Kusto emulator — no account, no trial;
see `evidence/native-execution/`) for 25 representative fixtures. All 25 produced the expected
outcome, but native execution surfaced a genuine, previously-undetected row-duplication defect:
a notification independently satisfying two or more `EvaluatedNoViolation`-tier conditions at
once produced one Informational-severity row per contributing signal instead of one row per
notification (fixtures V11-07, V14-04, V14-05). Fixed by collapsing such ties to exactly one row
per notification, retaining every contributing reason, in the JS oracle, KQL, and SPL alike; this
is native-execution-verified for KQL only — SPL was aligned by code parallel, not independently
executed (no Splunk instance was started this pass). See "Track 3 remediation pass, part 5" below
for the full account, including honest before/after re-execution of the exact pre-fix query text.

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
| Block 6 (validation/stress) | 75 | 351 | Adversarial-but-benign + boundary + evasion fixtures, incl. 11 join-key/multi-boundary fixtures (V11-01..V11-11), 13 scope-aware-correction fixtures (V12-01..V12-13), 6 example-driven regression fixtures (V13-01..V13-06), and 8 exact-multivalue-scope-intersection fixtures (V14-01..V14-08) |
| **Full stress-test corpus (3+4+6)** | **106** | **551** | This block's metrics |

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

### Full stress-test corpus (106 scenarios) — after all four Track 3 remediation passes

| Track | TP | FP | TN | FN | n | Precision | Recall |
|---|---|---|---|---|---|---|---|
| 1 | 8 | 0 | 98 | 0 | 106 | 1.000 | 1.000 |
| 2 | 9 | 0 | 97 | 0 | 106 | 1.000 | 1.000 |
| 3 (excl. experimental A-EXP1) | 25 | 0 | 80 | 0 | 105 | 1.000 | 1.000 |

**These per-scenario TP/FP/TN/FN numbers collapse `track3PrimaryFires` to a boolean (fired iff
at least one `confirmed_drift` row exists) — they do NOT show how many notifications were
evaluable at all.** A scenario counted as a correct "TN" (true negative, expected3=false) is
indistinguishable in this table from one where every notification came back
`insufficient_evidence` rather than a positively-confirmed clean result. See "Track 3 coverage
report" below for that breakdown, computed separately for exactly this reason.

### Track 3 coverage report (part 4 revision) — confirmed / clean / insufficient, reported separately

Computed mechanically by `tests/validation/metrics.test.js`'s coverage test, over every
notification in the full stress corpus (excluding the experimental A-EXP1 scenario):

| Outcome | Count | Share |
|---|---|---|
| `confirmed_drift` | 31 | 44.9% |
| `evaluated_no_violation` | 27 | 39.1% |
| `insufficient_evidence` | 11 | 15.9% |
| **Total evaluated notifications** | **69** | 100% |

`insufficient_evidence` breakdown by reason: `ambiguous_scope` (5), `no_invalidity_evidence` (1),
`missing_scope_evidence` (2), `conflicting_evidence` (1), `incompatible_hash_epoch` (1),
`incomplete_timing_evidence` (1). **This ~16% is not a defect to be minimized to zero** — it is
the correction working as intended: every one of these eleven notifications would previously have
either mechanically fired (a false-positive risk, e.g. via the now-removed sole-candidate
inference) or mechanically cleared (a false-negative risk) under principal-only, scope-blind, or
candidate-count logic, and now honestly reports that the telemetry available does not support a
confident answer either way. `missing_scope_evidence` grew from 1 to 2 in this revision because
fixture V14-06 (entirely absent `required_scope`) adds a second genuine instance of it — see
"Track 3 remediation pass, part 4" below.

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
| Track 3: close-suppression check removed | 0 / — | 66 / — | Yes |
| Track 3: `mcp.authz.change.type` filter removed (reintroduces V5-03) | 0 / — | 65 / — | Yes |

(Counts grew alongside the corpus after the four Track 3 remediation passes added
11 + 13 + 6 + 8 regression fixtures; re-run `node --test tests/validation/mutation.test.js` rather than assuming these
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
**This disclaimer applies throughout this section: neither model executes actual KQL or SPL
against the full 106-scenario corpus, and neither runs against a real Sentinel/Splunk backend
— "equivalent" here means "these two independently-authored models of each language's
documented semantics agree" across the FULL corpus, which remains the applicable claim at that
scale. A SEPARATE, smaller native-execution pass (25 representative fixtures, real KQL engine,
NOT this full-corpus JS-model comparison) has since been performed for KQL specifically — see
"Track 3 remediation pass, part 5" below and `evidence/native-execution/`; SPL native execution
remains not performed. Do not read the native-execution pass as extending to the full corpus, or
to SPL, or to a Sentinel deployment.** Both
models implement the precise, interval-bounded resolution algorithm the real KQL/SPL queries use
(part 3's fix; the earlier "ever observed for this principal" approximation this paragraph used
to describe here was corrected in that pass and this stale sentence was left unfixed until part
4 — see the KQL file's header comment for the full rationale). **One named, intentional exception
remains (part 4): fixture V14-07 (an explicitly-empty, not absent, `required_scope`) is where the
two models are EXPECTED to disagree** — KQL's `dynamic` type can represent "present but empty"
distinctly from "absent" (`isempty(dynamic([]))` is documented `false`); classic Splunk field
extraction cannot. `tests/validation/language_equivalence.test.js`'s equivalence test asserts
exactly this one disagreement by name, not zero, so this platform gap stays visible rather than
silently passing or silently failing the suite.

A third model, `preCorrectionModelResults`, reconstructs the **pre-scope-correction** behavior
(principal-only join, no binding/scope awareness at all — this is part 1's corrected-but-still-
principal-scoped model) purely to prove the new regression corpus actually exercises the
scope-aware correction — it must, and does, diverge from the corrected model on V11-11 and the
V12 fixtures designed to expose exactly this gap.

| Track | Sigma vs. KQL vs. SPL | Verified how |
|---|---|---|
| 1 | Fully equivalent across all 106 stress-corpus scenarios | `tests/validation/language_equivalence.test.js` — three independently-written JS predicates mirroring each language's literal filter, zero disagreements |
| 2 | Fully equivalent across all 106 stress-corpus scenarios | Same method, zero disagreements |
| 3 | **The independently-coded KQL-model and SPL-model outcomes agree on every notification across all 106 stress-corpus scenarios except ONE named, documented divergence (V14-07 — see above). Sigma is NOT equivalent — retained only as a documented, deliberately incomplete correlation.** | Per-notification outcome comparison, not a boolean; see matrix below for the Sigma comparison |

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

## Track 3 remediation pass, part 3 (example-driven regression pass)

A third follow-up review started from ten independently-specified examples (not from re-reading
the code first) and only then checked each example against the actual KQL and SPL source.

### The ten examples and their outcomes

| # | Example | Expected outcome | Fixture(s) |
|---|---|---|---|
| 1 | Subscription loses permission and delivers afterward | `confirmed_drift` | A12, V12-01 (binding A) |
| 2 | Same principal: A loses permission, independently authorized B delivers | `evaluated_no_violation` for B | V12-01 (binding B) |
| 3 | A valid replacement authorization takes effect before delivery | old expiry must not trigger | V12-06 |
| 4 | Delivery during an invalid interval before replacement | `confirmed_drift`; later renewal must not erase it | V13-01 |
| 5 | An unrelated binding exists earlier or appears later | must not affect this notification | V13-02 (earlier), V12-07 (later) |
| 6 | Revocation scope unknown, even with only one observed candidate | `insufficient_evidence` | V13-03 (clean case), V6-02 (real-world instance) |
| 7 | Unrelated permission removed / required permission removed | `evaluated_no_violation` / `confirmed_drift` | V12-03 / V12-04 |
| 8 | Events arrive out of order | resolved via authoritative effective times | V12-08 |
| 9 | A request ID is reused after reopening | old closes/revocations must not affect the new instance | V13-04 (same-principal reopen), V12-05 (cross-tenant reuse) |
| 10 | Timing or binding evidence is conflicting/incomplete | `insufficient_evidence` | V12-09 (missing scope), V12-10 (conflicting), V12-11 (hash epoch), V13-05 (incomplete timing) |

Row-level assertions for every example: `tests/validation/track3_row_regression.test.js`.

### Two further code defects found and fixed

1. **The "sole-candidate fallback" (part 2's own unsound shortcut) is removed.** It resolved an
   `affected_scope = unknown` change to `confirmed_drift` whenever exactly one binding was
   observed for a principal — still an inference, not evidence. `affected_scope = unknown` (or a
   legacy event predating the field) now ALWAYS resolves to `insufficient_evidence` when timing
   would otherwise indicate a violation, regardless of candidate count. Proven by fixture V13-03
   and the "RESTORED-BUG PROOF" test that re-derives the removed inference independently and
   shows it would wrongly confirm both V13-03 and V6-02.
2. **`affected_scope = all_principal_bindings` now uses a PRECISE effective-time interval**
   instead of an "ever observed anywhere in the queried window" approximation: a binding only
   counts as one of "all bindings this principal held" if it was already open, and not yet
   closed, at the moment the change took effect. Proven by fixture V13-06: an account-wide
   revocation confirms on a pre-existing binding but not on a binding issued afterward.
3. **Suppression is now checked before scope ambiguity/conflict, in both the JS oracle and both
   query files** — a legitimately closed stream needs no scope resolution at all; "the subscriber
   already stopped receiving notifications through the proper channel" is definitive regardless
   of which binding a revocation targeted. (Discovered while re-deriving fixture V11-07 under the
   stricter unknown-scope rule — without this reordering, a correctly-suppressed notification
   would have been misreported as `insufficient_evidence` instead of `evaluated_no_violation`.)
4. **A self-contradictory record shape is now explicitly detected**: an `authorization_change`
   claiming `timing_confidence = authoritative` but omitting `effective_at` entirely. Both the JS
   oracle and the KQL query detect this explicitly and report `insufficient_evidence` (reason
   `incomplete_timing_evidence`) rather than silently letting a null-timestamp comparison make the
   record disappear as if it "did not apply" (fixture V13-05).

### One exact unresolved case identified, not approximated

**A genuine bug was found and fixed in KQL during this pass, not merely documented.** The first
draft of this revision's KQL query relied on `todatetime()` converting a missing
`mcp.authz.change.effective_at` to `null`, and a `null` comparison (`notifTime > effectiveAt`)
silently filtering the row out of `RevocationCandidates` — which would have misreported fixture
V13-05 as `evaluated_no_violation`/no-signal-at-all rather than `insufficient_evidence`. Per the
explicit instruction to identify an unresolved case rather than approximate it, this was
investigated and found to be fixable: `MalformedTimingSignals` now detects the missing
`effective_at` explicitly, BEFORE any `todatetime()`-based comparison can silently discard it
(see the KQL file's own comment for the exact mechanism). This is called out here because it is
exactly the kind of gap this pass was designed to surface — the difference between "identify the
exact case and fix it" and "identify the exact case and approximate past it" mattered in
practice, not just in principle.

No other case in the ten examples was found to be inexpressible in either query language at the
level of precision this pass targets; both queries were checked example-by-example against the
JS reference oracle's row-level output (see `tests/validation/language_equivalence.test.js`) and
found to agree on every notification in the full stress corpus.

## Track 3 remediation pass, part 4 (exact multivalue scope intersection)

A fourth follow-up review targeted the ONE remaining documented Track 3 approximation named in
part 3's "remaining risks" item 5: the SPL scope-downgrade relevance check compared only the
first element of `mcp.subscription.required_scope` and `mcp.authz.change.removed_scope` via an
unanchored `mvfind()` regex.

### What inspecting the actual SPL query and its independent model found

Two separate, compounding problems, both in
`detections/spl/mcp_subscription_authorization_drift.spl`:

1. **A positional bug.** `mvindex(field, 0)` only ever looked at the FIRST tag in each
   multivalue field. A real overlap sitting anywhere else (e.g. the last position on both sides)
   was invisible to the check — fixture V14-01 demonstrates this exactly, and V14-02 shows the
   identical underlying overlap reordered to the first position produces the correct result,
   proving the bug was purely about position, not the tags themselves.
2. **A matching bug, independent of the first.** `mvfind()`'s second argument is always a
   regular expression (verified against Splunk's documented Multivalue eval functions reference),
   and the query passed a raw scope-tag string as that pattern with no anchors. An unanchored
   regex search matches as a substring, so a shorter tag could wrongly match inside an unrelated
   longer one that happens to start the same way — e.g. `"files:read"` matching inside
   `"files:read_all"`. Fixture V14-05 demonstrates this independently of the positional bug (both
   tags sit at position 0 in that fixture, so only the matching bug is exercised).

**Checking whether the previous models hid this discrepancy — they did.** The independently-coded
SPL model in `tests/validation/language_equivalence.test.js` (`splModelResults`) already computed
a full, exact, order-independent intersection (`rem.filter((s) => req.indexOf(s) >= 0)`) — it did
NOT reproduce the real query's first-tag/substring bugs. The model was accidentally MORE correct
than the query it claimed to represent, which meant every "KQL and SPL are equivalent" claim in
this document and in the test suite was true of the two MODELS but never actually exercised the
real SPL query's documented limitation, because no multi-tag fixture existed to force the model
and the query apart. This is now corrected on both sides: the real SPL query is fixed to match
the model's exact-intersection logic, and the model's missing-vs-empty-evidence check (below) was
corrected to stop overstating what SPL can actually do.

### The fix

Classic SPL has no built-in set-intersection function over two multivalue fields. The fix
computes the intersection using `mvmap()` to iterate every value of `removed_scope2`, testing
EXACT membership in `open_required_scope2` via an anchored (`\A...\z`), literally-quoted
(`\Q...\E`) `mvfind()` regex — Splunk's regex engine is confirmed PCRE2 (per Splunk's own SPL-
and-regular-expressions documentation), which supports `\Q...\E` literal quoting, so an arbitrary
scope-tag string can never be misread as a regex metacharacter sequence. `mvmap()` evaluates
entirely within the existing row via ordinary `eval` semantics — it never calls `mvexpand`, so it
cannot multiply rows or duplicate alerts even when several tags overlap at once (V14-08) or a
side contains a duplicate tag (V14-03). This is documented as a MODEL, not a verified-equivalent
native query: it has not been executed against a live Splunk instance (native execution remains
pending project-wide, per README.md), and the query's own header names one caveat this
methodology cannot rule out (a scope-tag value containing the literal substring `\E`, which is
outside this project's scope-tag vocabulary and not exercised by any fixture).

### Independently specified tests added (V14-01..V14-08)

| # | Test | Expected outcome | Fixture |
|---|---|---|---|
| 1 | Relevant match only in the second/last position | `confirmed_drift` | V14-01 |
| 2 | Reordered lists producing identical results | `confirmed_drift` (same as V14-01) | V14-02 |
| 3 | Duplicate tags | `confirmed_drift`, exactly ONE alert row | V14-03 |
| 4 | No overlap | `evaluated_no_violation` | V14-04 |
| 5 | Exact strings (`files:read` vs. `files:read_all`) | `evaluated_no_violation` | V14-05 |
| 6a | Missing scope evidence (field entirely absent) | `insufficient_evidence` (`missing_scope_evidence`) | V14-06 |
| 6b | Explicitly known empty scope evidence | `evaluated_no_violation` in KQL/oracle; **named SPL divergence**, see below | V14-07 |
| 7 | Multiple matching tags | `confirmed_drift`, exactly ONE alert row (not one per tag) | V14-08 |

Row-level assertions: `tests/validation/track3_row_regression.test.js`. Two "RESTORED-BUG PROOF"
tests independently re-derive the OLD first-tag/unanchored-match behavior and show it disagrees
with the fixed oracle on V14-01 (misses the real overlap) and V14-05 (wrongly matches the
substring) — direct evidence the regression suite would catch either bug's reintroduction.

### One exact unresolved case identified, not approximated (fixture V14-07)

Distinguishing "no scope evidence was ever recorded" (missing) from "the scope list was
explicitly recorded as empty" (known-empty) requires the underlying data model to represent both
states distinctly. KQL's `dynamic` type does: `isnull(dynamic([]))` is `false` and
`isempty(dynamic([]))` is also documented `false` — an empty array is neither null nor empty in
Kusto's terms, so it is preserved as a genuine, present, zero-element value distinct from an
absent field. **Classic Splunk field extraction (spath / `INDEXED_EXTRACTIONS=json`) has no
equivalent representation** — a field's value is fundamentally a bag of one or more strings, so
there is no "present with zero values" state to extract into; an explicitly-empty JSON array and
an absent field are indistinguishable once ingested. This is a genuine, structural platform
constraint, not a query-logic bug this project's SPL could have been written to avoid, and per
the explicit instruction to name an unresolved case rather than paper over it with an
approximation, it is not treated as fixed:

- The real SPL query's `isnull(open_required_scope2) OR isnull(removed_scope2)` check is already
  the most correct expression available in SPL — no change was needed to that specific
  comparison, only to the overlap computation it feeds.
- `tests/validation/language_equivalence.test.js`'s SPL model now encodes this platform
  constraint explicitly (an empty array is treated the same as absent, for SPL specifically —
  differently from the KQL model, which correctly treats it as present), and fixture V14-07 is
  asserted as exactly one NAMED disagreement between the two models — not folded into a "zero
  disagreements" claim, and not silently excluded from the corpus.
- A deployment that needs this distinction in SPL would need an additional, project-defined
  sentinel field (e.g. an explicit boolean or a placeholder scope value) — out of scope for this
  pass, since it would require a new telemetry field, not a query fix, and is recorded here as
  future work rather than invented under this instruction's constraints.

## Track 3 remediation pass, part 5 (native KQL execution; duplicate-row fix)

A fifth pass moved from JS-model comparison to **actual native query execution** for the first
time in this project, using Microsoft's official local Kusto emulator (Docker image
`mcr.microsoft.com/azuredataexplorer/kustainer-linux`, `BuildVersion 1.0.9753.23211`) — a free,
perpetual, local engine requiring only a plain `ACCEPT_EULA=Y` Docker flag, no account, no
subscription, no trial. **This is native KQL query execution, not a Sentinel deployment**: no
workspace, no scheduled analytics rule, no incident/alert pipeline, no Log Analytics ingestion
mapping was involved or is claimed. Full reproducible evidence — the exact engine version, the
exact executed query text per fixture, the raw JSON responses, and the converter scripts that
built the inputs — is committed under `evidence/native-execution/`.

### What was executed, and what was not

25 representative fixtures were run against the real, unmodified `.kql` query text (only the
input source — a `datatable(...)` literal built mechanically from the real JSONL fixtures — was
adapted, never the query body): the 8 `V14-01`..`V14-08` exact-intersection fixtures, 10 further
Track 3 fixtures spanning join-key, malformed-timing, and precise-interval regressions
(`V11-01`, `V11-02`, `V11-03`, `V11-07`, `V12-01`, `V12-13`, `V13-01`, `V13-03`, `V13-05`,
`V13-06`), and 7 Track 1/Track 2 fixtures (`A1`, `A6`, `A11`, `A17` for Track 1; `A7`, `A11`,
`A17` for Track 2). **All 25 produced the expected outcome.** This is 25 representative
fixtures, **not** the full 106-scenario corpus, and it covers KQL only — **SPL was not natively
executed** (no local Splunk instance was started this pass; see "One remaining, explicitly
deferred item" below). Native execution of the full corpus, and of a real Sentinel
ingestion/scheduled-rule/alert pipeline, both remain not performed.

### A real defect native execution found: duplicate `EvaluatedNoViolation` rows

Native execution surfaced a genuine row-count defect no prior JS-model comparison had
surfaced, because `tests/validation/language_equivalence.test.js`'s `kqlModelResults`/
`splModelResults` never tracked row count at all (only a single winning outcome per
notification) — the real KQL query's `AllSignals` union-of-independently-computed-tables design
did track multiplicity, and for good reason at the `ConfirmedDrift` tier (see "ties at max
priority ALL retained" throughout this document), but the SAME mechanism also applied,
unintentionally, to the `EvaluatedNoViolation` tier: whenever a notification independently
satisfied two or more `EvaluatedNoViolation` conditions at once (e.g. a not-yet-crossed
`valid_until` **and** a scope-irrelevant downgrade on the same notification), the query emitted
one Informational-severity row **per contributing signal** instead of one row for the
notification. `Outcome` values were never wrong — only the row count. Confirmed via honest
before/after re-execution (`evidence/native-execution/prefix-baseline/`, re-running the EXACT
pre-fix query text from commit `d08bfd6` against the same live engine, not a transcript claim):

| Fixture | Pre-fix rows | Post-fix rows | Outcome (both) |
|---|---|---|---|
| V11-07 | 2 | 1 | EvaluatedNoViolation |
| V14-04 | 2 | 1 | EvaluatedNoViolation |
| V14-05 | 2 | 1 | EvaluatedNoViolation |

### The fix

`EvaluatedNoViolation` ties now collapse to exactly **one row per notification**, retaining
**every** contributing reason (semicolon-joined, e.g. `"expiry_not_yet_reached;
scope_downgrade_irrelevant"`), grouped by an unambiguous notification identity — `instanceId` +
`subscriptionId` + `principalHash` + `notifTime` + `notificationType`, never `notifTime` alone.
`ConfirmedDrift` and `InsufficientEvidence` rows are explicitly, deliberately **untouched**:
collapsing those would hide a real distinct boundary or reason, which this fix does not do (see
fixture `V11-01`/`V11-03` below). Applied to all three implementations:

- **`tests/attack/track3util.js` (JS reference oracle)**: already produced one row per
  notification (a boolean `evaluatedNoViolation` flag, not a union of independent rows) — it did
  not have the row-duplication defect. It DID discard *which* condition(s) applied, always
  reporting `reason: null`. Upgraded to a `Set` of reason tags
  (`expiry_not_yet_reached`/`expiry_suppressed_by_close`/`revocation_not_yet_effective`/
  `revocation_suppressed_by_close`/`scope_downgrade_irrelevant`), joined the same way as KQL/SPL.
- **`detections/kql/mcp_subscription_authorization_drift.kql`**: `ExpirySignals`/
  `RevocationSignals` now blank `Boundary`/`BoundaryTime` for `EvaluatedNoViolation` rows (kept
  only for `ConfirmedDrift`) and tag a reason. The final combination splits into
  `NonInformationalResults` (unchanged `distinct`-based ConfirmedDrift/InsufficientEvidence
  behavior) and `CollapsedNoViolation` (`summarize make_set(Reason)` + `strcat_array`, `any()`
  for Boundary/BoundaryTime/change fields, deterministic since a genuine tie already blanks all
  four), unioned back together.
- **`detections/spl/mcp_subscription_authorization_drift.spl`**: aligned by direct structural
  parallel — `mvappend()`/`eventstats values()` collect per-signal reason tags (relying on
  Splunk's documented null-dropping behavior for `mvappend()`, not independently verified against
  a live Splunk instance), joined via `mvjoin()`, with a conditional `dedup_key` that collapses
  fully for `EvaluatedNoViolation` but preserves the existing per-`(Outcome, Boundary,
  BoundaryTime, change)` distinctness for other tiers. The final `eventstats`/`dedup` `by`/key
  clauses were also strengthened to the same 5-field unambiguous identity KQL already used
  (previously `instance_id, notif_time` only).
- **Reference models** (`tests/validation/language_equivalence.test.js`'s `kqlModelResults`/
  `splModelResults`): **no change needed**. These models already track only the single winning
  `[priority, outcome]` pair per notification (never row count), so they were already "aligned"
  with the one-outcome-per-notification contract — they simply never modeled row count at all,
  which is exactly why they could not have surfaced this defect. Recorded here rather than
  silently left unexplained.

### Proof that distinct notifications are never accidentally merged

The collapse groups by the SAME 5-field identity throughout — a genuine risk item is a second,
different notification sharing a timestamp being wrongly folded into the first. Natively
re-verified after the fix: `V11-01` (one notification confirms once, a second confirms on BOTH
of two applicable changes — 3 total `ConfirmedDrift` rows, exactly as before the fix — ties at
that tier are untouched); `V11-03` (one notification, two independently-crossed boundaries — 2
`ConfirmedDrift` rows, untouched); `V11-02`, `V12-01`, `V12-13`, `V13-01`, `V13-06` (each: two
DISTINCT notifications for the same principal or instance, correctly producing two independent
rows — one `EvaluatedNoViolation`, one `ConfirmedDrift` — never merged into one). Row-level JS
assertions for the three affected fixtures are in
`tests/validation/track3_row_regression.test.js`.

### One remaining, explicitly deferred item

**SPL's fix has not been independently executed against a live Splunk instance.** Per explicit
instruction, Splunk was not started this pass (its Docker path defaults to a 60-day "Enterprise
Trial" license requiring `SPLUNK_START_ARGS=--accept-license` and a separate
`SPLUNK_GENERAL_TERMS` acceptance — see `README.md`, "Native execution"). The SPL query text was
aligned to the verified KQL fix by direct structural parallel and careful manual trace-through
(documented in the SPL file's own header and inline comments), but this is **not** the same
confidence level as the KQL fix, which was proven against a real engine. This gap is named, not
hidden.

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
4. **RESOLVED in "Track 3 remediation pass, part 3" above.** Part 2's KQL/SPL sole-candidate
   fallback and its "ever observed anywhere in the queried window" approximation for
   `all_principal_bindings` are both removed/replaced: the sole-candidate fallback is gone
   entirely (fixture V13-03), and `all_principal_bindings` now uses a precise effective-time
   interval check in both KQL and SPL, matching the JS oracle (fixture V13-06).
5. **RESOLVED in "Track 3 remediation pass, part 4" above, with one exact case named rather than
   approximated away.** The SPL scope-downgrade relevance check no longer compares only each
   side's first scope tag: it now computes an exact, order-independent, anchored-literal-quoted
   multivalue intersection via `mvmap()`/`mvfind()`, verified against Splunk's documented
   Multivalue eval functions reference (fixtures V14-01..V14-05, V14-08). **One genuine,
   structural SPL/Splunk platform limitation could not be fixed and is named, not hidden**:
   classic Splunk field extraction cannot represent "field present with an explicitly empty
   value list" distinct from "field absent," unlike KQL's `dynamic` type — so an explicitly-empty
   `required_scope`/`removed_scope` reports `insufficient_evidence` in SPL where KQL and the JS
   oracle correctly report `evaluated_no_violation` (fixture V14-07). This is an intentional,
   documented divergence asserted by name in `tests/validation/language_equivalence.test.js`, not
   a defect and not silently swept into a "fully equivalent" claim.
6. **RESOLVED for KQL, natively verified, in "Track 3 remediation pass, part 5" above.**
   `EvaluatedNoViolation` row-duplication on ties is fixed and confirmed via real Kusto engine
   execution (25 representative fixtures, including honest before/after re-execution of the
   exact pre-fix query text for the 3 affected fixtures). **The SPL side of this same fix is
   NOT independently verified** — it was aligned by direct code parallel to the proven KQL fix,
   not executed against a live Splunk instance (none was started this pass; see `README.md`,
   "Native execution"). This is an open item, not a resolved one, for SPL specifically.
7. **Native execution coverage is partial, not corpus-wide.** 25 of 106 corpus scenarios have
   been run against a real KQL engine (`evidence/native-execution/`); the remaining scenarios,
   the full SPL query, and any real Sentinel ingestion/scheduled-rule/alert pipeline have not
   been. Do not read "native execution performed" anywhere in this document as extending beyond
   what `evidence/native-execution/README.md` explicitly documents.

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
