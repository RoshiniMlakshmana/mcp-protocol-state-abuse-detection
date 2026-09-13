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
| Block 6 (validation/stress) | 48 | 220 | Adversarial-but-benign + boundary + evasion fixtures, incl. 11 Track 3 remediation-pass regression fixtures (V11-01..V11-11) |
| **Full stress-test corpus (3+4+6)** | **79** | **420** | This block's metrics |

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

### Full stress-test corpus (79 scenarios) — after the Block 6 fixes and the Track 3 remediation pass

| Track | TP | FP | TN | FN | n | Precision | Recall |
|---|---|---|---|---|---|---|---|
| 1 | 8 | 0 | 71 | 0 | 79 | 1.000 | 1.000 |
| 2 | 9 | 0 | 70 | 0 | 79 | 1.000 | 1.000 |
| 3 (excl. experimental A-EXP1) | 15 | 0 | 63 | 0 | 78 | 1.000 | 1.000 |

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
| Track 3: `detected_at` used instead of `effective_at` | — / 0 | — / 4 | Yes |
| Track 3: close-suppression check removed | 0 / — | 51 / — | Yes |
| Track 3: `mcp.authz.change.type` filter removed (reintroduces V5-03) | 0 / — | 52 / — | Yes |

(Counts grew alongside the corpus after the Track 3 remediation pass added 11 regression
fixtures; re-run `node --test tests/validation/mutation.test.js` rather than assuming these
exact numbers stay fixed across future corpus changes.)

The last row is a direct, mechanical demonstration that this validation suite would have caught
the V5-03 regression had it not already been fixed — the mutation test literally reconstructs
the pre-fix logic and confirms it produces exactly the class of false positive V5-03 exposed.

## Language-equivalence findings (V9)

**Correction (Track 3 remediation pass):** the Track 3 "KQL and SPL are mutually equivalent"
test in a prior revision of this suite called `track3PrimaryFires` twice on the same input and
asserted the result equal to itself — a tautology that could never fail and verified nothing.
It has been replaced with two **independently-coded JS models**, one written from KQL's own
literal semantics (`kqlModelRows`) and one from the corrected SPL's own literal semantics
(`splModelCorrectedRows`), compared **row-for-row** (not just as a boolean) across the full
stress corpus. **This disclaimer applies throughout this section: neither model executes actual
KQL or SPL, and neither runs against a real Sentinel/Splunk backend — "equivalent" means "these
two independently-authored models of each language's documented semantics agree," which is the
strongest claim achievable without native execution (still pending; see README.md).**

A third model, `splModelPreFixBuggyRows`, reconstructs the **original, pre-fix** SPL semantics
(subscription_id-only expiry join, first-match-only joins) purely to prove the regression corpus
actually exercises the fixed bugs — see "Track 3 remediation pass" below.

| Track | Sigma vs. KQL vs. SPL | Verified how |
|---|---|---|
| 1 | Fully equivalent across all 79 stress-corpus scenarios | `tests/validation/language_equivalence.test.js` — three independently-written JS predicates mirroring each language's literal filter, zero disagreements |
| 2 | Fully equivalent across all 79 stress-corpus scenarios | Same method, zero disagreements |
| 3 | **The independently-coded KQL-semantics and corrected-SPL-semantics models agree row-for-row across all 79 stress-corpus scenarios. Sigma is NOT equivalent — retained only as a documented, deliberately incomplete correlation.** | Row-level `assert.deepEqual` per scenario, not a boolean comparison; see matrix below for the Sigma comparison |

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

### Scope boundary confirmed, deliberately NOT fixed

**Same-principal, multiple concurrent subscriptions on the revocation leg** (previously listed
as "remaining risks" item 1 below, based on reasoning alone) is now **empirically demonstrated**
by fixture V11-11: a principal with two concurrent subscriptions, one revoked, has the *other,
still-valid* subscription's notification mechanically fire, because
`mcp.subscription.authorization_change` carries no subscription id to disambiguate. Per explicit
instruction, this is reported as an unresolved scope boundary, not fixed by tightening the join
(which would reintroduce the V6-02 blind spot) or by inventing a subscription-id field that does
not exist in the locked telemetry contract.

## Remaining risks (unresolved, explicitly not decided in this block)

1. **Track 3's principal-only join for the authoritative/detected_only legs** (required to keep
   V6-02-style malformed telemetry detectable) can, for a principal holding two or more
   concurrent subscriptions where only one is revoked, cross-correlate the still-valid
   subscription's notifications against the other's revocation boundary. **Now empirically
   demonstrated** by fixture V11-11 (Track 3 remediation pass, above) — no longer only a
   reasoned risk. Deciding whether to tighten the join (trading away the V6-02 fix) remains
   deferred; doing so would require a subscription-id field on `authorization_change` events
   that does not exist in the locked telemetry contract, and inventing one is out of scope.
2. **Collector canonicalization dependency (V1-08)** has no rule-layer mitigation; only
   upstream instrumentation correctness prevents it.
3. **Severity-by-`mcp.validation.source` differentiation** for Track 1 remains an open,
   reasonable enhancement, deliberately not implemented this block.

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
