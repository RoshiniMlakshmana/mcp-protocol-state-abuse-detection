# Block 6 — Validation / Stress-Test Corpus

75 scenarios, 351 events. **Not mixed with Block 3 (normal) or Block 4 (attack/control) on
disk** — this corpus lives entirely under `data/validation/` and is loaded separately by
`tests/detections/corpus.js`'s `loadValidationCorpus()`. Includes 11 Track 3 join-key/multi-
boundary regression fixtures (V11-01..V11-11), 13 Track 3 scope-aware-correction regression
fixtures (V12-01..V12-13), 6 Track 3 example-driven regression fixtures (V13-01..V13-06), and 8
Track 3 exact-multivalue-scope-intersection fixtures (V14-01..V14-08) added across four later
remediation passes — see "Track 3 remediation pass," "Track 3 remediation pass, part 2," "Track
3 remediation pass, part 3," and "Track 3 remediation pass, part 4" below and
`docs/validation-report.md`.

**Purpose:** unlike Block 3 (demonstrate normal behavior) and Block 4 (demonstrate the three
attack classes), this corpus exists to **break the Block 5 detection rules** — adversarial-but-
benign traffic designed to produce false positives if the rules are weak, boundary conditions
designed to expose off-by-one/timing bugs, and evasion-documentation fixtures that make blind
spots concrete and testable rather than just asserted in prose. It found several real defects
across five remediation rounds (see `docs/validation-report.md`) — that is the corpus doing its
job, not a failure of the corpus.

## Regenerating

```
cd tools/harness && node generate_validation.js
node --test tests/validation/*.test.js
```

Deterministic (fixed clocks, fixed identifiers, same HMAC test key as Block 3/4).

## Layout

| Directory | Validation groups | Scenarios |
|---|---|---|
| `track1/` | V1 (false positives), V2 (evasion illustration) | V1-01…V1-09, V2-01 |
| `track2/` | V3 (false positives), V4 (evasion documentation) | V3-01…V3-07, V4-01, V4-02 |
| `track3/` | V5 (false positives/boundary), V6 (evasion documentation), V11/V12/V13/V14 (four remediation-pass regressions) | V5-01…V5-09, V6-01, V6-02, V11-01…V11-11, V12-01…V12-13, V13-01…V13-06, V14-01…V14-08 |
| `enrichment/` | V8 (output/token/schema must never independently drive a verdict) | V8-01…V8-05 |
| `hashing/` | V7 (HMAC key-epoch behavior) | V7-01…V7-03 |

V9 (language equivalence) and V10 (mutation testing) are **test-suite activities**
(`tests/validation/language_equivalence.test.js`, `tests/validation/mutation.test.js`), not
corpus scenarios — they operate on the full stress corpus rather than requiring their own
fixtures.

## Ground truth schema (`manifest.jsonl`)

`scenario_id`, `file`, `purpose`, `expected_detection_track_1/2/3`, `expected_confidence`
(`high`\|`not_applicable`\|`low`), `false_positive_test` (boolean), `evasion_test` (boolean),
`telemetry_limitation` (string or null — filled in whenever the scenario exposes a real
observability boundary), `notes`.

## Headline findings (see `docs/validation-report.md` for full detail)

1. **V5-03 exposed a real false positive**, since fixed: the Track 3 rules (Sigma component,
   KQL, SPL, and the shared test oracle) originally treated *any* authoritative
   `mcp.authz.change` event as an invalidating boundary, regardless of `mcp.authz.change.type`.
   A legitimate renewal (`scope_upgraded`) was therefore indistinguishable from a revocation.
   Fixed by restricting the invalidating-boundary check to `revoked`/`expired`/
   `scope_downgraded`.
2. **V6-02 exposed a reference-oracle fidelity bug**, since fixed: the JS test oracle
   (`tests/attack/track3util.js`) pre-filtered notifications by `mcp.subscription.id` before
   ever joining them to a revocation event, which is *stricter* than the real KQL/SPL query
   (which joins the revocation leg by `principal.id_hash` only). This masked how the real rules
   would have behaved on malformed telemetry (a notification missing `mcp.subscription.id`).
   Fixed by aligning the oracle's join structure exactly with the KQL query's actual joins —
   and this fix surfaced a **known, unresolved precision/recall tradeoff** in the real rules
   themselves (documented, not fixed): the principal-only join can, in principle, cross-
   correlate a revoked subscription's boundary against a *different*, still-valid subscription
   held by the same principal. **Reclassified again in "Track 3 remediation pass, part 3" below**:
   V6-02's revocation carries no `affected_scope` evidence at all, so under the corrected,
   no-inference resolver it now correctly reports `insufficient_evidence` rather than
   `confirmed_drift` — see part 3 and V12-12 for the corrected, explicitly-scoped counterpart.
3. **V5-09 is deliberately left as an accepted, documented false positive** — no
   policy-exception field exists in the locked Block 2 schema, so the rule correctly (given
   available telemetry) cannot suppress it. Tuning recommendation: a deployment-side allowlist,
   not a schema change. (V5-02 was similarly accepted-but-firing until the scope-aware
   correction below — it now correctly reports `insufficient_evidence` instead.)

## Track 3 remediation pass (V11-01..V11-11)

A follow-up review found two further genuine SPL code defects (a join-key inconsistency with
KQL on the expiry/close-suppression joins, and reliance on Splunk's `join` `max=1` default) and
several JS-oracle discrepancies against the actual KQL/SPL queries. Both are fixed; 11 new
regression fixtures were added specifically to prove it and to catch a future regression:

- **V11-01**: multiple authorization changes, emitted out of effective_at order — proves every
  applicable change is considered, not just the first found.
- **V11-02**: same subscription_id reused by two different principals, one of whom closes their
  own subscription — proves the close-suppression join correctly requires principal_hash too
  (this is the fixture that empirically distinguishes the corrected SPL model from the pre-fix
  buggy one in `tests/validation/language_equivalence.test.js`).
- **V11-03**: revocation and expiry both applicable to one notification — proves both legs are
  evaluated independently and unioned, not short-circuited.
- **V11-04**: silent expiry precedes a later-recorded, future revocation.
- **V11-05**: revocation with no retained `open` event at all.
- **V11-06**: a close on a *different* subscription (same principal) must not suppress.
- **V11-07 / V11-08**: exact-equality boundary conventions on the close side (inclusive) and the
  expiry-leg invalidation boundary (exclusive), mirroring V5-04/V5-05 for the revocation leg.
- **V11-09**: scope upgrade plus a not-yet-reached expiry — a clean double-negative.
- **V11-10**: duplicate/retried close events — proves suppression is a robust "any close at or
  before" check.
- **V11-11**: **empirically confirms** the previously-reasoned-only cross-subscription
  correlation risk is real — a still-valid concurrent subscription's notification mechanically
  fires because the revocation-leg join cannot disambiguate by subscription. Reported as an
  unresolved scope boundary, not fixed.

Row-level (not just boolean) assertions for all eleven are in
`tests/validation/track3_row_regression.test.js`, including two tests that reconstruct the
pre-fix buggy behavior independently and show it disagrees with the fixed oracle on V11-01 and
V11-02 — direct evidence the regression suite would catch either bug's reintroduction.

## Track 3 remediation pass, part 2 (V12-01..V12-13) — scope-aware correction

A second follow-up review found that part 1's fix still treated "same `principal.id_hash`" as
sufficient to scope a revocation — verified against current MCP/OAuth documentation to be a
genuine category error (a principal can hold multiple independent, independently-revocable
authorization bindings; a scope downgrade removes specific permissions, not blanket access; a
wire subscription id is not globally unique; a grant fingerprint is not a stable identifier).
Fixed via six new project-defined fields (`mcp.subscription.instance_id`, `mcp.authz.binding_id`,
`mcp.subscription.required_scope`, `mcp.authz.change.affected_scope`/`affected_binding_ids`/
`removed_scope` — see `telemetry/schema.md` §5) and a three-outcome reporting model
(`confirmed_drift`/`evaluated_no_violation`/`insufficient_evidence`). 13 new fixtures:

- **V12-01**: same principal, binding A revoked / binding B allowed — only A confirms drift.
- **V12-02**: two subscriptions share ONE binding, explicit revocation — both confirm drift.
- **V12-03 / V12-04**: a scope downgrade that doesn't (V12-03) vs. does (V12-04) intersect the
  instance's required scope — no violation vs. confirmed drift.
- **V12-05**: the identical wire `subscription_id` reused across tenants/reconnects — disambiguated
  by `instance_id`, not the wire id.
- **V12-06**: an old binding expires after a LATER notification proves rebinding to a new, valid
  binding — no violation (evaluated against the new binding, not the old one).
- **V12-07**: a brand-new, unrelated binding becoming valid elsewhere does NOT retroactively
  clear an old binding's real violation.
- **V12-08**: out-of-order event-stream arrival with trustworthy `effective_at` — resolution
  follows field values, never array/log position.
- **V12-09 / V12-10 / V12-11**: missing scope evidence, conflicting evidence (revoked + later
  scope-upgraded on the SAME binding), and an incompatible hash-key epoch — all three report
  `insufficient_evidence`, never a guessed default.
- **V12-12**: directly scoped invalidation with NO retained open event at all (the notification
  itself proves its binding) — contrast with V11-05, which lacks that proof and stays ambiguous.
- **V12-13**: the corrected counterpart to V11-11 — identical two-concurrent-subscription shape,
  but with explicit `affected_binding_ids` naming one binding, resolving cleanly.

**V5-02, V11-05, and V11-11 are retained, event content unmodified, and reclassified** from
`confirmed_drift` to `insufficient_evidence` — not deleted, not silently excluded from any
metrics or coverage count. See `docs/validation-report.md`, "Track 3 remediation pass, part 2"
and "Track 3 coverage report," and `tests/validation/track3_row_regression.test.js`.

## Track 3 remediation pass, part 3 (V13-01..V13-06) — example-driven regression pass

A third follow-up review worked from ten independently-specified examples (each an expected
outcome stated before checking the query source) and found that part 2's "scope-aware
correction" still carried two unsound shortcuts, plus two ordering/detection gaps. Fixed in
`tests/attack/track3util.js`, both `detections/kql/mcp_subscription_authorization_drift.kql`
and `detections/spl/mcp_subscription_authorization_drift.spl`, and both independently-coded
models in `tests/validation/language_equivalence.test.js`:

- **Removed a "sole-candidate" scope inference**: an `affected_scope=unknown`/legacy change was
  previously resolved to `confirmed_drift` if exactly one candidate binding had been observed
  for that principal — itself an unsupported inference (a count of observed bindings is not
  evidence of which binding a change applies to), not merely a documented approximation. It is
  now removed entirely; `unknown`/legacy scope always reports `insufficient_evidence`
  (`ambiguous_scope`), regardless of candidate count. **This reclassifies V6-02** (see above).
- **Replaced an "ever observed" approximation with a precise effective-time interval check**
  for `affected_scope=all_principal_bindings`: a binding now only counts as covered if it was
  already open (`open_time <= effective_at`) and not already closed before `effective_at` — not
  merely "observed somewhere in the window."
- **Reordered suppression before scope-ambiguity/conflict checks**: a legitimately closed
  stream is now always resolved to `evaluated_no_violation` before any ambiguity/conflict logic
  runs, fixing a genuine ordering bug the example-driven pass surfaced (V11-07 regressed to
  `insufficient_evidence` under the corrected `unknown`-scope rule until this was fixed).
- **Added explicit detection of self-contradictory timing evidence**: a change claiming
  `timing_confidence=authoritative` but omitting `effective_at` is now explicitly detected
  (before any timestamp comparison) and reported as `insufficient_evidence`
  (`incomplete_timing_evidence`), rather than silently falling out of a null comparison.

Six new fixtures, one per example not already covered by an existing fixture:

- **V13-01**: delivery occurs during an invalid interval before a valid replacement
  authorization takes effect — confirms drift; a later renewal must not erase it.
- **V13-02**: an unrelated binding exists (earlier and later) — must not affect the notification
  under evaluation.
- **V13-03**: `affected_scope=unknown` with exactly one observed candidate binding — reports
  `insufficient_evidence`, proving the sole-candidate inference is gone.
- **V13-04**: a wire `subscription_id`/request id is reused after the stream is reopened — the
  prior instance's close/revocation must not affect the new instance.
- **V13-05**: an `authorization_change` claims `timing_confidence=authoritative` but omits
  `effective_at` — reports `insufficient_evidence` (`incomplete_timing_evidence`), not a silent
  non-match.
- **V13-06**: `affected_scope=all_principal_bindings` where the binding was not yet open at
  `effective_at` — proves the precise interval check, not "ever observed," decides coverage.

Row-level assertions for all six are in `tests/validation/track3_row_regression.test.js`,
including an `oldBuggySoleCandidateInference` reconstruction of the removed mechanism that is
shown to disagree with the fixed oracle on V13-03 and V6-02 — direct evidence the regression
suite would catch reintroduction of the removed inference.

**V6-02 is retained, event content unmodified, and reclassified** from `confirmed_drift` to
`insufficient_evidence` — not deleted, not silently excluded from any metrics or coverage count.
See `docs/validation-report.md`, "Track 3 remediation pass, part 3."

## Track 3 remediation pass, part 4 (V14-01..V14-08) — exact multivalue scope intersection

A fourth follow-up review targeted the one remaining documented Track 3 approximation: the SPL
scope-downgrade relevance check (`removed_scope` vs. `required_scope`) compared only the FIRST
element of each multivalue field via an unanchored regex. Two compounding bugs, both in
`detections/spl/mcp_subscription_authorization_drift.spl`:

- **A positional bug**: a real overlap sitting anywhere but the first position on either side was
  invisible to the check (fixture V14-01; V14-02 shows the identical overlap reordered to the
  first position produces the correct result, proving the bug was purely about position).
- **A matching bug, independent of the first**: `mvfind()`'s second argument is always a regex,
  and the query passed a raw scope-tag string with no anchors — an unanchored regex matches as a
  substring, so `"files:read"` could wrongly match inside `"files:read_all"` (fixture V14-05).

**Checking whether the previous models hid this discrepancy — they did.** The independently-coded
SPL model in `tests/validation/language_equivalence.test.js` already computed a full, exact,
order-independent intersection — it never reproduced the real query's first-tag/substring bugs.
The model was accidentally MORE correct than the query it claimed to represent, so every prior
"KQL and SPL agree" claim never actually exercised this bug, because no multi-tag fixture existed
to force the model and the query apart.

**Fixed** with an exact, order-independent, anchored (`\A...\z`), literally-quoted (`\Q...\E`)
multivalue intersection via `mvmap()`/`mvfind()` (Splunk's regex engine is confirmed PCRE2, which
supports `\Q...\E` literal quoting; syntax verified against Splunk's documented Multivalue eval
functions reference). `mvmap()` evaluates entirely within the existing row and never calls
`mvexpand`, so it cannot multiply rows even when several tags overlap at once (V14-08) or a side
has a duplicate tag (V14-03).

**One genuine, unresolved SPL/Splunk platform limitation was found and is named, not
approximated past** (fixture V14-07): classic Splunk field extraction cannot represent a field
present with an explicitly empty value list as distinct from an absent field, unlike KQL's
`dynamic` type (`isempty(dynamic([]))` is documented `false`). So an explicitly-empty
`required_scope`/`removed_scope` reports `insufficient_evidence` in the real SPL query, where the
JS oracle and KQL correctly report `evaluated_no_violation`. This one disagreement is asserted BY
NAME in `tests/validation/language_equivalence.test.js`, not silently folded into a "fully
equivalent" claim or silently excluded from the corpus.

Eight new fixtures, covering the seven independently-specified tests this pass was built from
(test 6 split into two fixtures — missing vs. explicitly-empty evidence are two distinct,
independently meaningful evidentiary states):

- **V14-01 / V14-02**: overlap at a non-first position, and the same overlap reordered to the
  first position — proves the fix is genuinely order-independent, not accidentally correct.
- **V14-03**: a duplicate tag confirms exactly once, not zero or twice.
- **V14-04**: genuinely disjoint scope lists produce `evaluated_no_violation`.
- **V14-05**: `"files:read"` vs. `"files:read_all"` — exact strings, never a substring match.
- **V14-06**: `required_scope` entirely absent — `insufficient_evidence` (`missing_scope_evidence`).
- **V14-07**: `required_scope` explicitly empty (`[]`) — `evaluated_no_violation` in the oracle
  and KQL; the named SPL divergence described above.
- **V14-08**: two independently-overlapping tags still produce exactly one alert row.

Row-level assertions for all eight are in `tests/validation/track3_row_regression.test.js`,
including two "RESTORED-BUG PROOF" tests that independently re-derive the old first-tag/
unanchored-match behavior and show it disagrees with the fixed oracle on V14-01 (misses the real
overlap) and V14-05 (wrongly matches the substring).

## Safety

All fixtures are synthetic, local, deterministic test data, exactly as in Block 3/4. No real
credential, external system, or third-party infrastructure is referenced anywhere in this
corpus or its generator.
