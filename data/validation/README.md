# Block 6 — Validation / Stress-Test Corpus

61 scenarios, 285 events. **Not mixed with Block 3 (normal) or Block 4 (attack/control) on
disk** — this corpus lives entirely under `data/validation/` and is loaded separately by
`tests/detections/corpus.js`'s `loadValidationCorpus()`. Includes 11 Track 3 join-key/multi-
boundary regression fixtures (V11-01..V11-11) and 13 Track 3 scope-aware-correction regression
fixtures (V12-01..V12-13) added in two later remediation passes — see "Track 3 remediation
pass" and "Track 3 remediation pass, part 2" below and `docs/validation-report.md`.

**Purpose:** unlike Block 3 (demonstrate normal behavior) and Block 4 (demonstrate the three
attack classes), this corpus exists to **break the Block 5 detection rules** — adversarial-but-
benign traffic designed to produce false positives if the rules are weak, boundary conditions
designed to expose off-by-one/timing bugs, and evasion-documentation fixtures that make blind
spots concrete and testable rather than just asserted in prose. It found several real defects
across three remediation rounds (see `docs/validation-report.md`) — that is the corpus doing its
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
| `track3/` | V5 (false positives/boundary), V6 (evasion documentation), V11/V12 (two remediation-pass regressions) | V5-01…V5-09, V6-01, V6-02, V11-01…V11-11, V12-01…V12-13 |
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
   held by the same principal.
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

## Safety

All fixtures are synthetic, local, deterministic test data, exactly as in Block 3/4. No real
credential, external system, or third-party infrastructure is referenced anywhere in this
corpus or its generator.
