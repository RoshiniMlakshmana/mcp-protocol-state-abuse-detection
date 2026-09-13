# Block 6 — Validation / Stress-Test Corpus

37 scenarios, 163 events. **Not mixed with Block 3 (normal) or Block 4 (attack/control) on
disk** — this corpus lives entirely under `data/validation/` and is loaded separately by
`tests/detections/corpus.js`'s `loadValidationCorpus()`.

**Purpose:** unlike Block 3 (demonstrate normal behavior) and Block 4 (demonstrate the three
attack classes), this corpus exists to **break the Block 5 detection rules** — adversarial-but-
benign traffic designed to produce false positives if the rules are weak, boundary conditions
designed to expose off-by-one/timing bugs, and evasion-documentation fixtures that make blind
spots concrete and testable rather than just asserted in prose. It found two real bugs (see
`docs/validation-report.md`) — that is the corpus doing its job, not a failure of the corpus.

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
| `track3/` | V5 (false positives/boundary), V6 (evasion documentation) | V5-01…V5-09, V6-01, V6-02 |
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
3. **V5-02 and V5-09 are deliberately left as accepted, documented false positives** — no
   grace-period or policy-exception field exists in the locked Block 2 schema, so the rules
   correctly (given available telemetry) cannot suppress them. Tuning recommendation:
   deployment-side query constants, not a schema change.

## Safety

All fixtures are synthetic, local, deterministic test data, exactly as in Block 3/4. No real
credential, external system, or third-party infrastructure is referenced anywhere in this
corpus or its generator.
