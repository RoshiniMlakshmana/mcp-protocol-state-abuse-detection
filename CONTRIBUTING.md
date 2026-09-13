# Contributing

Thanks for considering a contribution. This project is small and opinionated on purpose — the
value of the detection tracks depends on the telemetry contract and corpora staying internally
consistent, so contributions are held to a few non-negotiable rules.

## Before you open a PR

Read `docs/threat-model.md`, `telemetry/schema.md`, and the relevant block's README under
`data/` — most proposed changes turn out to already be addressed there, or to require touching
a locked assumption (see below).

## Non-negotiable rules for new detections or tests

1. **Deterministic fixtures.** Any new corpus fixture must use a fixed logical clock, fixed
   identifiers, and the project's documented test HMAC key/scheme (`tools/harness/lib/hash.js`)
   — never `Date.now()`, `Math.random()`, or a real secret. Regenerating the corpus must
   produce byte-identical output.
2. **Truthfulness.** Do not claim a fixture demonstrates SDK-verified or real-world-observed
   behavior unless it actually does (see `docs/sdk-discrepancy.md` for how this project handles
   that distinction). Label synthetic/experimental content as such.
3. **Telemetry provenance.** Every field a rule or fixture uses must already exist in
   `telemetry/schema.md`. Do not invent a new field to make a detection easier to write —
   propose a schema change explicitly and separately, with its own justification, and expect it
   to be scrutinized against the locked Block 1/2 telemetry contract.
4. **Positive and negative controls.** A new detection is not complete without: at least one
   fixture that should fire (true positive), at least one that should not (true negative /
   benign control), and — where relevant — a boundary or false-positive-risk fixture. See
   `data/validation/` for the pattern.
5. **Tests must recompute, not just assert labels.** A test that only checks
   `expected === actual` by reading both from the same manifest proves nothing. Tests should
   independently recompute the expected outcome from raw event fields wherever practical (see
   `tests/attack/track3util.js` and `tests/detections/oracle.js` for the pattern this project
   uses).

## What requires discussion first (open an issue before a PR)

- Adding a fourth detection track, or changing the definition of an existing one.
- Adding a new telemetry field.
- Weakening a detection's logic to reduce false positives without a corresponding, documented
  root-cause analysis (see `docs/validation-report.md` for the standard this project holds
  itself to: document the failure, find the root cause, decide whether to tune, re-run
  regressions, report before/after).

## Running the test suite

```
node --test tests/normal/*.test.js tests/attack/*.test.js tests/detections/*.test.js tests/validation/*.test.js
```

All tests must pass, including after regenerating every corpus (see `README.md`
"Reproduction").

## Style

- No emojis unless explicitly relevant to the content.
- Prefer clear, verbose detection logic (KQL/SPL) over compact-but-opaque queries.
- Document limitations in the same PR that introduces the detection — don't leave that for
  later.
