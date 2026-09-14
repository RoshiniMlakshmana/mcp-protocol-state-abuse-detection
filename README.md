# MCP Protocol-State Abuse Detection

**Detecting Task Routing, Authorization, and Long-Lived Subscription State Violations**

Detection-engineering content (Sigma, KQL, SPL) plus the threat model, telemetry contract, and
deterministic local test corpora behind it, for three protocol-state abuse patterns in MCP
(Model Context Protocol) Tasks (SEP-2663) and long-lived subscriptions
(`subscriptions/listen`, MCP specification revision `2026-07-28`).

**This is a controlled, self-authored validation project.** Every metric in this repository
comes from a small, deterministic, synthetic corpus built specifically to exercise these three
detections — not from production telemetry. See "Results" and "Operational limitations" below
before deploying anything here.

## Validation status and disclosures — read this first

- **Validation used this project's own deterministic reference harness**
  (`tools/harness/`), not a live MCP server or an official-SDK wire capture — see
  `docs/sdk-discrepancy.md` for exactly what was verified against real, current SDK source code
  and why the harness exists.
- **Native execution against a real Microsoft Sentinel workspace or Splunk instance, and
  official Sigma CLI / pySigma conversion validation, have not been performed and remain
  pending unless independently verified.** KQL and SPL were hand-written and hand-reviewed
  against documented query-language semantics and this project's own JS test oracle — never
  executed against live backend software (Python, required for the official Sigma tooling, was
  unavailable in the development environment).
- **These detections require a custom MCP security audit telemetry contract**
  (`telemetry/schema.md`) that does not exist by default in Sentinel, Splunk, or any
  OpenTelemetry deployment — see `telemetry/field-mapping.md`. Nothing here fires against
  unmodified, out-of-the-box telemetry.
- **An alert from any of these rules does not by itself prove compromise.** Each track has
  documented, confirmed conditions under which it fires on entirely benign activity — see
  "Operational limitations" below and `docs/false-positive-analysis.md` — and every detection's
  "Investigation fields" should be checked before treating a hit as confirmed malicious.
- **Track 3's Sigma correlation rule is best-effort hunting content, not semantically
  equivalent to the KQL/SPL implementations** for that track — see "Operational limitations."
- **"KQL and SPL equivalence" for Track 3 means two independently-coded JS models of each
  language's own written semantics agree row-for-row on the shared corpus — not that either was
  executed as native KQL or SPL against a real backend.** See `tests/validation/language_equivalence.test.js`
  and "Native execution" above. A prior version of this test compared one oracle function to
  itself and has been replaced.
- **Track 3 now resolves revocation scope to a specific authorization binding, not a principal.**
  A scope-aware correction added `mcp.authz.binding_id` and
  `mcp.authz.change.affected_scope`/`affected_binding_ids`/`removed_scope` (all new,
  project-defined fields — see `telemetry/schema.md`), fixing a genuine category error verified
  against current MCP/OAuth documentation: principal identity does not establish revocation
  scope, a scope downgrade does not necessarily remove permission for a given subscription, a
  wire subscription id is not globally unique, and a grant fingerprint is not a stable
  identifier. Every Track 3 result is now one of `confirmed_drift` / `evaluated_no_violation` /
  `insufficient_evidence` — ambiguous or incomplete evidence is reported as such, never defaulted
  to a confirmed finding. A follow-up example-driven pass then removed a subtler unsound
  shortcut (a "sole-candidate fallback" that resolved unknown-scope changes via candidate count)
  and replaced an "ever observed" approximation with a precise effective-time interval check for
  account-wide revocations. See "Operational limitations", `docs/validation-report.md` "Track 3
  remediation pass, part 2" and "part 3", and fixture V11-11 (retained, unmodified, as a worked
  example of legacy telemetry that still cannot be resolved without the new fields).
- **No claim of proven novelty, and no claim of detections.ai acceptance, is made anywhere in
  this project.** `publication/novelty-check.md` documents a specific research pass, not a
  guarantee that no prior art exists; this project has not been submitted to or accepted by
  detections.ai.

---

## What this project is

This project detects **security violations in stateful MCP task and subscription workflows** —
disagreements between protocol routing metadata and the request it's supposed to describe,
authorization decisions that reveal one principal touching another's task, and subscription
streams that keep delivering events after the authorization behind them has lapsed.

It does **not** detect prompt content, jailbreaks, malicious tool descriptions, or generic
anomalous AI behavior. It looks at MCP's protocol-level state machine — task lifecycle,
authorization decisions, subscription lifecycle — not at what a model or agent said or did with
its output.

## Why this project exists

Public MCP security detection content today is heavily concentrated around prompt injection,
malicious MCP server configuration, child-process execution from tool calls, credential access,
suspicious network behavior, and tool poisoning. **That work is valuable and this project does
not claim otherwise.** It simply sits in a different, comparatively unexplored corner: the
protocol-*state* and authorization-*state* telemetry introduced by MCP's newer Tasks extension
and long-lived subscription mechanism — a surface that only exists because of the `2026-07-28`
specification revision, and that most current detection content (including large public rule
repositories checked during this project's own research — see `publication/novelty-check.md`)
does not yet cover.

## Detection Tracks

### Detection 1 — MCP Task Routing Header/Body Desynchronization

The `Mcp-Method`/`Mcp-Name` routing headers (SEP-2243) are supposed to mirror the JSON-RPC
body. When they genuinely conflict — a real value disagreement, not a missing or
version-incompatible header — an intermediary routing on the header and a server executing the
body can act on two different things. This rule fires only on that disagreement.

### Detection 2 — MCP Cross-Principal Task Authorization Violation

A syntactically valid task request (`tasks/get`/`update`/`cancel`) is denied because the
authenticated principal is not authorized for that specific task/operation — detected from
server-side authorization evidence (`mcp.authz.decision`/`mcp.authz.reason`), never from the
JSON-RPC response code, since a denied-but-existing task and a genuinely nonexistent task
typically return the identical `-32602` by design (SEP-2663's own anti-enumeration choice).
**The underlying task-ID cross-principal risk class is not something this project discovered —
SEP-2663 documents it directly** (task IDs function as bearer-token-like credentials); this
project turns that already-known risk into concrete, testable detection logic.

### Detection 3 — MCP Long-Lived Subscription Authorization Drift

A `subscriptions/listen` notification is delivered *after* authorization was authoritatively
revoked or expired, while the subscription stream remained active with no valid closure in
between. **This rule has an explicit deployment prerequisite**: it assumes no unmodeled grace
period or permanent open-stream exemption policy exists. If your deployment has either, this
rule will fire on that legitimate traffic and needs environment-specific tuning before use —
see `docs/false-positive-analysis.md`.

## Supporting telemetry

Output-schema validity, payload size, token counts, and task lifecycle fields are **enrichment
only**. They appear in alert output for investigation context, but no detection track's
verdict depends on them — a tiny malicious mismatch fires; a huge, fully-authorized legitimate
result never does.

## Project workflow

1. **Threat/state model** — `docs/threat-model.md`, `docs/state-invariants.md`
2. **Telemetry contract** — `telemetry/schema.md`, `telemetry/field-mapping.md`, `telemetry/correlation.md`
3. **Normal corpus** — `data/normal/` (13 scenarios / 106 events)
4. **Controlled attacks** — `data/attack/` (18 scenarios / 94 events)
5. **Detection rules** — `detections/` (Sigma, KQL, SPL)
6. **Validation** — `data/validation/` (67 scenarios / 319 events) + `docs/validation-report.md`
7. **Publication** — `publication/` (this block)

## Results

| Corpus | Scenarios | Events |
|---|---|---|
| Normal (Block 3) | 13 | 106 |
| Attack/control (Block 4) | 18 | 94 |
| Validation/stress (Block 6) | 67 | 319 |
| **Total** | **98** | **519** |

**129/129 automated tests pass** (`node --test tests/normal/*.test.js tests/attack/*.test.js
tests/detections/*.test.js tests/validation/*.test.js`), fully deterministic on regeneration.
This count reflects three Track 3 remediation passes: (1) SPL join-key/max=0 fixes, oracle
multi-boundary/independent-leg fixes, a genuine two-model language-equivalence replacement, and
11 regression fixtures (V11-01..V11-11); (2) a scope-aware correction resolving revocation
scope to a specific authorization binding rather than a principal, adding six new project-defined
telemetry fields, a three-outcome (`confirmed_drift`/`evaluated_no_violation`/
`insufficient_evidence`) reporting model, and 13 further regression fixtures (V12-01..V12-13);
(3) an example-driven regression pass built from ten independently-specified examples, which
removed a subtler unsound "sole-candidate" scope inference part 2 still carried, replaced an
"ever observed" approximation with a precise effective-time interval check, and added 6 further
fixtures (V13-01..V13-06) — see `docs/validation-report.md` for the full before/after account.
Re-run the suite yourself rather than assuming any specific number stays fixed across future
changes.

Controlled-corpus precision/recall is 1.000/1.000 for all three tracks under their declared
prerequisites (see `docs/validation-report.md`, "View 1"). **This is not, and must not be read
as, expected production performance.** It confirms the rules implement their own declared logic
correctly against known-labeled synthetic fixtures — nothing more. A separate, explicit
accounting of scenarios that mechanically fire on *benign* traffic once a real-world
prerequisite is violated is in `docs/validation-report.md`, "View 2", and summarized below.

## Operational limitations

Each item below is classified as exactly one of: a **code defect** (a bug in this project's own
rule/oracle logic, now fixed unless stated otherwise), a **deployment prerequisite** (the rule is
correct but depends on an environment condition outside this project's control), a **validation
gap** (not yet checked against something that would strengthen confidence, e.g. a live backend),
or a **scope boundary** (a limitation inherent to the declared detection logic/telemetry
contract, not something a code change here can close).

- **[Code defect, FIXED this pass] SPL's Track 3 expiry-leg join and close-suppression join
  previously keyed on `subscription_id` alone.** `detections/spl/mcp_subscription_authorization_drift.spl`
  now requires `subscription_id` AND `principal_hash` on both, matching KQL, because
  `mcp.subscription.id` is only a per-connection JSON-RPC id and is not globally unique across
  principals (see fixture V11-02).
- **[Code defect, FIXED this pass] SPL's `join type=inner` subsearches previously relied on
  Splunk's `max=1` default,** silently keeping only the first matching authorization_change/open
  event per notification. All such joins now set `max=0` (see fixture V11-01).
- **[Code defect, FIXED this pass] The JS test oracle (`tests/attack/track3util.js`) previously
  required an `open` event to exist, used `.find()` instead of iterating every applicable
  change, and evaluated the revocation/expiry legs as an if/else-if chain instead of two
  independent, unioned legs.** All three are fixed; see `computeTrack3AlertRows` and fixtures
  V11-01, V11-03, V11-04, V11-05.
- **[Validation gap, WITHDRAWN this pass] A prior Track 3 "language equivalence" test compared
  one oracle function's output to itself and proved nothing.** It has been replaced with two
  independently-coded JS models (one per language's own written semantics) compared row-for-row
  — see `tests/validation/language_equivalence.test.js`. This remains a JS-model comparison, not
  native query execution (see "Validation status and disclosures" above).
- **[Code defect, FIXED in a second remediation pass] Same-principal, multiple concurrent
  subscriptions on the revocation leg.** `mcp.subscription.authorization_change` carries no
  subscription id, and the previous pass's revocation leg treated "same principal" as sufficient
  scope — verified against current MCP/OAuth documentation to be a genuine category error, not
  a stylistic one (a principal can hold multiple independent, independently-revocable bindings
  at once). Fixed by adding `mcp.authz.binding_id` and
  `mcp.authz.change.affected_scope`/`affected_binding_ids`, which resolve scope to a specific
  binding without needing a subscription-id field on the change event at all. See fixture
  V12-13 (the corrected counterpart) and `docs/validation-report.md`, "Track 3 remediation pass,
  part 2." Fixture V11-11 is retained, unmodified, as a worked example of legacy telemetry
  (predating the new fields) that still correctly reports `insufficient_evidence` rather than a
  confirmed or silently-cleared result.
- **[Deployment prerequisite, new this pass] Track 3's scope-aware correction only helps
  deployments that emit the new fields.** A deployment that never adds `mcp.authz.binding_id`,
  `mcp.subscription.required_scope`, or `mcp.authz.change.affected_scope`/`affected_binding_ids`/
  `removed_scope` gets the safer default (`insufficient_evidence` on genuine ambiguity, instead
  of the previous pass's unsound principal-only confirm) but not a fully resolved answer. See
  "Track 3 coverage report" in `docs/validation-report.md` for how often this matters in the
  test corpus.
- **[Code defects, FIXED in a third remediation pass] A "sole-candidate" scope inference and an
  "ever observed" timing approximation are both removed.** Part 2's own fix still resolved an
  `affected_scope = unknown` change to a confirmed finding whenever exactly one binding was
  observed for a principal — still an inference, not evidence (fixture V13-03 proves this must
  never happen, even at a candidate count of exactly one). It also approximated
  `affected_scope = all_principal_bindings` as "ever observed anywhere in the queried window"
  rather than a precise effective-time interval (fixture V13-06: a binding issued after an
  account-wide revocation must not be swept up by it). Both are fixed in KQL, SPL, and the JS
  oracle. See `docs/validation-report.md`, "Track 3 remediation pass, part 3."
- **[Code defect, FIXED] Suppression is now checked before scope ambiguity/conflict.** A
  legitimately closed stream needs no scope resolution at all; this was reordered in the JS
  oracle and both query files after being caught while re-deriving fixture V11-07 under the
  stricter unknown-scope rule.
- **[Code defect, FIXED] A self-contradictory record (authoritative timing claimed, no
  `effective_at`) is now explicitly detected** and reported as `insufficient_evidence`
  (`incomplete_timing_evidence`) rather than silently disappearing behind a null-timestamp
  comparison. A real instance of this exact gap was found and fixed in the KQL query itself
  during this pass, not merely documented — see `docs/validation-report.md`, "Track 3
  remediation pass, part 3," "One exact unresolved case identified, not approximated."
- **[Deployment prerequisite] Collector canonicalization can create Track 1 artifacts.** A
  collector that hashes a Base64-sentinel-encoded routing header without decoding it first will
  manufacture a false conflict for an identical underlying value. Treat
  `mcp.validation.source = collector_derived` conflicts as lower-confidence than `server_native`
  ones pending corroboration.
- **[Scope boundary] Track 2 depends on trustworthy server-side authorization audit telemetry.**
  If a server mislabels `mcp.authz.reason`, or an attacker holds the victim's own valid stolen
  credentials, the emitted telemetry looks identical to a legitimate access — not detectable by
  this rule.
- **[Deployment prerequisite] Track 3 depends on trustworthy authorization timing and policy
  semantics.** Clock skew between the authorization server and MCP server, or an authorization
  server misreporting `effective_at`, can hide a real violation. No field in the locked telemetry
  contract represents this risk directly.
- **[Deployment prerequisite] Grace periods / open-stream policy exemptions require tuning.**
  Track 3 has no schema field for either; deployments with such policies will see known,
  documented false positives until they add deployment-side suppression (a query-level constant
  or allowlist).
- **[Scope boundary] Missing telemetry creates visibility gaps, not false negatives that can be
  silently fixed.** No `mcp.task.authorization` event, no
  `mcp.subscription.authorization_change`/`valid_until` — these tracks have nothing to reason
  from and correctly stay silent.
- **[Scope boundary] A compromised but legitimate identity evades authorization-state logic
  entirely.** Track 2 detects a mismatch between caller and authorization context, not that the
  caller's own claimed identity is fraudulent — identity theft is upstream of this telemetry.
- **[Scope boundary] Sigma Track 3 is incomplete compared with KQL/SPL.** Sigma's correlation
  model can order and time-window matched events but cannot compare a field value
  (`effective_at`) against another event's own timestamp, and cannot assert the absence of a
  closing event. The Sigma correlation rule is retained as best-effort hunting content and is
  documented, in its own file, as **not** semantically equivalent to the authoritative KQL/SPL
  implementations.
- **[Validation gap] Native execution against a real Microsoft Sentinel workspace or Splunk
  instance remains pending.** Nothing in this remediation pass changes that — all fixes were
  verified via the JS models/oracle described above, never against a live backend.

## Reproduction

```bash
# Install dependencies (only js-yaml, for Sigma structural validation)
npm install

# Generate the normal corpus (Block 3)
cd tools/harness && node generate.js && cd ../..

# Generate the attack/control corpus (Block 4)
cd tools/harness && node generate_attacks.js && cd ../..

# Generate the validation/stress corpus (Block 6)
cd tools/harness && node generate_validation.js && cd ../..

# Run all tests (122 total; re-run to confirm, do not assume this number)
node --test tests/normal/*.test.js tests/attack/*.test.js tests/detections/*.test.js tests/validation/*.test.js
```

All three generators are deterministic — re-running them reproduces every `.jsonl` file
byte-for-byte (fixed logical clocks, fixed identifiers, fixed HMAC test key).

## Repository layout

```
docs/            threat model, invariants, false-positive analysis, evasion limitations, validation report, SDK-discrepancy notes
telemetry/       the locked audit telemetry contract (schema, field mapping, correlation logic)
data/            normal / attack / validation corpora (JSONL) + manifests + per-corpus READMEs
tools/harness/   deterministic corpus generators + shared hashing/protocol-validation helpers
tests/           Node test suites (normal, attack, detections, validation) — 129 tests
detections/      Sigma / KQL / SPL rules + field-mapping + detection documentation
publication/     detections.ai / GitHub Sync / Intel Exchange / novelty-check materials (this block)
```

## Documentation index

- Threat model & invariants: `docs/threat-model.md`, `docs/state-invariants.md`
- Telemetry contract: `telemetry/schema.md`, `telemetry/field-mapping.md`, `telemetry/correlation.md`
- Detection documentation: `detections/README.md`, `detections/field-mapping.md`
- Quality/limitations: `docs/false-positive-analysis.md`, `docs/evasion-limitations.md`, `docs/validation-report.md`
- Implementation-gap notes: `docs/sdk-discrepancy.md`
- Publication materials: `publication/`

## License

Apache License 2.0 — see `LICENSE`.

## Security

See `SECURITY.md` for responsible-use expectations and how to report an issue with this
project's own content.

## Contributing

See `CONTRIBUTING.md`.
