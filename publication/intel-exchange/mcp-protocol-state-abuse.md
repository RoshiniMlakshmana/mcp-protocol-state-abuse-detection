# MCP Protocol-State Abuse Detection

**Detecting Task Routing, Authorization, and Long-Lived Subscription State Violations**

*Draft technical write-up. Optional publication content — prepared alongside the required
GitHub/detections.ai publication package.*

---

## 1. Executive summary

This project develops and validates three Sigma/KQL/SPL detections for protocol-state abuse in
the Model Context Protocol's (MCP) newer Tasks extension (SEP-2663) and long-lived subscription
mechanism (`subscriptions/listen`, introduced in MCP specification revision `2026-07-28`):

1. **Task routing header/body desynchronization** — a value conflict between the `Mcp-Method`/
   `Mcp-Name` routing headers and the JSON-RPC body they mirror.
2. **Cross-principal task authorization violation** — a syntactically valid task request denied
   because the authenticated caller is not authorized for that specific task/operation.
3. **Long-lived subscription authorization drift** — a subscription notification delivered after
   the authorization that justified it was revoked or expired, with no valid closure in between.

The work includes a threat model, a custom audit-telemetry contract (since MCP defines no
security-audit schema of its own), 79 deterministic test scenarios (420 events) across normal,
controlled-attack, and adversarial-stress corpora, 118 automated tests, and documented
false-positive/evasion analysis. All controlled-corpus metrics are explicitly not claimed as
real-world performance figures. (A subsequent Track 3 remediation pass fixed two SPL join
defects, replaced a vacuous language-equivalence test, and added 11 regression fixtures — see
`docs/validation-report.md`, "Track 3 remediation pass," for the full account; re-run the test
suite rather than assuming these exact counts stay fixed.)

## 2. Why MCP state matters

Most current public MCP security content concentrates on prompt injection, malicious server
configuration, tool poisoning, credential access, and suspicious network/process behavior. That
work is valuable and this document does not suggest otherwise. It addresses a different,
narrower surface: MCP's *protocol state machine* — task lifecycle, authorization decisions tied
to specific protocol objects, and subscription lifecycle — which only exists as a distinct
attack surface because of the `2026-07-28` specification revision's Tasks extension and
stateless-with-long-lived-streams design. A search of major public detection-rule sources
during this project's research phase (`publication/novelty-check.md`) found no equivalent
detection content for any of the three patterns above, though the underlying architectural
risks are, to varying degrees, already discussed publicly (see section 11 and the novelty
check for full detail and citations).

## 3. MCP `2026-07-28` / Tasks context

Key facts this project relied on, each independently verified against primary sources (not
secondary summaries) during Block 1 research:

- MCP `2026-07-28` made the core protocol stateless: no `initialize` handshake, no
  `Mcp-Session-Id`, credentials carried per-request.
- SEP-2243 introduced mandatory `Mcp-Method`/`Mcp-Name` routing headers on Streamable HTTP,
  validated against the JSON-RPC body, with a dedicated `-32020` `HeaderMismatch` error.
- SEP-2663 moved Tasks out of the experimental core and into a formal extension
  (`io.modelcontextprotocol/tasks`), redesigning the method set to `tasks/get`/`tasks/update`/
  `tasks/cancel` (removing the enumeration-prone `tasks/list`), and explicitly documents task
  IDs as bearer-token-like credentials requiring per-request authorization checks.
- SEP-2575 replaced the old `resources/subscribe`/HTTP-GET-SSE model with `subscriptions/listen`
  — a single long-lived POST-response stream, opt-in per notification type, acknowledged via
  `notifications/subscriptions/acknowledged`, correlated by `subscriptionId`.
- A verified implementation gap exists in the wild: the official TypeScript SDK's stable v2 line
  genuinely implements `2026-07-28` core (headers, `subscriptions/listen`) but does not yet
  implement SEP-2663's current shape — its task-status notification type is marked
  `@deprecated ... no SDK runtime` in its own shipped source (`docs/sdk-discrepancy.md`).

## 4. Threat model

Full model: `docs/threat-model.md`, `docs/state-invariants.md`. Trust boundaries: client ↔ MCP
server, client/server ↔ intermediary (header-routing-aware gateways), MCP server ↔
authorization server, and MCP server ↔ its own task/subscription state store (which has no
protocol-level "owner" concept — a server-side implementation detail this project treats as an
overlay, not a wire fact). Principals: authenticated caller, the task's authorization context
(server-defined, not a protocol field), the MCP server as authorization decision point, and the
authorization server as the source of grant truth.

## 5. Detection Track 1 — Task Routing Header/Body Desynchronization

**Condition:** `Mcp-Method`/`Mcp-Name` conflicts with the JSON-RPC body's `method`/
`params.taskId|name|uri`. **Logic:** single-event rule on `mcp.request.validation` where
`mcp.validation.method.result` or `mcp.validation.name.result` equals `conflict` — deliberately
excluding `missing`/`malformed`/`version_incompatible`, which are separate, lower-confidence or
non-violation conditions. Full detail, false positives, and the confirmed collector-
canonicalization risk: `publication/detections-ai/detection-1-task-routing-desynchronization/metadata.md`.

## 6. Detection Track 2 — Cross-Principal Task Authorization Violation

**Condition:** a task operation is denied with `mcp.authz.reason = principal_mismatch` — the
authenticated caller is not the task's authorization-context owner and has no explicit grant.
**Logic:** single-event rule on `mcp.task.authorization`, built entirely on server-side
`mcp.authz.*` evidence, never on the JSON-RPC response code (SEP-2663's anti-enumeration design
makes a denied-existing-task and a nonexistent-task response typically identical). **This
project explicitly credits SEP-2663 for documenting this risk class already** — see section 11.
Full detail: `publication/detections-ai/detection-2-cross-principal-task-authorization/metadata.md`.

## 7. Detection Track 3 — Long-Lived Subscription Authorization Drift

**Condition:** a notification is delivered after an authoritative `effective_at` (or a
computable `mcp.authz.valid_until` expiry, when no revocation event exists) with no valid close
in between. **Logic:** genuine multi-event temporal correlation (KQL/SPL — see section 13 for
why Sigma cannot fully express this). **Explicit deployment prerequisite:** the rule assumes no
unmodeled grace period or permanent open-stream exemption policy — both are confirmed,
documented, mechanically-verified operational false-positive sources if that assumption doesn't
hold (fixtures V5-02, V5-09). Full detail:
`publication/detections-ai/detection-3-subscription-authorization-drift/metadata.md`.

## 8. Telemetry contract

MCP defines no security-audit schema of its own, so this project designed one
(`telemetry/schema.md`), explicitly separating every field into three buckets
(`telemetry/field-mapping.md`):

- **Standard external fields** (OpenTelemetry RPC/HTTP/GenAI semantic conventions, W3C Trace
  Context, ECS categorization fields) — reused, never redefined.
- **MCP wire values** (`Mcp-Method`, `Mcp-Name`, `TaskStatus` enum, `subscriptionId`) — genuinely
  present on the wire per the current specification, cited to primary sources.
- **Project-defined security-audit fields** (`mcp.authz.decision`/`reason`,
  `mcp.authz.change.*`, `mcp.validation.*`) — invented specifically because MCP has no owner
  field, no authorization-changed event, and no wire-level disambiguation between a
  not-found and an unauthorized task.

**These fields are not assumed to exist by default in Sentinel, Splunk, or OpenTelemetry
deployments.** A deployment must actually emit this contract from its own MCP server/gateway
instrumentation before any of these rules can fire on anything.

Hashing/pseudonymization: all identity-bearing fields are HMAC-keyed hashes
(`security.hash.key_id`/`algorithm` carried alongside), never raw identifiers, never derived
from bearer tokens (`telemetry/schema.md` §6).

## 9. Controlled simulation

Three separate, never-merged-on-disk corpora, all generated by a deterministic Node.js harness
(`tools/harness/`, fixed logical clocks, fixed identifiers, fixed HMAC test key):

- **Normal** (`data/normal/`) — 13 scenarios, 106 events: legitimate task operations, polling,
  full lifecycle transitions, legitimate shared access, benign denials, normal subscriptions,
  large payloads, high token counts, missing optional telemetry, protocol-compatibility traffic.
- **Attack/control** (`data/attack/`) — 18 scenarios, 94 events: all three tracks' true
  positives, explicit negative controls, a combined multi-track scenario, and one clearly
  labeled experimental scenario.
- **Validation/stress** (`data/validation/`) — 48 scenarios, 220 events: adversarial-but-benign
  and boundary-condition fixtures designed specifically to expose false positives, plus
  evasion-illustration fixtures documenting what these rules cannot see, including 11 Track 3
  join-key/multi-boundary regression fixtures (V11-01..V11-11) from a later remediation pass.

All attack simulation is local and synthetic — no external MCP server, real credential, or
third-party infrastructure is targeted anywhere in this project.

## 10. Detection results

118/118 automated tests pass (`node --test tests/normal/*.test.js tests/attack/*.test.js
tests/detections/*.test.js tests/validation/*.test.js`), fully deterministic. Controlled-corpus
metrics under each rule's declared prerequisites (`docs/validation-report.md`, "View 1"):

| Track | TP | FP | TN | FN | Precision | Recall |
|---|---|---|---|---|---|---|
| 1 | 8 | 0 | 71 | 0 | 1.000 | 1.000 |
| 2 | 9 | 0 | 70 | 0 | 1.000 | 1.000 |
| 3 (excl. experimental) | 15 | 0 | 63 | 0 | 1.000 | 1.000 |

**These are controlled-corpus implementation-correctness metrics, not real-world precision or
recall.** A separate, mechanically-computed accounting of scenarios that fire on genuinely
benign traffic once a real deployment prerequisite is violated exists specifically because a
single "precision" number cannot honestly represent both questions at once — see section 11 and
`docs/validation-report.md`, "View 2."

## 11. False-positive analysis

Full detail: `docs/false-positive-analysis.md`, `docs/validation-report.md`. Two categories:

**A genuine rule defect, found and fixed:** stress-test fixture V5-03 exposed that the original
Track 3 logic treated *any* authoritative authorization-change event as invalidating, without
checking its type — so a legitimate renewal (`scope_upgraded`) was misclassified as a
revocation. Root-caused and fixed identically across Sigma, KQL, SPL, and the test suite;
regression-verified against all 118 tests.

**A follow-up Track 3 remediation pass** found and fixed two further genuine code defects
specific to SPL (a join-key inconsistency with KQL, and reliance on Splunk's `join` `max=1`
default that could silently drop applicable matches), withdrew a vacuous "language equivalence"
test that compared one function's output to itself, and added 11 new regression fixtures
(V11-01..V11-11) — including one, V11-11, that empirically confirms a previously
reasoned-but-undemonstrated cross-subscription scope boundary is real, and reports it as
unresolved rather than silently patching it with an invented field. Full account:
`docs/validation-report.md`, "Track 3 remediation pass."

**Confirmed operational false positives, not rule defects, deliberately not "fixed" by
fabricating a schema field:**
- **V1-08** (Track 1): a collector that hashes a routing header without correctly decoding its
  Base64-sentinel encoding first manufactures an artificial conflict for an identical
  underlying value.
- **V5-02 / V5-09** (Track 3): a legitimate grace period or a permanent open-stream policy
  exemption is mechanically indistinguishable from a real violation, because the locked
  telemetry contract has no field for either. Tuning recommendation: deployment-side query
  constants/allowlists, not a schema change.

## 12. Known evasions

Full detail, classified detectable/partially detectable/not detectable:
`docs/evasion-limitations.md`. Highlights:
- **Track 1:** keeping routing values consistent evades it by definition — there is no
  violation to detect. Track 2 independently catches the cross-principal case Track 1 cannot
  (demonstrated concretely in Block 4 A10 and Block 6 V2-01).
- **Track 2:** compromising the authorized principal's own identity, or corrupting the
  telemetry-emitting component itself, are both not detectable by this rule — it detects a
  caller/context mismatch, not that a caller's own claimed identity is fraudulent.
- **Track 3:** operating where no revocation/expiry evidence exists at all, exploiting clock
  skew between the authorization server and MCP server, or an authorization server misreporting
  `effective_at`, are all not detectable by query logic alone.

## 13. Sigma/KQL/SPL notes

Track 1 and Track 2 are fully equivalent across Sigma, KQL, and SPL (mechanically verified,
`tests/validation/language_equivalence.test.js`, zero disagreements across 79 scenarios). For
Track 3, "KQL and SPL are equivalent" means two independently-coded JS models of each language's
own written semantics agree row-for-row on the shared corpus (replacing an earlier, vacuous
self-comparison test) — not that either was executed as native KQL or SPL against a real
backend, which remains pending (see `README.md`, "Validation status and disclosures").

**Track 3 is not equivalent across languages, and this is not hidden.** The current official
Sigma correlation specification can order and time-window matched events and group them by
equal field values, but has no mechanism to compare a field value (`effective_at`) against
another event's own timestamp, and no mechanism to assert the absence of a closing event. Of
three non-experimental true positives, the Sigma correlation correctly matches only one (the
case where log order happens to match causal order); it structurally cannot detect silent
expiry at all, and produces a false negative on the "delayed observation" case. **KQL and SPL
are the authoritative Track 3 implementations. The Sigma correlation is retained as best-effort
hunting content, explicitly labeled as such in its own file.**

## 14. Limitations

- Controlled-corpus validation only — see sections 10–11. No real-world telemetry was used or
  is claimed to have been used anywhere in this project.
- Entirely dependent on a deployment actually emitting this project's custom telemetry contract
  — nothing here works against unmodified Sentinel/Splunk/OpenTelemetry defaults.
- The Track 3 revocation-leg join (by principal only, to remain robust against malformed
  telemetry) carries a documented, currently unresolved precision/recall tradeoff for
  principals with multiple concurrent subscriptions — see `docs/validation-report.md`,
  "remaining risks."
- No Sigma CLI / pySigma validation or automated Sigma→KQL/SPL conversion was run (Python is
  unavailable in the development environment); Sigma YAML was validated structurally against
  the specification text instead, and KQL/SPL were hand-written and hand-reviewed, never
  executed against a live Sentinel workspace or Splunk instance.

## 15. References

- MCP specification `2026-07-28`: https://modelcontextprotocol.io/specification/2026-07-28/
- SEP-2663 (Tasks extension): https://github.com/modelcontextprotocol/modelcontextprotocol/blob/main/seps/2663-tasks-extension.md
- SEP-2243 / header routing, folded into the `2026-07-28` changelog: https://modelcontextprotocol.io/specification/2026-07-28/changelog
- Subscriptions pattern: https://modelcontextprotocol.io/specification/2026-07-28/basic/patterns/subscriptions
- Authorization & security considerations: https://modelcontextprotocol.io/specification/2026-07-28/basic/authorization/security-considerations
- Sigma correlation rules specification: https://github.com/SigmaHQ/sigma-specification/blob/main/specification/sigma-correlation-rules-specification.md
- This project's own novelty check (full citation list): `publication/novelty-check.md`

## Distinguishing known research, protocol requirements, and this project's contribution

- **Known security research / already public:** the general risk that MCP task IDs function as
  bearer-token-like credentials (SEP-2663 itself); the architectural discussion of header/body
  desynchronization risk at gateways (public vendor commentary); the general principle that
  revocation should propagate to active sessions (general cloud/agent security guidance).
- **Protocol requirements (not this project's invention):** the `HeaderMismatch` validation
  rule, the Tasks extension's authorization-check mandate, the `subscriptions/listen` mechanism
  itself — all specified by MCP `2026-07-28`/SEP-2663/SEP-2575, verified against primary
  sources, not invented for this project.
- **This project's detection-engineering contribution:** the custom audit-telemetry contract
  that makes these conditions observable at all; the specific Sigma/KQL/SPL detection logic;
  the deterministic multi-corpus validation methodology; the documented false-positive/evasion
  analysis; and the explicit, mechanically-verified characterization of where Sigma's
  correlation model falls short of KQL/SPL for Track 3.
