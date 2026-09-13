# Evasion / Detection Limitations

Block 6 deliverable. Describes, per track, realistically how an attacker could operate without
tripping the corresponding detection — grounded in concrete, tested fixtures
(`data/normal/`, `data/attack/`, `data/validation/`), not speculation. Each is classified as
**detectable**, **partially detectable**, or **not detectable** with the current locked
telemetry contract (`telemetry/schema.md`).

This document explains *why* a gap exists so defenders can reason about compensating controls.
It does not provide offensive operational guidance beyond what is necessary to explain the
detection boundary (e.g., it does not describe how to obtain a stolen token — only that if one
is obtained, this specific telemetry cannot see the theft).

---

## Track 1 — MCP Task Routing Header/Body Desynchronization

**The evasion:** keep routing header values byte-identical to the JSON-RPC body. Since Track 1
exists specifically to catch *disagreement* between the header and body, an attacker who simply
never introduces one is invisible to it by construction — this is not a weakness to fix, it is
the rule's exact, intended scope.

**Concrete demonstration:** Block 4 A10 and Block 6 V2-01 both show an attacker with a
correctly-formatted, "stolen" or otherwise obtained valid task identifier submitting a
perfectly-routed request. Track 1's routing-validation fields (`mcp.validation.method.result`,
`mcp.validation.name.result`) both correctly resolve to `match` — there is no routing evidence
of anything wrong, because there genuinely is none at the routing layer.

**Secondary evasion — protocol-version downgrade:** header validation is gated on the
negotiated protocol version (only `2026-07-28` requires `Mcp-Method`/`Mcp-Name`, per SEP-2243).
A client that can force, or falsely claim, an older negotiated version sheds the header
requirement entirely and could route a mismatched request without ever populating the fields
Track 1 inspects. The MCP specification's own transport section anticipates this at the
intermediary layer ("verify that `MCP-Protocol-Version` indicates a version that requires
header–body validation... reject the request rather than trusting unvalidated header values" —
`docs/threat-model.md` §14) — detecting the downgrade attempt itself is a distinct,
protocol-negotiation-integrity concern outside this project's three locked tracks.

**Classification:** detectable by design when a real conflict exists; **not detectable** when
routing is genuinely consistent (by definition — there is nothing to detect) or when a
protocol-version downgrade removes the header requirement before a mismatch could ever be
observed.

**What catches what routing evasion cannot:** Track 2. See Block 4 A10 and Block 6 V2-01 — both
demonstrate Track 1 correctly staying silent while Track 2 independently fires on the same
event set.

---

## Track 2 — MCP Cross-Principal Task Authorization Violation

**The evasion:** compromise the authorized principal's own identity, or corrupt/bypass the
authorization decision source, rather than attempting to access a task as a *visibly different*
principal.

**Sub-case 1 — stolen valid identity (Block 6 V4-01):** an attacker who has obtained the
victim's own valid, authenticated credentials makes the request *as* the victim. The
authorization system genuinely (and, from its own point of view, correctly) resolves the caller
to the rightful owner: `mcp.authz.decision = allow`, `mcp.authz.reason = authorized_owner`.
Track 2 detects a *mismatch* between the caller and the authorization context — it has no way
to detect that the caller's own claimed identity is itself fraudulent, because that
determination happens entirely upstream of MCP task-authorization telemetry (in whatever system
issued and validated the credential).
**Classification: not detectable.** Would require separate identity/credential-theft
detection (e.g., impossible-travel analysis, token-binding anomalies, IP/device reputation) —
entirely outside MCP task-authorization telemetry and outside this project's three tracks.

**Sub-case 2 — authorization telemetry disabled (Block 6 V4-02):** the server correctly
enforces authorization (the request is genuinely denied), but the `mcp.task.authorization` audit
event is never emitted — instrumentation disabled, crashed, or suppressed by a compromised
component. Track 1's routing telemetry remains intact and clean, so it correctly finds nothing
wrong; Track 2 has zero evidence to act on.
**Classification: partially detectable** — not by Track 2 itself, but the *absence* of an
expected `mcp.task.authorization` event for a request that reaches a task operation is itself a
detectable signal, via a telemetry-completeness/coverage monitor (a companion operational
check, not one of the three locked security tracks — recommended for a later block or
deployment runbook, not implemented here).

**Sub-case 3 — corrupted/compromised telemetry producer:** if the component emitting audit
events is itself compromised, it can emit whatever `mcp.authz.decision`/`reason` it chooses,
including a fabricated `allow`/`authorized_owner` for an attack that actually occurred. This is
not a distinct rule gap so much as a restatement of a general principle: **any detection built
on telemetry is only as trustworthy as the telemetry's producer.** No amount of query logic
compensates for a compromised source. Standard mitigations (out of scope for this project) are
telemetry integrity/signing and separating the audit-emission path from the code path an
attacker who compromises the server would control.
**Classification: not detectable** by any query-layer logic; requires telemetry-integrity
controls upstream of detection.

---

## Track 3 — MCP Long-Lived Subscription Authorization Drift

**The evasion:** operate specifically where authorization-change telemetry is absent, delayed,
or untrustworthy, since Track 3's entire detection surface is built from *inferring* invalidity
from `mcp.authz.change.*` or `mcp.authz.valid_until` — there is no direct, positive signal of
"this stream should not still be open."

**Sub-case 1 — no invalidity evidence at all (Block 6 V6-01):** neither an
`mcp.subscription.authorization_change` event nor an `mcp.authz.valid_until` value exists
anywhere in the telemetry for a subscription that has, in reality, outlived its authorization by
hours. There is nothing for Track 3 to reason from.
**Classification: not detectable.** This is a hard prerequisite, not a tunable gap — a
deployment that emits neither field has zero Track 3 coverage by construction, regardless of
how the query is written.

**Sub-case 2 — malformed/incomplete telemetry on the notification (Block 6 V6-02):** a
notification event is missing `mcp.subscription.id` entirely. The revocation-leg join (by
`principal.id_hash`) still succeeds and the drift is still flagged — but the close-suppression
check, which relies on `mcp.subscription.id` to scope which close events are relevant, cannot
reliably clear or confirm this specific record.
**Classification: partially detectable** — the violation is still caught, but with reduced
confidence in the close-suppression step specifically. See also the **residual, unresolved
precision risk** this implies: the same principal-scoped join that makes this case still
detectable would, for a principal with two or more concurrent subscriptions (one revoked, one
still legitimately valid), risk cross-correlating the wrong pair. `docs/validation-report.md`
documents this as an open tradeoff, not a solved problem.

**Sub-case 3 — clock skew (Block 6 V5-06):** if the authorization server's and MCP server's
clocks disagree (e.g., the AS's clock runs fast), a reported `effective_at` can appear to be
*after* a notification that, in true wall-clock time, actually followed the real revocation.
This produces a **false negative** — a real violation the current telemetry, taken at face
value, cannot distinguish from a benign ordering.
**Classification: not detectable** without synchronized clocks (e.g., NTP) or an explicit
clock-skew-compensation mechanism, neither of which the locked telemetry contract defines.

**Sub-case 4 — inaccurate `effective_at` from the authorization server:** whether from a bug, a
misconfiguration, or a compromised/malicious authorization server deliberately misreporting a
later `effective_at` than the true revocation time, the detection trusts the value it is given.
A malicious authorization server that controls what it reports can, in principle, manufacture a
window in which its own revocation appears to have "already been respected" by the time it
actually reports it.
**Classification: not detectable** at the MCP-telemetry layer; would require independent,
out-of-band verification of the authorization server's own revocation log — outside this
project's scope.

**Sub-case 5 — dropped stream/notification events:** if notification or subscription-lifecycle
events are selectively dropped from the telemetry pipeline (rather than simply delayed), Track 3
cannot reason about activity it never observed. This is the same telemetry-integrity dependency
described under Track 2 sub-case 3, applied to the subscription event stream.
**Classification: not detectable** by query logic alone; a telemetry-completeness/coverage
monitor (counting expected vs. observed event volume per subscription) is the only mitigation,
and it is outside this project's three locked tracks.

---

## Summary table

| Track | Evasion | Classification |
|---|---|---|
| 1 | Keep routing values consistent | Not detectable (by design — no violation exists) |
| 1 | Force/spoof a protocol-version downgrade | Not detectable (header requirement no longer applies) |
| 2 | Compromise/steal the authorized principal's identity | Not detectable |
| 2 | Disable or suppress authorization audit telemetry | Partially detectable (via a telemetry-completeness monitor, not Track 2 itself) |
| 2 | Compromise the telemetry-emitting component itself | Not detectable by query logic |
| 3 | Operate where no revocation/expiry evidence exists at all | Not detectable |
| 3 | Malformed telemetry (missing subscription id) | Partially detectable (with a documented, residual precision tradeoff) |
| 3 | Exploit authorization-server/MCP-server clock skew | Not detectable |
| 3 | Authorization server misreports `effective_at` | Not detectable |
| 3 | Drop stream/notification events from the pipeline | Not detectable by query logic |
