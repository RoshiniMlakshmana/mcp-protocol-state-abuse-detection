# Resume-Safe Project Description

Every claim below is deliberately scoped to what this project actually did and can defend under
questioning. See `publication/novelty-check.md` for the evidence behind the novelty language.

## One-line version

Developed and validated protocol-aware Sigma/KQL/SPL detections for MCP (Model Context
Protocol) task-routing, cross-principal task-authorization, and long-lived subscription
authorization-drift abuse, backed by a deterministic normal/attack/validation telemetry corpus
and false-positive/evasion testing.

## Two-bullet resume version

- Designed a threat model and custom audit-telemetry contract for MCP's Tasks (SEP-2663) and
  long-lived subscription (`subscriptions/listen`) extensions, then built three Sigma/KQL/SPL
  detections for protocol-routing desynchronization, cross-principal task authorization
  violations, and post-revocation subscription drift — an area with no public detection
  equivalent found during the project's research phase (per `publication/novelty-check.md`).
- Built a 68-scenario, 363-event deterministic test corpus (normal, controlled-attack, and
  adversarial-stress fixtures) and 104 automated tests to validate detection logic, discovering
  and fixing a real false-positive-causing rule defect, documenting known operational false
  positives and evasion limitations, and comparing Sigma/KQL/SPL semantic equivalence across all
  three detections.

## Interview explanation

"I built a small, self-contained detection-engineering project around a part of the Model
Context Protocol that's newer and less covered by existing security content than things like
prompt injection or malicious tool configs — specifically, MCP's Tasks extension and its
long-lived subscription mechanism.

I started by reading the actual current MCP specification and its Tasks extension SEP directly
— not just blog summaries — to build a threat model with three concrete, testable invariants:
that a routing header has to agree with the JSON-RPC body it's describing; that a task
operation has to be authorized for the specific principal making the request, not just any
authenticated caller; and that a subscription shouldn't keep delivering notifications after the
authorization behind it has been revoked or expired.

For each of those, I designed a custom audit telemetry schema — since MCP itself doesn't define
security-audit-specific fields — and then wrote Sigma, KQL, and SPL detections against it. The
part I'm most proud of is the validation work: I built three separate deterministic JSONL
corpora — normal traffic, controlled attacks, and then a third 'stress test' corpus specifically
designed to try to break my own rules with benign-but-tricky edge cases. That stress testing
actually found a real bug — my subscription-drift rule was treating a legitimate authorization
*renewal* the same as a revocation — so I root-caused it, fixed it identically across Sigma,
KQL, SPL, and my test suite, and documented the before/after rather than just quietly patching
it.

I also spent time being honest about what doesn't work: Sigma's correlation feature literally
can't express part of the subscription-drift logic — it can't compare a timestamp field against
another event's own timestamp — so I documented that limitation explicitly rather than shipping
a Sigma rule that looks equivalent to the KQL/SPL version but isn't. And for the
cross-principal-task-authorization detection, I made a point of crediting the MCP Tasks
extension's own specification for already identifying that risk class — I didn't want to imply
I'd discovered something that was already documented upstream."

## Guardrails for any external-facing use of this description

- Never say "discovered a new MCP vulnerability" — the risk classes (especially cross-principal
  task authorization) are credited to SEP-2663 and existing MCP Tasks discussion, not claimed as
  a personal discovery.
- Never say "first" or "novel" detection — say "no public equivalent found during the
  documented research phase," and be ready to describe exactly what was searched (see
  `publication/novelty-check.md`).
- Never cite the 1.000/1.000 controlled-corpus precision/recall figures as real-world
  performance — they are stated everywhere in this project as controlled-corpus correctness
  metrics only.
- If asked "did you find this bug for real or did you plant it," answer honestly: the V5-03
  false positive was a genuine defect in logic written earlier in the same project, discovered
  by a fixture specifically designed to test authorization-renewal handling — not a
  pre-arranged demonstration.
