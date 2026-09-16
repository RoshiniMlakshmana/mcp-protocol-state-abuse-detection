# MCP Cross-Principal Task Authorization Violation

**Canonical source (keep in sync if either changes):**
`detections/sigma/mcp_cross_principal_task_authorization.yml`,
`detections/kql/mcp_cross_principal_task_authorization.kql`,
`detections/spl/mcp_cross_principal_task_authorization.spl`

## Description

Detects a server-side authorization denial for an MCP task operation
(`tasks/get`/`tasks/update`/`tasks/cancel`, or task creation) where the denial reason
specifically records a principal/task-context mismatch (`mcp.authz.reason = "principal_mismatch"`)
— i.e., the authenticated caller is not the principal the task's authorization context is bound
to, and is not covered by an explicit shared-access grant. A syntactically valid, correctly
routed task request is denied purely on authorization grounds.

## Why it matters

SEP-2663 (the MCP Tasks extension) treats task IDs as bearer-token-like credentials to
server-held state and mandates a per-request authorization check specifically because of this
risk. **This project does not claim to have discovered this risk class.** SEP-2663 documents it
directly, and this rule operationalizes an already-known, spec-acknowledged risk into concrete,
testable detection logic — see "Known security research" below.

This rule is deliberately narrower than "any denial": ordinary policy denials, insufficient-scope
denials, and denials for a nonexistent task (`mcp.authz.reason` = `policy_denied` /
`insufficient_scope` / `context_unbound`) are excluded on purpose, because they are not
cross-principal task misuse.

**This rule never infers a violation from the JSON-RPC response code.** Per SEP-2663's own
anti-enumeration design, a denied request against an existing-but-unauthorized task and a
request against a genuinely nonexistent task both typically surface the identical `-32602`
(Invalid params) response — specifically so a caller cannot use the error to enumerate valid
task IDs belonging to other principals. That ambiguity is exactly why this rule is built on
`mcp.authz.*` server-side evidence fields, never on `rpc.status_code`/`http.response.status_code`.

## Data source

Project-defined MCP security audit telemetry (`telemetry/schema.md`). **These fields are not
assumed to exist by default in Sentinel, Splunk, or OpenTelemetry deployments.**

## Required fields

| Field | Source category |
|---|---|
| `event.name` | project-defined event taxonomy |
| `mcp.authz.decision` | project-defined (`allow`\|`deny`) |
| `mcp.authz.reason` | project-defined enum — only `principal_mismatch` gates this rule |
| `principal.id_hash`, `mcp.task.id_hash` | project-defined, pseudonymized |
| `mcp.task.operation` | project-defined |
| `mcp.task.authz_context_id_hash` | project-defined, pseudonymized — **investigation context only, never a filter condition; a null value must never gate this rule in either direction** |

## Query — Sigma

```yaml
title: MCP Cross-Principal Task Authorization Violation
id: 92a674ad-4000-4a11-98e6-0ed1e93d54b7
status: experimental
description: |
    Detects a server-side authorization denial for an MCP task operation where the denial
    reason specifically records a principal/task-context mismatch
    (mcp.authz.reason = "principal_mismatch"). Relies entirely on explicit server-side
    authorization evidence, never on the JSON-RPC response code, since SEP-2663's
    anti-enumeration design makes a denied-but-existing task and a nonexistent task both
    typically surface the same -32602 response.
references:
    - https://modelcontextprotocol.io/specification/2026-07-28/schema#headermismatcherror
    - https://github.com/modelcontextprotocol/modelcontextprotocol/blob/main/seps/2663-tasks-extension.md
    - https://modelcontextprotocol.io/seps/2663-tasks-extension
author: MCP Protocol-State Abuse Detection project
date: 2026-09-13
logsource:
    category: application
    product: mcp
    service: mcp_security_audit
detection:
    selection:
        event.name: mcp.task.authorization
        mcp.authz.decision: deny
        mcp.authz.reason: principal_mismatch
    condition: selection
fields:
    - principal.id_hash
    - mcp.task.id_hash
    - mcp.task.authz_context_id_hash
    - mcp.task.operation
    - mcp.authz.reason
    - mcp.authz.policy_version
falsepositives:
    - Incorrect server-side policy configuration that denies (and mislabels as
      principal_mismatch) an access that should have been an explicit shared grant.
    - Shared/delegated access implemented at the application layer but not yet reflected in
      authorization telemetry.
    - Stale authorization context racing a recent task/grant transfer between principals.
level: high
```

## Query — KQL

`MCPSecurityAudit` is a **project/example table name — not a built-in Microsoft Sentinel
table.** See `telemetry/field-mapping.md`.

```kql
MCPSecurityAudit
| where ['event.name'] == "mcp.task.authorization"
| where ['mcp.authz.decision'] == "deny"
| where ['mcp.authz.reason'] == "principal_mismatch"
// Excludes, by construction: policy_denied / insufficient_scope / context_unbound / unknown
| extend Severity = "High", DetectionTrack = "Track2_CrossPrincipalTaskAuthorization"
| project
    ['timestamp'], Severity, DetectionTrack, ['principal.id_hash'], ['principal.authenticated'],
    ['mcp.task.id_hash'], ['mcp.task.authz_context_id_hash'], ['mcp.task.operation'],
    ['mcp.authz.decision'], ['mcp.authz.reason'], ['mcp.authz.policy_version']
| order by ['timestamp'] asc
```

## Query — SPL

`index=mcp_security_audit sourcetype=mcp:audit:json` is an **explicit placeholder — Splunk does
not natively emit MCP security audit events.**

```spl
index=mcp_security_audit sourcetype=mcp:audit:json "event.name"="mcp.task.authorization"
    "mcp.authz.decision"="deny" "mcp.authz.reason"="principal_mismatch"
| eval Severity="High"
| eval DetectionTrack="Track2_CrossPrincipalTaskAuthorization"
| table _time Severity DetectionTrack "principal.id_hash" "principal.authenticated"
    "mcp.task.id_hash" "mcp.task.authz_context_id_hash" "mcp.task.operation"
    "mcp.authz.decision" "mcp.authz.reason" "mcp.authz.policy_version"
| sort 0 _time
```

## False positives

- Incorrect server-side policy configuration mislabeling what should be an `authorized_grant`
  as `principal_mismatch`.
- Shared/delegated access implemented at the application layer but not yet reflected in
  authorization telemetry.
- Stale authorization context racing a recent task/grant transfer.
- No environmental false positive was found for this rule during controlled stress testing
  (`docs/validation-report.md`) — its enum-based evidence has no equivalent "grace period" or
  "canonicalization" ambiguity to the other two tracks.

## Limitations

- Entirely dependent on the emitting server correctly labeling `mcp.authz.reason`. A server
  that denies for the right reason but mislabels it (e.g., emits `unknown`) produces a false
  negative no wire-level signal can catch.
- If a deployment's authorization system is itself fooled (e.g., an attacker holding the
  victim's own valid, stolen credentials), the emitted telemetry is indistinguishable from a
  legitimate access — not a Track 2 detection gap in the rule-logic sense, but a fundamental
  observability limit. See `docs/evasion-limitations.md`.
- If `mcp.task.authorization` audit instrumentation is disabled or fails silently while the
  server still enforces authorization correctly, this rule has nothing to fire on.

## Validation and native-execution disclosures

- **All validation data is synthetic**, generated by this project's own deterministic reference
  harness (`tools/harness/`) — never production telemetry, never captured from a real MCP
  deployment.
- **This detection requires custom MCP security audit instrumentation and field mapping** — see
  "Data source" above and `telemetry/field-mapping.md`. None of the required fields are emitted
  by Sentinel, Splunk, or any OpenTelemetry deployment by default.
- **An alert from this rule does not, by itself, prove compromise or successful unauthorized
  access.** See "Limitations" above and `docs/evasion-limitations.md` before treating a hit as
  confirmed malicious.
- **KQL and SPL are implemented counterparts of the Sigma logic above**, mechanically verified
  identical via three independently-written JS predicates comparing outcomes across the full
  stress corpus (`tests/validation/language_equivalence.test.js`) — this is JS-model comparison,
  not native execution of either language.
- **Native KQL execution:** 3 representative test cases for this track (A7, A11, A17 —
  synthetic fixtures) were separately, and later, executed against a real Kusto query engine:
  Microsoft's local "Kusto emulator" Docker image
  (`mcr.microsoft.com/azuredataexplorer/kustainer-linux`). **This is native KQL query execution
  only — it is NOT a deployed Microsoft Sentinel analytics rule, workspace, or alert pipeline.**
  All 3 produced the expected outcome. Full record (part of a 25-fixture, 28-execution run
  spanning all three tracks): `evidence/native-execution/manifest.jsonl`.
- **Native SPL execution has not been performed for this detection. Zero SPL fixtures were
  executed.** An authorized attempt was made using a local Splunk Free instance (license
  verified genuinely Free, not a trial) but the instance became unresponsive after a required
  configuration restart before any fixture could be tested; the root cause is unconfirmed. See
  `evidence/native-execution/splunk-prep/STATUS.md`.

## Investigation fields

`principal.id_hash`, `mcp.task.id_hash`, `mcp.task.authz_context_id_hash`, `mcp.task.operation`,
`mcp.authz.policy_version`, `trace_id` (if present).

## References

- MCP specification `2026-07-28`: https://modelcontextprotocol.io/specification/2026-07-28/schema#headermismatcherror
- SEP-2663 (Tasks extension), raw source: https://github.com/modelcontextprotocol/modelcontextprotocol/blob/main/seps/2663-tasks-extension.md
- SEP-2663 (Tasks extension), historical record: https://modelcontextprotocol.io/seps/2663-tasks-extension

## Known security research (credit, not a novelty claim)

The underlying MCP task-ID cross-principal risk class is **not** something this project
discovered. SEP-2663 itself documents that task IDs function as bearer-token-like credentials
and specifically mandates the authorization check this rule verifies is actually working. This
rule turns an already-known, spec-acknowledged risk into concrete, testable detection content —
see `publication/novelty-check.md` for what public detection *content* (as opposed to risk
discussion) this project could and could not find.

## Severity recommendation

**High.** The evidence required to fire is already an explicit, disambiguated server-side
statement of the violation.

## MITRE ATT&CK

`No precise ATT&CK technique assigned.` **(Corrected in this publication pass.)** An earlier
draft of this rule proposed `T1550.001` (Use Alternate Authentication Material). On review this
was withdrawn: in every scenario this rule detects, the caller authenticates with their own
legitimate credentials — the violation is an *authorization*-boundary failure (accessing an
object identifier the caller is not entitled to), not an *authentication*-material failure
(using someone else's token to authenticate as them), which is what T1550.001 specifically
describes. This is closer to an IDOR-style object-authorization issue, for which ATT&CK — an
adversary-behavior taxonomy, not an application-vulnerability taxonomy — has no precise
technique. No tag is assigned rather than force one because the behavior sounds generally like
credential access.
