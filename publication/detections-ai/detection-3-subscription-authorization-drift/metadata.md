# MCP Long-Lived Subscription Authorization Drift

**Canonical source (KQL/SPL are authoritative; keep in sync if either changes):**
`detections/kql/mcp_subscription_authorization_drift.kql`,
`detections/spl/mcp_subscription_authorization_drift.spl`.
Sigma (best-effort only — see below): `detections/sigma/mcp_subscription_drift_correlation.yml`
+ its three component rules.

## Description

Detects a `subscriptions/listen` notification delivered **after** the authorization that
justified the subscription became invalid (authoritative revocation/expiry, or a computable
`mcp.authz.valid_until` boundary when no revocation event exists at all), while the
subscription remained active with **no valid `mcp.subscription.close` in between**.

## Why it matters

MCP `2026-07-28` made the protocol stateless and treats credentials as per-request input — but
`subscriptions/listen` is architecturally a single, very-long-lived request whose response
stream never receives a fresh per-notification credential check. Nothing in the specification
(or the current official SDK, per `docs/sdk-discrepancy.md`) forces a server to notice a
mid-stream authorization change and close the stream. Per this project's own threat model, an
ordinary drifted `notifications/resources/updated` exposes a change/activity signal (a URI),
not necessarily protected content — **this detection does not assert content disclosure**, only
continued event visibility past the point authorization ceased to be valid.

## ⚠️ Deployment prerequisite — read before enabling as a paging alert

This high-confidence rule is appropriate **only** where an authoritative `revoked`, `expired`,
or `scope_downgraded` `effective_at` means the subscription is genuinely no longer authorized to
receive relevant notifications at and after that instant. **If your organization has grace
periods, grandfathered/open-stream exemptions, or other policy semantics that legitimately
permit delivery after that timestamp, this rule will fire on that legitimate traffic** and
requires environment-specific tuning (a query-level grace-period constant or exemption
allowlist) before deployment — no such field exists in the underlying telemetry contract to
express this automatically. Confirmed in this project's own stress testing (fixtures V5-02,
V5-09 — `docs/validation-report.md`, View 2).

## Data source

Project-defined MCP security audit telemetry (`telemetry/schema.md`). **These fields are not
assumed to exist by default in Sentinel, Splunk, or OpenTelemetry deployments.**

## Required fields

| Field | Source category |
|---|---|
| `mcp.subscription.id`, `principal.id_hash` | join/group-by keys (MCP wire value + project-defined pseudonymized field) |
| `mcp.authz.change.effective_at`, `mcp.authz.change.timing_confidence` | project-defined — preferred boundary when `timing_confidence = authoritative` |
| `mcp.authz.change.type` | project-defined — must be `revoked`/`expired`/`scope_downgraded` to count as invalidating (`scope_upgraded` must NOT, per a confirmed Block 6 fix) |
| `mcp.authz.valid_until` | project-defined — expiry boundary used when no change event exists |
| `mcp.subscription.notification_type`, notification's own timestamp | MCP wire value / envelope field |
| `mcp.subscription.close.reason` | project-defined — used to suppress a correctly-closed stream |

## Query — KQL (authoritative)

`MCPSecurityAudit` is a **project/example table name — not a built-in Microsoft Sentinel
table.** See `telemetry/field-mapping.md`.

```kql
let AuthoritativeChanges = MCPSecurityAudit
| where ['event.name'] == "mcp.subscription.authorization_change"
| where ['mcp.authz.change.timing_confidence'] == "authoritative"
| where ['mcp.authz.change.type'] in ("revoked", "expired", "scope_downgraded")
| project
    principal_hash = ['principal.id_hash'],
    effective_at = todatetime(['mcp.authz.change.effective_at']),
    change_type = ['mcp.authz.change.type'],
    change_source = ['mcp.authz.change.source'];

let ExpiryBoundaries = MCPSecurityAudit
| where ['event.name'] == "mcp.subscription.open"
| where isnotempty(['mcp.authz.valid_until'])
| project
    subscription_id = tostring(['mcp.subscription.id']),
    principal_hash = ['principal.id_hash'],
    valid_until = todatetime(['mcp.authz.valid_until']);

let Notifications = MCPSecurityAudit
| where ['event.name'] == "mcp.subscription.notification"
| project
    subscription_id = tostring(['mcp.subscription.id']),
    principal_hash = ['principal.id_hash'],
    notif_time = todatetime(['timestamp']),
    notification_type = ['mcp.subscription.notification_type'];

let Closes = MCPSecurityAudit
| where ['event.name'] == "mcp.subscription.close"
| project
    subscription_id = tostring(['mcp.subscription.id']),
    principal_hash = ['principal.id_hash'],
    close_time = todatetime(['timestamp']);

// FIX (Track 3 remediation pass): joins on BOTH subscription_id AND principal_hash, not
// subscription_id alone -- mcp.subscription.id is only a per-connection JSON-RPC id and is not
// guaranteed unique across different principals' connections. principal.id_hash is already a
// required field on mcp.subscription.close (telemetry/schema.md).
let ClosedBeforeNotification = Notifications
| join kind=leftouter (Closes) on subscription_id, principal_hash
| where isnotempty(close_time) and close_time <= notif_time
| distinct subscription_id, principal_hash, notif_time;

let RevocationDrift = Notifications
| join kind=inner (AuthoritativeChanges) on principal_hash
| where notif_time > effective_at
| join kind=leftanti (ClosedBeforeNotification) on subscription_id, principal_hash, notif_time
| extend Confidence = "high", Boundary = "effective_at", BoundaryTime = effective_at,
         AuthzChangeType = change_type, AuthzChangeSource = change_source;

let ExpiryDrift = Notifications
| join kind=inner (ExpiryBoundaries) on subscription_id, principal_hash
| where notif_time > valid_until
| join kind=leftanti (ClosedBeforeNotification) on subscription_id, principal_hash, notif_time
| extend Confidence = "high", Boundary = "valid_until", BoundaryTime = valid_until,
         AuthzChangeType = "expired", AuthzChangeSource = "token_expiry_computed";

let HighConfidenceDrift = RevocationDrift
| project subscription_id, principal_hash, notif_time, notification_type, Confidence, Boundary, BoundaryTime, AuthzChangeType, AuthzChangeSource
| union (ExpiryDrift | project subscription_id, principal_hash, notif_time, notification_type, Confidence, Boundary, BoundaryTime, AuthzChangeType, AuthzChangeSource);

HighConfidenceDrift
| extend Severity = "High", DetectionTrack = "Track3_SubscriptionAuthorizationDrift"
| project notif_time, Severity, DetectionTrack, subscription_id, principal_hash, notification_type,
    Boundary, BoundaryTime, AuthzChangeType, AuthzChangeSource, Confidence
| order by notif_time asc
```

A separate, clearly-labeled `detected_at`-only informational query (never merged into the above)
is in the full file: `detections/kql/mcp_subscription_authorization_drift.kql`.

## Query — SPL (authoritative)

`index=mcp_security_audit sourcetype=mcp:audit:json` is an **explicit placeholder — Splunk does
not natively emit MCP security audit events.**

```spl
index=mcp_security_audit sourcetype=mcp:audit:json "event.name"="mcp.subscription.notification"
| rename "mcp.subscription.id" as subscription_id, "principal.id_hash" as principal_hash,
    "mcp.subscription.notification_type" as notification_type
| eval notif_time=_time
| join type=inner max=0 principal_hash
    [ search index=mcp_security_audit sourcetype=mcp:audit:json
        "event.name"="mcp.subscription.authorization_change"
        "mcp.authz.change.timing_confidence"="authoritative"
        ("mcp.authz.change.type"="revoked" OR "mcp.authz.change.type"="expired" OR "mcp.authz.change.type"="scope_downgraded")
      | rename "principal.id_hash" as principal_hash,
          "mcp.authz.change.type" as change_type, "mcp.authz.change.source" as change_source
      | eval effective_at=strptime('mcp.authz.change.effective_at', "%Y-%m-%dT%H:%M:%S.%3QZ")
      | fields principal_hash effective_at change_type change_source ]
| where notif_time > effective_at
| join type=left subscription_id principal_hash
    [ search index=mcp_security_audit sourcetype=mcp:audit:json "event.name"="mcp.subscription.close"
      | rename "mcp.subscription.id" as subscription_id, "principal.id_hash" as principal_hash
      | eval close_time=_time
      | stats min(close_time) as earliest_close_time by subscription_id, principal_hash ]
| where isnull(earliest_close_time) OR earliest_close_time > notif_time
| eval Boundary="effective_at", BoundaryTime=strftime(effective_at, "%Y-%m-%dT%H:%M:%S.%3QZ")
| eval Confidence="high"
| table notif_time subscription_id principal_hash notification_type Boundary BoundaryTime
    change_type change_source Confidence
| append
    [ search index=mcp_security_audit sourcetype=mcp:audit:json "event.name"="mcp.subscription.notification"
      | rename "mcp.subscription.id" as subscription_id, "principal.id_hash" as principal_hash,
          "mcp.subscription.notification_type" as notification_type
      | eval notif_time=_time
      | join type=inner max=0 subscription_id principal_hash
          [ search index=mcp_security_audit sourcetype=mcp:audit:json "event.name"="mcp.subscription.open"
              "mcp.authz.valid_until"=*
            | rename "mcp.subscription.id" as subscription_id, "principal.id_hash" as principal_hash
            | eval valid_until=strptime('mcp.authz.valid_until', "%Y-%m-%dT%H:%M:%S.%3QZ")
            | fields subscription_id principal_hash valid_until ]
      | where notif_time > valid_until
      | join type=left subscription_id principal_hash
          [ search index=mcp_security_audit sourcetype=mcp:audit:json "event.name"="mcp.subscription.close"
            | rename "mcp.subscription.id" as subscription_id, "principal.id_hash" as principal_hash
            | eval close_time=_time
            | stats min(close_time) as earliest_close_time by subscription_id, principal_hash ]
      | where isnull(earliest_close_time) OR earliest_close_time > notif_time
      | eval Boundary="valid_until", BoundaryTime=strftime(valid_until, "%Y-%m-%dT%H:%M:%S.%3QZ")
      | eval change_type="expired", change_source="token_expiry_computed", Confidence="high"
      | table notif_time subscription_id principal_hash notification_type Boundary BoundaryTime
          change_type change_source Confidence ]
| eval Severity="High", DetectionTrack="Track3_SubscriptionAuthorizationDrift"
| sort 0 notif_time
```

**FIXES (Track 3 remediation pass), see `docs/validation-report.md`:** (1) the expiry-leg join
now requires `subscription_id` AND `principal_hash` (previously `subscription_id` alone,
inconsistent with the KQL version above); (2) every `join type=inner` now sets `max=0`, since
Splunk's `join` command defaults to `max=1` and would otherwise silently keep only the first
matching authorization_change/open event per notification; (3) the close-suppression joins now
require `subscription_id` AND `principal_hash` (previously `subscription_id` alone), for the
same reason as the KQL fix above.

**Note on the ASCII-quote `strptime()` format string above:** it assumes ISO-8601 with
millisecond precision (`2026-09-05T10:10:00.000Z`). This has not been executed against a live
Splunk instance in this project (no Splunk instance was available during development — see
`detections/README.md`, "validation tooling used") — validate it against your own ingested
field format before relying on it.

A separate, clearly-labeled `detected_at`-only informational search (never merged into the
above) is in the full file: `detections/spl/mcp_subscription_authorization_drift.spl`.

## Query — Sigma: BEST-EFFORT CORRELATION / HUNTING CONTENT ONLY — NOT SEMANTICALLY EQUIVALENT TO KQL/SPL

**Do not treat the Sigma correlation below as full detection coverage for this track.** The
current official Sigma correlation specification can order and time-window matched events and
group them by equal field values, but has **no mechanism to compare one event's field value
(`effective_at`) against another event's own timestamp, and no mechanism to assert the absence
of a third event type** (a valid close). As a direct, mechanically-verified consequence
(`tests/validation/language_equivalence.test.js`) — **"equivalence" here and above means two
independently-coded JS models of each language's own written semantics agree row-for-row on a
shared test corpus, not that any of KQL, SPL, or Sigma was executed natively against a real
backend (that remains pending — see `README.md`)**:

| Scenario | KQL/SPL (authoritative) | Sigma correlation | Agree? |
|---|---|---|---|
| Authoritative revocation, notification logged after it (normal case) | fires | fires | yes |
| Silent expiry, no revocation event at all | fires | **cannot fire — no event exists to correlate against** | **NO** |
| Authoritative revocation, but notification logged (in raw event order) *before* the revocation event, even though `effective_at` proves it was already a violation | fires | **does not fire — orders by log timestamp, not by `effective_at`** | **NO** |
| Correctly, promptly closed stream | does not fire | does not fire | yes |

`detections/sigma/mcp_subscription_drift_correlation.yml` (`type: temporal_ordered`, built from
`mcp_subscription_authorization_change_authoritative.yml` and
`mcp_subscription_notification.yml`, grouped by `principal.id_hash`) is retained because it
still demonstrates part of the condition and its component rules remain independently useful
for cross-platform hunting — **not** because it is a complete substitute for the KQL/SPL logic
above. See the Sigma file's own description field for the full, in-file limitation statement,
and `detections/README.md`, "Sigma limitations for Track 3," for the complete analysis.

## False positives

- **Grace periods** (confirmed, `data/validation/track3/v5_grace_period_policy.jsonl`, scenario
  V5-02): a notification within a deployment-defined grace window after a scope downgrade fires
  mechanically, because no grace-period field exists in the schema.
- **Permanent policy exemptions** (confirmed, scenario V5-09): a documented, deployment-specific
  decision to allow certain already-open streams to continue indefinitely after revocation is
  likewise invisible to the schema and fires mechanically.
- Clock skew between the authorization server and the MCP server can produce a **false
  negative** (a real violation hidden because the reported `effective_at` looks later than it
  truly was) — see `docs/false-positive-analysis.md`.
- Inaccurate `effective_at` reported by the authorization server — the rule trusts the value it
  is given.

## Limitations

- No grace-period or permanent-exemption field exists in the locked telemetry contract — see
  "Deployment prerequisite" above. Tuning recommendation: apply a deployment-side constant
  (`WHERE notif_time > boundary + grace_period`) or allowlist downstream of this query, rather
  than expecting the base query to know about product policy.
- Depends on a push-based revocation feed for the `effective_at` path, which most real OAuth
  deployments do not have — the `valid_until`/silent-expiry leg exists specifically so detection
  does not depend on one existing at all.
- **[Scope boundary, confirmed, not resolved]** The revocation-leg join is by `principal.id_hash`
  only (not also `mcp.subscription.id`) — intentional, so that a notification event missing
  `mcp.subscription.id` (malformed telemetry) still correlates — but this means a principal
  holding two or more concurrent subscriptions, one revoked and one still legitimately valid,
  could have the still-valid subscription's notifications cross-correlated against the other's
  revocation boundary. This is a genuine, unresolved precision/recall tradeoff, now empirically
  demonstrated by fixture V11-11 (`data/validation/track3/v11_same_principal_cross_subscription_risk.jsonl`)
  and documented in `docs/validation-report.md`, "remaining risks" / "Track 3 remediation pass" —
  not resolved in this release, and not fixable without a subscription-id field on
  `authorization_change` events that does not exist in the locked telemetry contract.
- **[Code defect, FIXED]** The close-suppression join and the SPL expiry-leg join previously keyed
  on `subscription_id` alone in one or both languages, which could let one principal's close
  event suppress a different principal's genuine violation (or miscorrelate expiry across
  principals) whenever `mcp.subscription.id` values collided. Both now require
  `subscription_id` AND `principal_hash`. See `docs/validation-report.md`, "Track 3 remediation
  pass," fixture V11-02.
- **[Code defect, FIXED]** SPL's `join type=inner` subsearches previously relied on Splunk's
  `max=1` default and could silently drop additional applicable authorization_change/open
  events. All such joins now set `max=0`. See fixture V11-01.
- `detected_at`-only timing is never promoted to this rule's high-confidence result set by
  design — see the separate informational query.

## Investigation fields

`mcp.subscription.id`, `principal.id_hash`, `mcp.subscription.notification_type`,
`mcp.authz.change.type`/`source`, the resolved boundary type/time, `trace_id` (if present).

## References

- MCP specification `2026-07-28`, subscriptions pattern: https://modelcontextprotocol.io/specification/2026-07-28/basic/patterns/subscriptions
- MCP specification `2026-07-28`, authorization: https://modelcontextprotocol.io/specification/2026-07-28/basic/authorization
- MCP specification `2026-07-28`, authorization security considerations: https://modelcontextprotocol.io/specification/2026-07-28/basic/authorization/security-considerations
- Sigma correlation rules specification (for the documented Sigma limitation): https://github.com/SigmaHQ/sigma-specification/blob/main/specification/sigma-correlation-rules-specification.md

## Severity recommendation

**High** for the KQL/SPL authoritative queries, when the boundary is authoritative
`effective_at` or a computable `valid_until`. **Never high confidence** for `detected_at`-only
timing — that remains a separate, low-confidence/informational query. The Sigma correlation, to
the extent it fires at all, should be treated as hunting content, not an equivalent alert.

## MITRE ATT&CK

`No precise ATT&CK technique assigned.` This models a systemic authorization-propagation-delay
exposure window (a control/timing gap), not a distinct adversary technique — an attacker does
not need to do anything beyond passively continuing to receive already-established stream data,
which does not map cleanly onto any ATT&CK technique.
