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

This rule now reports one of three outcomes per notification — `ConfirmedDrift`,
`EvaluatedNoViolation`, or `InsufficientEvidence` — rather than a single fired/not-fired boolean;
only `ConfirmedDrift` warrants a page. It is appropriate to page on **only** where an
authoritative `revoked`/`expired` `effective_at`, or a `scope_downgraded` change proven relevant
via `required_scope`/`removed_scope`, means the subscription is genuinely no longer authorized
to receive relevant notifications at and after that instant. **If your organization has
grandfathered/open-stream exemptions or other policy semantics that legitimately permit delivery
after that timestamp, this rule will still report `ConfirmedDrift` on that legitimate traffic**
and requires environment-specific tuning (a query-level exemption allowlist) before deployment —
no such field exists in the underlying telemetry contract to express this automatically.
Confirmed in this project's own stress testing (fixture V5-09 — `docs/validation-report.md`,
View 2). **This rule also depends on the new `mcp.authz.binding_id`/`mcp.subscription.required_scope`/
`mcp.authz.change.affected_scope` fields (see "Required fields" below) to resolve revocation
scope precisely — a deployment that has not instrumented them yet will see more
`InsufficientEvidence` results and fewer resolved `ConfirmedDrift`/`EvaluatedNoViolation` ones,
which is the safe default, not a rule defect.**

## Data source

Project-defined MCP security audit telemetry (`telemetry/schema.md`). **These fields are not
assumed to exist by default in Sentinel, Splunk, or OpenTelemetry deployments.**

## Required fields

| Field | Source category |
|---|---|
| `mcp.subscription.instance_id`, `principal.id_hash` | **(new, scope-aware correction)** authoritative join/group-by keys — `instance_id` is project-defined (not the connection-scoped wire `mcp.subscription.id`); `principal.id_hash` is project-defined pseudonymized |
| `mcp.authz.binding_id` | **(new)** project-defined — the specific authorization binding backing an instance; required on `.open`, optional-if-proven on `.notification` |
| `mcp.authz.change.affected_scope`, `affected_binding_ids` | **(new)** project-defined — resolves WHICH binding(s) a change affects; `unknown`/absent ALWAYS reports `insufficient_evidence` (never inferred from how many bindings happen to be observed, and never a blanket principal-wide assumption) |
| `mcp.subscription.required_scope`, `mcp.authz.change.removed_scope` | **(new)** project-defined — required to determine whether a `scope_downgraded` change is relevant to a given instance |
| `mcp.authz.change.effective_at`, `mcp.authz.change.timing_confidence` | project-defined — preferred boundary when `timing_confidence = authoritative` |
| `mcp.authz.change.type` | project-defined — must be `revoked`/`expired`/`scope_downgraded` to count as invalidating (`scope_upgraded` must NOT) |
| `mcp.authz.valid_until` | project-defined — expiry boundary; may also appear on `.notification` when `binding_id` is present (proven rebinding) |
| `mcp.subscription.notification_type`, notification's own timestamp | MCP wire value / envelope field |
| `mcp.subscription.close.reason` | project-defined — used to suppress a correctly-closed stream |

**Legacy-compatibility fallbacks exist for every new field above** (an event predating a field
is not rejected, just resolved more conservatively — see `telemetry/schema.md` §5 and
`telemetry/correlation.md`). `mcp.authz.grant_snapshot_hash` (pre-existing field) is drift-hinting
only and MUST NOT be used as an identity/join key — that role belongs to `mcp.authz.binding_id`.

## Query — KQL (authoritative)

`MCPSecurityAudit` is a **project/example table name — not a built-in Microsoft Sentinel
table.** See `telemetry/field-mapping.md`. Implements `telemetry/correlation.md`'s "Resolving
affected bindings" reference algorithm — see that document and
`detections/kql/mcp_subscription_authorization_drift.kql`'s own header comment for the full
citation trail. **This revision removes the "sole-candidate fallback" and the "ever observed"
approximation an earlier revision of this query used** — see "Limitations" below.

```kql
let InvalidatingTypes = dynamic(["revoked", "expired", "scope_downgraded"]);

let Opens = MCPSecurityAudit
| where ['event.name'] == "mcp.subscription.open"
| project
    subscriptionId = tostring(['mcp.subscription.id']),
    instanceId = tostring(coalesce(['mcp.subscription.instance_id'], strcat(['principal.id_hash'], ":", ['mcp.subscription.id']))),
    principalHash = ['principal.id_hash'],
    bindingId = tostring(coalesce(['mcp.authz.binding_id'], strcat("legacy:", ['principal.id_hash'], ":", ['mcp.subscription.id']))),
    requiredScope = ['mcp.subscription.required_scope'],
    validUntil = todatetime(coalesce(['mcp.authz.valid_until'], ['mcp.authz.grant_expiry'])),
    openTime = todatetime(['timestamp']),
    keyId = ['security.hash.key_id'];

let Notifications = MCPSecurityAudit
| where ['event.name'] == "mcp.subscription.notification"
| project
    subscriptionId = tostring(['mcp.subscription.id']),
    instanceId = tostring(coalesce(['mcp.subscription.instance_id'], strcat(['principal.id_hash'], ":", ['mcp.subscription.id']))),
    principalHash = ['principal.id_hash'],
    notifTime = todatetime(['timestamp']),
    notificationType = ['mcp.subscription.notification_type'],
    ownBindingId = tostring(['mcp.authz.binding_id']),
    ownValidUntil = todatetime(['mcp.authz.valid_until']),
    keyId = ['security.hash.key_id'];

// Pre-aggregated to the earliest close per instance BEFORE any join -- see the KQL file's own
// comment for why joining raw close rows directly can multiply/mis-suppress.
let EarliestClose = MCPSecurityAudit
| where ['event.name'] == "mcp.subscription.close"
| extend instanceId = tostring(coalesce(['mcp.subscription.instance_id'], strcat(['principal.id_hash'], ":", ['mcp.subscription.id']))), principalHash = ['principal.id_hash'], closeTime = todatetime(['timestamp'])
| summarize earliestCloseTime = min(closeTime) by instanceId, principalHash;

let Changes = MCPSecurityAudit
| where ['event.name'] == "mcp.subscription.authorization_change"
| where ['mcp.authz.change.timing_confidence'] == "authoritative"
| where ['mcp.authz.change.type'] in (InvalidatingTypes)
| project
    principalHash = ['principal.id_hash'],
    changeType = ['mcp.authz.change.type'],
    changeSource = ['mcp.authz.change.source'],
    effectiveAt = todatetime(['mcp.authz.change.effective_at']),
    affectedScope = tostring(coalesce(['mcp.authz.change.affected_scope'], "unknown")),
    affectedBindingIds = coalesce(['mcp.authz.change.affected_binding_ids'], dynamic([])),
    removedScope = ['mcp.authz.change.removed_scope'],
    keyId = ['security.hash.key_id'];

// Conflicting-evidence pre-pass: a binding named invalidated by one authoritative change and
// ALSO named scope_upgraded by another cannot be resolved by picking a side.
let InvalidatedBindings = Changes
| where affectedScope == "binding" and changeType in (InvalidatingTypes)
| mv-expand bindingId = affectedBindingIds to typeof(string)
| distinct bindingId;
let UpgradedBindings = Changes
| where affectedScope == "binding" and changeType == "scope_upgraded"
| mv-expand bindingId = affectedBindingIds to typeof(string)
| distinct bindingId;
let ConflictedBindings = InvalidatedBindings | join kind=inner (UpgradedBindings) on bindingId | distinct bindingId;

let NotificationsResolved = Notifications
| join kind=leftouter (Opens | project instanceId, openBindingId = bindingId, openValidUntil = validUntil, requiredScope, openTime, openKeyId = keyId) on instanceId
| join kind=leftouter (EarliestClose) on instanceId, principalHash
| extend effectiveBindingId = coalesce(ownBindingId, openBindingId)
| extend effectiveValidUntil = iif(isnotempty(ownBindingId) and isnotnull(ownValidUntil), ownValidUntil, openValidUntil)
| extend epochMismatch = isnotempty(openKeyId) and isnotempty(keyId) and openKeyId != keyId
| extend isConflicted = effectiveBindingId in (ConflictedBindings);

// Signal 1: expiry leg. A suppressed (closed-before) crossing is EvaluatedNoViolation, never
// silently dropped.
let ExpirySignals = NotificationsResolved
| where isnotnull(effectiveValidUntil) and not(epochMismatch)
| extend crossed = notifTime > effectiveValidUntil,
         suppressed = isnotnull(earliestCloseTime) and earliestCloseTime <= notifTime
| extend Outcome = iif(crossed and not(suppressed), "ConfirmedDrift", "EvaluatedNoViolation"),
         Priority = iif(crossed and not(suppressed), 3, 1),
         Boundary = "valid_until", BoundaryTime = effectiveValidUntil, Reason = ""
| distinct instanceId, subscriptionId, principalHash, notifTime, notificationType, effectiveBindingId, Outcome, Priority, Boundary, BoundaryTime, changeType1=tostring(""), changeSource1=tostring(""), Reason;

// Signal 2: epoch mismatch.
let EpochSignals = NotificationsResolved
| where epochMismatch
| project instanceId, subscriptionId, principalHash, notifTime, notificationType, effectiveBindingId,
    Outcome = "InsufficientEvidence", Priority = 2, Boundary = "", BoundaryTime = datetime(null),
    changeType1 = "", changeSource1 = "", Reason = "incompatible_hash_epoch";

// Signal 2b: incomplete timing evidence -- a change record claiming authoritative timing but
// omitting effective_at is self-contradictory; detected explicitly here, BEFORE any timing
// comparison, so it surfaces as InsufficientEvidence instead of silently disappearing behind a
// null-timestamp comparison.
let MalformedTimingChanges = MCPSecurityAudit
| where ['event.name'] == "mcp.subscription.authorization_change"
| where ['mcp.authz.change.timing_confidence'] == "authoritative"
| where ['mcp.authz.change.type'] in (InvalidatingTypes)
| where isempty(['mcp.authz.change.effective_at'])
| project principalHash = ['principal.id_hash'];
let MalformedTimingSignals = NotificationsResolved
| where not(epochMismatch)
| join kind=inner (MalformedTimingChanges) on principalHash
| project instanceId, subscriptionId, principalHash, notifTime, notificationType, effectiveBindingId,
    Outcome = "InsufficientEvidence", Priority = 2, Boundary = "", BoundaryTime = datetime(null),
    changeType1 = "", changeSource1 = "", Reason = "incomplete_timing_evidence";

// Signal 3: revocation / downgrade leg, expanded per Changes row. Timing and suppression are
// resolved BEFORE scope -- a legitimately closed stream or a not-yet-effective change never
// needs scope resolution at all.
let RevocationCandidates = NotificationsResolved
| where not(epochMismatch)
| join kind=inner (Changes) on principalHash
| extend crossed = notifTime > effectiveAt,
         suppressed = isnotnull(earliestCloseTime) and earliestCloseTime <= notifTime
| where crossed
// PRECISE effective-time interval check for all_principal_bindings -- NOT "ever observed
// anywhere in the window": the binding must have been open AND not already closed by the time
// the change took effect.
| extend bindingExistedAtEffectiveAt = isnull(openTime) or openTime <= effectiveAt
| extend bindingAlreadyClosedByEffectiveAt = isnotnull(earliestCloseTime) and earliestCloseTime <= effectiveAt
| extend Applies = case(
    suppressed, "suppressed",
    isConflicted, "conflict",
    affectedScope == "all_principal_bindings", iif(bindingExistedAtEffectiveAt and not(bindingAlreadyClosedByEffectiveAt), "yes", "no"),
    affectedScope == "binding", case(isempty(effectiveBindingId), "ambiguous", set_has_element(affectedBindingIds, effectiveBindingId), "yes", "no"),
    "ambiguous")
| where Applies != "no" and Applies != "suppressed";

let ClearedByClose = NotificationsResolved
| where not(epochMismatch)
| join kind=inner (Changes) on principalHash
| extend crossed = notifTime > effectiveAt,
         suppressed = isnotnull(earliestCloseTime) and earliestCloseTime <= notifTime
| where crossed and suppressed
| project instanceId, subscriptionId, principalHash, notifTime, notificationType, effectiveBindingId,
    Outcome = "EvaluatedNoViolation", Priority = 1, Boundary = "", BoundaryTime = datetime(null),
    changeType1 = "", changeSource1 = "", Reason = "";

let RevocationSignals = RevocationCandidates
| where Applies == "yes"
| extend ScopeOk = case(
    changeType != "scope_downgraded", "yes",
    isempty(requiredScope) or isempty(removedScope), "missing",
    array_length(set_intersect(requiredScope, removedScope)) > 0, "yes",
    "irrelevant")
| extend Outcome = case(
    ScopeOk == "missing", "InsufficientEvidence",
    ScopeOk == "irrelevant", "EvaluatedNoViolation",
    "ConfirmedDrift")
| extend Priority = case(Outcome == "ConfirmedDrift", 3, Outcome == "InsufficientEvidence", 2, 1)
| extend Reason = iif(ScopeOk == "missing", "missing_scope_evidence", "")
| project instanceId, subscriptionId, principalHash, notifTime, notificationType, effectiveBindingId,
    Outcome, Priority, Boundary = "effective_at", BoundaryTime = effectiveAt,
    changeType1 = tostring(changeType), changeSource1 = tostring(changeSource), Reason;

let ConflictSignals = RevocationCandidates
| where Applies == "conflict"
| project instanceId, subscriptionId, principalHash, notifTime, notificationType, effectiveBindingId,
    Outcome = "InsufficientEvidence", Priority = 2, Boundary = "", BoundaryTime = datetime(null),
    changeType1 = "", changeSource1 = "", Reason = "conflicting_evidence";

let AmbiguousSignals = RevocationCandidates
| where Applies == "ambiguous"
| project instanceId, subscriptionId, principalHash, notifTime, notificationType, effectiveBindingId,
    Outcome = "InsufficientEvidence", Priority = 2, Boundary = "", BoundaryTime = datetime(null),
    changeType1 = "", changeSource1 = "", Reason = "ambiguous_scope";

// Baseline: every notification gets a floor row so summarize always has something to pick.
let BaselineSignals = NotificationsResolved
| project instanceId, subscriptionId, principalHash, notifTime, notificationType, effectiveBindingId,
    Outcome = "InsufficientEvidence", Priority = 0, Boundary = "", BoundaryTime = datetime(null),
    changeType1 = "", changeSource1 = "", Reason = "no_invalidity_evidence";

let AllSignals = union ExpirySignals, EpochSignals, MalformedTimingSignals, RevocationSignals, ConflictSignals, AmbiguousSignals, ClearedByClose, BaselineSignals;

// One row per (instance, notification): the highest-priority signal wins; ties at the max
// (e.g. revocation AND expiry both ConfirmedDrift) are both retained.
AllSignals
| summarize MaxPriority = max(Priority) by instanceId, subscriptionId, principalHash, notifTime, notificationType
| join kind=inner (AllSignals) on instanceId, subscriptionId, principalHash, notifTime, notificationType
| where Priority == MaxPriority
| distinct instanceId, subscriptionId, principalHash, notifTime, notificationType, effectiveBindingId,
    Outcome, Boundary, BoundaryTime, changeType1, changeSource1, Reason
| extend Severity = case(Outcome == "ConfirmedDrift", "High", Outcome == "InsufficientEvidence", "Medium", "Informational"),
         DetectionTrack = "Track3_SubscriptionAuthorizationDrift"
| project
    notifTime, Outcome, Severity, DetectionTrack, instanceId, subscriptionId, principalHash,
    notificationType, BindingId = effectiveBindingId, Boundary, BoundaryTime,
    AuthzChangeType = changeType1, AuthzChangeSource = changeSource1, Reason
| order by notifTime asc
```

A separate, clearly-labeled `detected_at`-only informational note (never promoted into the query
above at all, by design) is in the full file's closing comment block:
`detections/kql/mcp_subscription_authorization_drift.kql`.

## Query — SPL (authoritative)

`index=mcp_security_audit sourcetype=mcp:audit:json` is an **explicit placeholder — Splunk does
not natively emit MCP security audit events.** This SPL query is a direct STRUCTURAL PORT of the
KQL query above for this pass (same tables, same resolution algorithm, same documented
simplification), not an independent re-derivation from first principles — so the two stay
honestly comparable rather than accidentally diverging in ways neither author intended.

```spl
index=mcp_security_audit sourcetype=mcp:audit:json
| eval instance_id=coalesce('mcp.subscription.instance_id', 'principal.id_hash'.":".'mcp.subscription.id')
| eval key_id='security.hash.key_id'
| eval is_open=if('event.name'=="mcp.subscription.open", 1, 0)
| eval open_binding_id=if(is_open=1, coalesce('mcp.authz.binding_id', "legacy:"."principal.id_hash".":".'mcp.subscription.id'), null())
| eval open_required_scope=if(is_open=1, 'mcp.subscription.required_scope', null())
| eval open_valid_until=if(is_open=1, strptime(coalesce('mcp.authz.valid_until','mcp.authz.grant_expiry'), "%Y-%m-%dT%H:%M:%S.%3QZ"), null())
| eval open_key_id=if(is_open=1, key_id, null())
| eval open_time=if(is_open=1, _time, null())
| eval is_notif=if('event.name'=="mcp.subscription.notification", 1, 0)
| eval own_binding_id=if(is_notif=1, 'mcp.authz.binding_id', null())
| eval own_valid_until=if(is_notif=1 AND isnotnull('mcp.authz.binding_id'), strptime('mcp.authz.valid_until', "%Y-%m-%dT%H:%M:%S.%3QZ"), null())
| eval notif_time=if(is_notif=1, _time, null())
| eval is_close=if('event.name'=="mcp.subscription.close", 1, 0)
| eval close_time=if(is_close=1, _time, null())
| eval is_change=if('event.name'=="mcp.subscription.authorization_change" AND 'mcp.authz.change.timing_confidence'=="authoritative" AND ('mcp.authz.change.type'="revoked" OR 'mcp.authz.change.type'="expired" OR 'mcp.authz.change.type'="scope_downgraded"), 1, 0)
| eval affected_scope=if(is_change=1, coalesce('mcp.authz.change.affected_scope', "unknown"), null())
| eval has_effective_at=if(is_change=1, isnotnull('mcp.authz.change.effective_at') AND 'mcp.authz.change.effective_at'!="", 1, 0)
| eventstats min(close_time) as earliest_close_time by instance_id, "principal.id_hash"
| eval invalidated_marker=if(is_change=1 AND affected_scope=="binding" AND ('mcp.authz.change.type'="revoked" OR 'mcp.authz.change.type'="expired" OR 'mcp.authz.change.type'="scope_downgraded"), 'mcp.authz.change.affected_binding_ids', null())
| eval upgraded_marker=if(is_change=1 AND affected_scope=="binding" AND 'mcp.authz.change.type'="scope_upgraded", 'mcp.authz.change.affected_binding_ids', null())
| eventstats values(invalidated_marker) as all_invalidated_bindings, values(upgraded_marker) as all_upgraded_bindings
| where is_notif=1
| join type=left instance_id
    [ search index=mcp_security_audit sourcetype=mcp:audit:json "event.name"="mcp.subscription.open"
      | eval instance_id=coalesce('mcp.subscription.instance_id', 'principal.id_hash'.":".'mcp.subscription.id')
      | eval open_binding_id2=coalesce('mcp.authz.binding_id', "legacy:"."principal.id_hash".":".'mcp.subscription.id')
      | eval open_required_scope2='mcp.subscription.required_scope'
      | eval open_valid_until2=strptime(coalesce('mcp.authz.valid_until','mcp.authz.grant_expiry'), "%Y-%m-%dT%H:%M:%S.%3QZ")
      | eval open_key_id2='security.hash.key_id'
      | eval open_time2=_time
      | fields instance_id open_binding_id2 open_required_scope2 open_valid_until2 open_key_id2 open_time2 ]
| eval effective_binding_id=coalesce(own_binding_id, open_binding_id2)
| eval effective_valid_until=if(isnotnull(own_binding_id) AND isnotnull(own_valid_until), own_valid_until, open_valid_until2)
| eval epoch_mismatch=if(isnotnull(open_key_id2) AND isnotnull(key_id) AND open_key_id2!=key_id, 1, 0)
| eval is_conflicted=if(isnotnull(effective_binding_id) AND mvfind(all_invalidated_bindings, effective_binding_id)>=0 AND mvfind(all_upgraded_bindings, effective_binding_id)>=0, 1, 0)
| eval expiry_applicable=if(isnotnull(effective_valid_until) AND epoch_mismatch=0, 1, 0)
| eval expiry_crossed=if(expiry_applicable=1 AND notif_time>effective_valid_until, 1, 0)
| eval expiry_suppressed=if(isnotnull(earliest_close_time) AND earliest_close_time<=notif_time, 1, 0)
| eval expiry_outcome=case(expiry_applicable=0, null(), expiry_crossed=1 AND expiry_suppressed=0, "ConfirmedDrift", 1=1, "EvaluatedNoViolation")
| eval expiry_priority=case(expiry_outcome=="ConfirmedDrift", 3, expiry_outcome=="EvaluatedNoViolation", 1, 1=1, null())
| eval epoch_priority=if(epoch_mismatch=1, 2, null())
`comment("Incomplete timing evidence: a change claims authoritative timing but omits effective_at -- detected explicitly so it surfaces as InsufficientEvidence instead of silently failing a later timing comparison")`
| join type=left "principal.id_hash"
    [ search index=mcp_security_audit sourcetype=mcp:audit:json "event.name"="mcp.subscription.authorization_change"
        "mcp.authz.change.timing_confidence"="authoritative"
        ("mcp.authz.change.type"="revoked" OR "mcp.authz.change.type"="expired" OR "mcp.authz.change.type"="scope_downgraded")
        NOT "mcp.authz.change.effective_at"=*
      | eval has_malformed_timing_change=1
      | stats max(has_malformed_timing_change) as has_malformed_timing_change by "principal.id_hash" ]
| eval malformed_timing_priority=if(has_malformed_timing_change=1, 2, null())
| join type=left "principal.id_hash"
    [ search index=mcp_security_audit sourcetype=mcp:audit:json "event.name"="mcp.subscription.authorization_change"
        "mcp.authz.change.timing_confidence"="authoritative"
        ("mcp.authz.change.type"="revoked" OR "mcp.authz.change.type"="expired" OR "mcp.authz.change.type"="scope_downgraded")
        "mcp.authz.change.effective_at"=*
      | eval change_effective_at2=strptime('mcp.authz.change.effective_at', "%Y-%m-%dT%H:%M:%S.%3QZ")
      | eval affected_scope2=coalesce('mcp.authz.change.affected_scope', "unknown")
      | rename "mcp.authz.change.affected_binding_ids" as affected_binding_ids2, "mcp.authz.change.removed_scope" as removed_scope2,
          "mcp.authz.change.type" as change_type2, "mcp.authz.change.source" as change_source2
      | fields "principal.id_hash" change_effective_at2 affected_scope2 affected_binding_ids2 removed_scope2 change_type2 change_source2 ]
| eval rev_crossed=if(notif_time>change_effective_at2, 1, 0)
| eval rev_suppressed=if(isnotnull(earliest_close_time) AND earliest_close_time<=notif_time, 1, 0)
`comment("PRECISE effective-time interval for all_principal_bindings -- NOT ever observed anywhere in the window: the binding must have been open AND not already closed by the time the change took effect")`
| eval binding_existed_at_effective_at=if(isnull(open_time2) OR open_time2<=change_effective_at2, 1, 0)
| eval binding_already_closed_by_effective_at=if(isnotnull(earliest_close_time) AND earliest_close_time<=change_effective_at2, 1, 0)
| eval rev_applies=case(
    rev_crossed=0, "not_yet",
    rev_suppressed=1, "suppressed",
    is_conflicted=1, "conflict",
    affected_scope2=="all_principal_bindings", if(binding_existed_at_effective_at=1 AND binding_already_closed_by_effective_at=0, "yes", "no"),
    affected_scope2=="binding", if(isnull(effective_binding_id), "ambiguous", if(mvfind(affected_binding_ids2, effective_binding_id)>=0, "yes", "no")),
    1=1, "ambiguous")
`comment("EXACT, order-independent multivalue scope intersection (Track 3 remediation pass, part 4). A prior revision compared only mvindex(field,0) on each side via an unanchored mvfind() regex -- both a positional bug and a substring-match bug. Fixed via mvmap()/mvfind() with an anchored (\\A...\\z), literally-quoted (\\Q...\\E) pattern -- Splunk's regex engine is PCRE2, which supports \\Q...\\E literal quoting")`
| eval removed_scope_matches=if(isnotnull(removed_scope2), mvmap(removed_scope2, if(mvfind(open_required_scope2, "\\A\\Q" . removed_scope2 . "\\E\\z")>=0, removed_scope2, null())), null())
| eval scope_overlap_count=mvcount(removed_scope_matches)
| eval rev_scope_ok=case(
    rev_applies!="yes", null(),
    change_type2!="scope_downgraded", "yes",
    isnull(open_required_scope2) OR isnull(removed_scope2), "missing",
    scope_overlap_count>0, "yes",
    1=1, "irrelevant")
| eval rev_outcome=case(
    rev_applies=="not_yet", null(),
    rev_applies=="suppressed", "EvaluatedNoViolation",
    rev_applies=="ambiguous", "InsufficientEvidence",
    rev_applies=="conflict", "InsufficientEvidence",
    rev_applies=="no", null(),
    rev_applies=="yes" AND rev_scope_ok=="missing", "InsufficientEvidence",
    rev_applies=="yes" AND rev_scope_ok=="irrelevant", "EvaluatedNoViolation",
    rev_applies=="yes", "ConfirmedDrift",
    1=1, null())
| eval rev_reason=case(rev_applies=="ambiguous", "ambiguous_scope", rev_applies=="conflict", "conflicting_evidence", rev_applies=="yes" AND rev_scope_ok=="missing", "missing_scope_evidence", 1=1, "")
| eval rev_priority=case(rev_outcome=="ConfirmedDrift", 3, rev_outcome=="InsufficientEvidence", 2, rev_outcome=="EvaluatedNoViolation", 1, 1=1, null())
| eval overall_priority=case(
    coalesce(expiry_priority,0)>=coalesce(rev_priority,0) AND coalesce(expiry_priority,0)>=coalesce(epoch_priority,0) AND coalesce(expiry_priority,0)>=coalesce(malformed_timing_priority,0), coalesce(expiry_priority,0),
    coalesce(rev_priority,0)>=coalesce(epoch_priority,0) AND coalesce(rev_priority,0)>=coalesce(malformed_timing_priority,0), coalesce(rev_priority,0),
    coalesce(epoch_priority,0)>=coalesce(malformed_timing_priority,0), coalesce(epoch_priority,0),
    1=1, coalesce(malformed_timing_priority,0))
| eval Outcome=case(
    overall_priority=3, "ConfirmedDrift",
    overall_priority=2, "InsufficientEvidence",
    overall_priority=1, "EvaluatedNoViolation",
    1=1, "InsufficientEvidence")
| eval Reason=case(
    Outcome=="InsufficientEvidence" AND overall_priority=2 AND rev_priority=2 AND isnotnull(rev_reason) AND rev_reason!="", rev_reason,
    Outcome=="InsufficientEvidence" AND overall_priority=2 AND epoch_priority=2, "incompatible_hash_epoch",
    Outcome=="InsufficientEvidence" AND overall_priority=2 AND malformed_timing_priority=2, "incomplete_timing_evidence",
    Outcome=="InsufficientEvidence" AND overall_priority=0, "no_invalidity_evidence",
    1=1, "")
| eval Boundary=case(overall_priority=3 AND rev_priority=3, "effective_at", overall_priority=3 AND expiry_priority=3, "valid_until", 1=1, "")
| eval BoundaryTime=case(Boundary=="effective_at", strftime(change_effective_at2, "%Y-%m-%dT%H:%M:%S.%3QZ"), Boundary=="valid_until", strftime(effective_valid_until, "%Y-%m-%dT%H:%M:%S.%3QZ"), 1=1, "")
| eval Severity=case(Outcome=="ConfirmedDrift", "High", Outcome=="InsufficientEvidence", "Medium", 1=1, "Informational")
| eval DetectionTrack="Track3_SubscriptionAuthorizationDrift"
| eval row_priority=case(Outcome=="ConfirmedDrift", 3, Outcome=="InsufficientEvidence", 2, Outcome=="EvaluatedNoViolation", 1, 1=1, 0)
| eventstats max(row_priority) as max_row_priority by instance_id, notif_time
| where row_priority=max_row_priority
| dedup instance_id notif_time Outcome Boundary BoundaryTime
| rename "mcp.subscription.id" as subscription_id, "principal.id_hash" as principal_hash, "mcp.subscription.notification_type" as notification_type
| table notif_time Outcome Severity DetectionTrack instance_id subscription_id principal_hash notification_type effective_binding_id Boundary BoundaryTime change_type2 change_source2 Reason
| rename effective_binding_id as BindingId, change_type2 as AuthzChangeType, change_source2 as AuthzChangeSource
| sort 0 notif_time
```

**Fixed in a fourth remediation pass (previously an approximation here — see
`docs/validation-report.md`, "Track 3 remediation pass, part 4")**: SPL has no built-in
set-intersection function over two multivalue fields (verified against Splunk's documented
Multivalue eval functions reference; `mvfind()`'s second argument is always a regex, and there
is no exact non-regex membership test). A prior revision of this query compared only each side's
FIRST scope tag via an unanchored regex — both a positional bug (a real overlap anywhere else
went undetected) and a substring-matching bug (an unanchored regex let a short tag wrongly match
inside an unrelated longer one, e.g. `"files:read"` inside `"files:read_all"`). The query above
now computes an exact, order-independent intersection via `mvmap()`/`mvfind()` with an anchored,
literally-quoted (`\Q...\E`) pattern, which cannot multiply rows even when several tags overlap
at once (it never calls `mvexpand`).

**One genuine, unresolved SPL/Splunk platform limitation remains, named rather than
approximated**: classic Splunk field extraction cannot represent a field that is present with an
explicitly empty value list as distinct from an absent field (unlike KQL's `dynamic` type, where
`isempty(dynamic([]))` is documented `false`). So `isnull(open_required_scope2)`/
`isnull(removed_scope2)` above cannot distinguish "no scope evidence was ever recorded" from "the
scope list was explicitly recorded as empty" — both report `insufficient_evidence`
(`missing_scope_evidence`) on this platform, where the JS oracle and KQL correctly report
`evaluated_no_violation` for the explicitly-empty case. This is asserted as one intentional,
named KQL/SPL disagreement in `tests/validation/language_equivalence.test.js` (fixture V14-07),
not silently folded into a "fully equivalent" claim.

**Note on the ASCII-quote `strptime()` format string above:** it assumes ISO-8601 with
millisecond precision (`2026-09-05T10:10:00.000Z`). This SPL query has not been successfully
executed against a live Splunk instance. An authorized attempt was made (Splunk Free, license
verified as genuinely Free — not a trial) but the instance became unresponsive after a required
configuration restart before any query could be tested; zero SPL detection queries were
executed. See `evidence/native-execution/splunk-prep/STATUS.md` for the full account. Validate
this format string against your own ingested field format before relying on it.

A separate, clearly-labeled `detected_at`-only informational note (never promoted into the query
above at all) is in the full file's closing comment block:
`detections/spl/mcp_subscription_authorization_drift.spl`.

## Query — Sigma: BEST-EFFORT CORRELATION / HUNTING CONTENT ONLY — NOT SEMANTICALLY EQUIVALENT TO KQL/SPL

**Do not treat the Sigma correlation below as full detection coverage for this track.** The
current official Sigma correlation specification can order and time-window matched events and
group them by equal field values, but has **no mechanism to compare one event's field value
(`effective_at`) against another event's own timestamp, and no mechanism to assert the absence
of a third event type** (a valid close). As a direct, mechanically-verified consequence
(`tests/validation/language_equivalence.test.js`) — **"equivalence" here and above, at FULL-corpus
scale, means two independently-coded JS models of each language's own written semantics agree
row-for-row on a shared test corpus, not that any of KQL, SPL, or Sigma was executed natively
against a real backend at that scale (that remains pending; a separate, smaller pass has since
natively executed KQL specifically for 25 representative fixtures — see `README.md`, "Native
execution status")**:

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

- **Permanent policy exemptions** (confirmed, scenario V5-09): a documented, deployment-specific
  decision to allow certain already-open streams to continue indefinitely after revocation is
  invisible to the schema and fires mechanically as `ConfirmedDrift`.
- Clock skew between the authorization server and the MCP server can produce a **false
  negative** (a real violation hidden because the reported `effective_at` looks later than it
  truly was) — see `docs/false-positive-analysis.md`.
- Inaccurate `effective_at` reported by the authorization server — the rule trusts the value it
  is given.
- **RECLASSIFIED (scope-aware correction): grace periods no longer fire mechanically as an
  accepted false positive.** A notification within a deployment-defined grace window after a
  scope downgrade (scenario V5-02, a legacy-shaped fixture with no `required_scope`/
  `removed_scope` evidence) now correctly reports `InsufficientEvidence`, not `ConfirmedDrift` —
  the honest answer when relevance cannot be determined, rather than a confirmed-but-forgiven
  violation. A deployment emitting both scope fields gets a definitive `EvaluatedNoViolation`
  when the downgrade genuinely doesn't affect a given subscription's required scope (see
  fixture V12-03); no grace-period field is still needed for that specific case, though one
  would still be needed for a *relevant* downgrade a deployment wants to tolerate temporarily.

## Limitations

- Depends on a push-based revocation feed for the `effective_at` path, which most real OAuth
  deployments do not have — the `valid_until`/silent-expiry leg exists specifically so detection
  does not depend on one existing at all.
- **[Code defect, FIXED — scope-aware correction] Revocation scope is now resolved to a specific
  authorization binding, not a principal.** The previous release's revocation-leg join was by
  `principal.id_hash` only, so a principal holding two or more concurrent subscriptions could
  have a still-valid subscription's notifications cross-correlated against a different one's
  revocation — empirically demonstrated by fixture V11-11 (retained, unmodified, as a legacy
  worked example). Verified against current MCP/OAuth documentation: a principal can hold
  multiple independent, independently-revocable bindings; "same principal" is not "same
  authorization scope." Fixed via `mcp.authz.binding_id` and
  `mcp.authz.change.affected_scope`/`affected_binding_ids` — no subscription-id field on
  `authorization_change` was needed. See fixture V12-13 and `docs/validation-report.md`, "Track
  3 remediation pass, part 2."
- **[Code defects, FIXED — example-driven regression pass] A "sole-candidate" scope inference
  and an "ever observed" timing approximation, both introduced by the second pass, are removed.**
  The second pass still resolved an `affected_scope = unknown` change to a confirmed finding
  whenever exactly one binding was observed for a principal (still an inference, not evidence —
  fixture V13-03), and approximated `affected_scope = all_principal_bindings` as "ever observed
  anywhere in the queried window" rather than a precise effective-time interval (fixture V13-06).
  Both fixed in KQL, SPL, and the JS oracle. **This reclassifies fixture V6-02** (malformed
  telemetry, no scope evidence on its revocation) from a claimed "partially detectable"
  finding to `InsufficientEvidence` — see `docs/validation-report.md`, "Track 3 remediation
  pass, part 3."
- **[Code defect, FIXED] Suppression is now checked before scope ambiguity/conflict.** A
  legitimately closed stream needs no scope resolution at all — caught while re-deriving fixture
  V11-07 under the stricter unknown-scope rule.
- **[Code defect, FIXED] A self-contradictory record (authoritative timing claimed, no
  `effective_at`) is explicitly detected** and reported as `InsufficientEvidence`
  (`incomplete_timing_evidence`) rather than silently disappearing behind a null-timestamp
  comparison (fixture V13-05). A real instance of this gap was found and fixed in the KQL query
  itself during this pass, not merely documented.
- **[Deployment prerequisite] The scope-aware correction only helps deployments that emit
  the new fields.** Legacy telemetry lacking `mcp.authz.binding_id`/`affected_scope` gets the
  safe default (`InsufficientEvidence` on genuine ambiguity) rather than a fully resolved
  answer — see the "Track 3 coverage report" in `docs/validation-report.md`.
- **[Scope boundary, partial] A `scope_downgraded` change's relevance to a given subscription
  requires BOTH `mcp.subscription.required_scope` and `mcp.authz.change.removed_scope`.** Either
  missing reports `InsufficientEvidence` (fixtures V5-02, V12-09), never a guessed default.
- **[Code defect, FIXED — fourth remediation pass] The SPL scope-downgrade relevance check
  previously compared only each side's first scope tag via an unanchored regex** — a positional
  bug (a real overlap anywhere else went undetected, fixture V14-01) compounded by a
  substring-matching bug (an unanchored regex let `"files:read"` wrongly match inside
  `"files:read_all"`, fixture V14-05). Fixed with an exact, order-independent,
  anchored-literal-quoted multivalue intersection (`mvmap()`/`mvfind()`, syntax verified against
  Splunk's documented Multivalue eval functions reference), matching the JS oracle and KQL's
  (`set_intersect`) precise any-element intersection. Checking this also found the
  independently-coded SPL model in `tests/validation/language_equivalence.test.js` had silently
  been implementing the correct intersection all along, hiding the real query's bug from every
  prior "KQL/SPL agree" claim — corrected on both sides. **[Named, unresolved SPL/Splunk platform
  limitation]** classic Splunk field extraction cannot represent an explicitly-empty scope list
  as distinct from an absent one (unlike KQL's `dynamic` type) — fixture V14-07 is asserted as
  one intentional, named KQL/SPL disagreement, not folded into a "fully equivalent" claim. See
  `docs/validation-report.md`, "Track 3 remediation pass, part 4."
- **[Code defects, FIXED — first remediation pass]** The close-suppression join and the SPL
  expiry-leg join previously keyed on `subscription_id` alone in one or both languages; SPL's
  `join type=inner` subsearches previously relied on Splunk's `max=1` default. Both fixed; see
  `docs/validation-report.md`, "Track 3 remediation pass" (part 1), fixtures V11-01/V11-02.
- `detected_at`-only timing is never promoted to a scored outcome of any kind — see the separate
  informational query and "Track 3 coverage report."

## Investigation fields

`instance_id`, `subscription_id`, `principal_hash`, `notification_type`, `BindingId`,
`AuthzChangeType`/`AuthzChangeSource`, the resolved `Boundary` type/time, `Reason` (populated for
`InsufficientEvidence` — one of `ambiguous_scope`, `missing_scope_evidence`,
`conflicting_evidence`, `incompatible_hash_epoch`, `no_invalidity_evidence`, `timing_unconfirmed`),
`trace_id` (if present).

## References

- MCP specification `2026-07-28`, subscriptions pattern: https://modelcontextprotocol.io/specification/2026-07-28/basic/patterns/subscriptions
- MCP specification `2026-07-28`, authorization: https://modelcontextprotocol.io/specification/2026-07-28/basic/authorization
- MCP specification `2026-07-28`, authorization security considerations: https://modelcontextprotocol.io/specification/2026-07-28/basic/authorization/security-considerations
- OAuth 2.0 Token Revocation, RFC 7009 (per-token vs. per-grant revocation scope): https://www.rfc-editor.org/rfc/rfc7009
- OAuth 2.0 Authorization Framework, RFC 6749 §6 (refresh tokens issue new values for the same grant): https://www.rfc-editor.org/rfc/rfc6749#section-6
- Sigma correlation rules specification (for the documented Sigma limitation): https://github.com/SigmaHQ/sigma-specification/blob/main/specification/sigma-correlation-rules-specification.md

## Severity recommendation

**High** for `ConfirmedDrift` (authoritative `effective_at` or a computable `valid_until`).
**Medium** for `InsufficientEvidence` — worth a human look (ambiguous scope, missing scope
evidence, a hash-epoch or conflicting-evidence anomaly), never an automatic page. **None** for
`EvaluatedNoViolation`. `detected_at`-only timing is never promoted to any scored outcome — that
remains a separate, low-confidence/informational query. The Sigma correlation, to the extent it
fires at all, should be treated as hunting content, not an equivalent alert.

## MITRE ATT&CK

`No precise ATT&CK technique assigned.` This models a systemic authorization-propagation-delay
exposure window (a control/timing gap), not a distinct adversary technique — an attacker does
not need to do anything beyond passively continuing to receive already-established stream data,
which does not map cleanly onto any ATT&CK technique.
