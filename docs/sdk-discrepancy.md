# SDK/Spec Implementation Discrepancy (found during Block 3, corrected in patch)

**Status:** informational finding, does not change the locked Block 1/Block 2 model. Per the
Block 3 instructions: "If an implementation contradicts a locked assumption, STOP that
scenario, document the contradiction, and report it rather than silently changing the model."
This document is that report.

**Correction notice:** the original version of this document treated
`@modelcontextprotocol/sdk@1.30.0` as *the* official TypeScript SDK and concluded the official
SDK as a whole lacks `2026-07-28` support. That was incorrect — it checked only the legacy v1
line. This revision checks both lines directly against their shipped source and corrects the
finding: the **stable v2 line does implement `2026-07-28` core**, but the **SEP-2663 Tasks
extension is not part of what v2 implements yet**. Both claims below were verified by
installing the packages and reading the shipped `dist/` output, not by reading documentation
alone.

## The two current TypeScript SDK lines

### v1 (legacy line) — `@modelcontextprotocol/sdk`

```
$ npm view @modelcontextprotocol/sdk dist-tags   # checked 2026-09-12
{ latest: '1.30.0' }
```

Installed and inspected directly:

```js
// @modelcontextprotocol/sdk@1.30.0, dist/cjs/types.js
exports.LATEST_PROTOCOL_VERSION = '2025-11-25';
exports.SUPPORTED_PROTOCOL_VERSIONS = ['2025-11-25', '2025-06-18', '2025-03-26', '2024-11-05', '2024-10-07'];
```

- Monolithic package, maintained for compatibility/security fixes.
- Targets the 2025-era protocol family (max `2025-11-25`).
- Task methods present: `tasks/get`, `tasks/result`, `tasks/list`, `tasks/cancel` (the
  pre-SEP-2663 core-protocol shape).
- Subscriptions: `resources/subscribe`/`resources/unsubscribe` (pre-SEP-2575 shape).
- No `Mcp-Method`/`Mcp-Name`/`HeaderMismatch` anywhere in the package (SEP-2243 not present).

**This is accurate as a description of v1, and only v1.** It is not evidence about the SDK
family as a whole, which is the mistake the original version of this document made.

### v2 (stable line) — `@modelcontextprotocol/client` + `@modelcontextprotocol/server` (+ shared `@modelcontextprotocol/core`)

```
$ npm view @modelcontextprotocol/client dist-tags   # checked 2026-09-12
{ latest: '2.0.0' }
$ npm view @modelcontextprotocol/server dist-tags
{ latest: '2.0.0' }
```

Both packages' READMEs state directly: *"v2 is the stable release line, implementing the
[2026-07-28 MCP spec]."* This was independently confirmed by installing `2.0.0` of both and
reading the shipped `dist/` code (not trusting the README alone):

- **Stateless `2026-07-28` core, genuinely wired up:** `PROTOCOL_VERSION_META_KEY`,
  `CLIENT_INFO_META_KEY`, `CLIENT_CAPABILITIES_META_KEY`, `SERVER_INFO_META_KEY`,
  `TRACEPARENT_META_KEY`, `TRACESTATE_META_KEY`, `BAGGAGE_META_KEY` are all real exports,
  matching the `_meta`-based stateless model Block 1 verified from SEP-2575/SEP-414.
- **MRTR (SEP-2322):** `InputRequiredResult`, `InputRequest`/`InputRequests`,
  `InputResponse`/`InputResponses` are real exports.
- **`subscriptions/listen` (SEP-2575) is genuinely implemented**, not a stub:
  `SubscriptionsListenRequest`, `SubscriptionsListenResult`,
  `SubscriptionsAcknowledgedNotification`, `SubscriptionFilter`, `SUBSCRIPTION_ID_META_KEY` are
  real exports, and the server's route dispatcher contains a live branch:
  `route.message.method === "subscriptions/listen"` (`server/dist/index.mjs`).
- **`Mcp-Method`/`Mcp-Name` header validation and `-32020` `HeaderMismatch` are genuinely
  implemented at runtime**, not just typed. Directly from the shipped code
  (`server/dist/src-CX2iR2pK.mjs`):
  > `* the `Mcp-Method` header is validated against the body when [...] disagreeing with the
  > body method) is rejected with `-32020` (`HeaderMismatch`) on HTTP 400.`

  and a live rejection-building function, `paramHeaderMismatchRejection`, plus explicit
  `Mcp-Param-*` (custom header, SEP-2243) validation logic. `server/discover`,
  `UnsupportedProtocolVersionError`, and `MissingRequiredClientCapabilityError` are also real
  exports, matching Block 1's changelog citations exactly.

**Conclusion: the official TypeScript SDK, in its current stable (v2) release line, does
implement MCP `2026-07-28` core behavior.** The blanket claim in the original version of this
document — that the official SDK lacks `2026-07-28` support — is withdrawn.

## The actual, narrower discrepancy: SEP-2663 Tasks extension support in v2

This is the part of the original finding that **does hold up** under direct verification, with
more precision than before.

`@modelcontextprotocol/server@2.0.0`'s full export list (`dist/index.d.mts`) includes task
types, but they are the **2025-11-25 core-protocol shape**, not SEP-2663's extension shape:

| Exported (v2, 2.0.0) | Corresponds to | SEP-2663 (current, per Block 1) |
|---|---|---|
| `GetTaskRequest` / `GetTaskResult` | `tasks/get` | Same method name, compatible shape |
| `GetTaskPayloadRequest` / `GetTaskPayloadResult` | `tasks/result` | **Removed** — SEP-2663 replaced this with `tasks/update` |
| `ListTasksRequest` / `ListTasksResult` | `tasks/list` | **Removed** — SEP-2663 deliberately dropped this to prevent cross-caller task enumeration (Block 1 SS6) |
| `CancelTaskRequest` / `CancelTaskResult` | `tasks/cancel` | Same method name, compatible shape |
| *(absent)* | — | **`tasks/update`/`UpdateTaskResult` does not exist anywhere in the v2 package** |
| *(absent)* | — | **No `io.modelcontextprotocol/tasks` extension-capability identifier anywhere in the v2 package** |

The clearest single piece of evidence is in the shipped source itself
(`server/dist/src-CX2iR2pK.mjs`), on the task-status notification type:

```js
/**
* A notification sent when a task's status changes.
*
* @deprecated 2025-11-25 wire vocabulary with no SDK runtime; kept importable for
* interoperability only.
*/
const TaskStatusNotificationSchema$1 = NotificationSchema$1.extend({
  method: z.literal("notifications/tasks/status"),
  ...
});
```

This is the SDK's **own** documentation of its own limitation: the type is `@deprecated`, uses
the old `notifications/tasks/status` method name (SEP-2663's current name is `notifications/tasks`,
no `/status`), and is explicitly marked **"no SDK runtime"** — i.e., kept only so old code that
imports the type doesn't break, not wired to anything that actually sends or receives it. There
is no `taskIds` filter field on `SubscriptionFilter` either. **Consequently: `subscriptions/listen`
itself is real and functional in v2 for resource/list-changed notifications, but there is no
working path for Tasks-extension task-status notifications over it.**

One more piece of corroborating, SDK-authored evidence: v2's own error-code documentation for
`MethodNotSupportedByProtocolVersion` uses this exact example — *"the spec method being sent
does not exist on the negotiated protocol version's wire era (e.g. `tasks/get` toward a
`2026-07-28` peer...)"*. The SDK authors are explicitly aware that core-protocol `tasks/get` is
not valid MCP `2026-07-28` core (because SEP-2663 moved tasks out of core) — they simply have
not yet shipped the SEP-2663 extension replacement for it.

## Revised justification for the project reference harness

> The official TypeScript SDK v2 implements MCP 2026-07-28 core behavior, but the SEP-2663
> Tasks extension still has implementation gaps. The project reference harness implements only
> the documented Tasks-extension mechanics needed for deterministic detection testing and is
> not presented as a replacement MCP SDK.

## Why Block 3's normal corpus still uses the reference harness for every scenario, including the one non-Task scenario (N8)

11 of 13 normal-corpus scenarios (all except N8 and N13) involve `tasks/get`, `tasks/update`,
or `tasks/cancel` directly — for these, v2's Tasks-extension gap above is dispositive: the
reference harness is required regardless.

N8 (`subscriptions.jsonl`) is a plain resource-subscription scenario with no task involved, and
v2's `subscriptions/listen` implementation is real. Swapping *only* N8 to genuine v2-SDK-captured
traffic was considered and **deliberately not done in this pass**: doing so honestly would
require standing up real client/server processes over an HTTP transport, capturing live wire
traffic, and building a translation layer from the SDK's actual JSON-RPC/HTTP output into the
Block 2 audit schema — a materially larger engineering surface than one scenario justifies, and
one that trades away this corpus's current, verified byte-for-byte determinism (fixed logical
clock, fixed identifiers) for real network/async timing that would need its own reproducibility
strategy. Per this block's explicit instruction ("If doing so would require a large redesign, do
not force it"), N8 remains `project_reference_harness`-generated, documented here rather than
silently left ambiguous. This is a reasonable candidate to revisit in a later block if the corpus
generation pipeline itself is ever redesigned.

## Corpus provenance labels (this patch)

Every scenario in `data/normal/manifest.jsonl` now carries a `provenance` field using exactly
the three values requested for this project:
- `official_sdk_v2` — not currently used by any scenario (see above); reserved for future use
  if N8 (or a future non-Task scenario) is regenerated from real v2-SDK traffic.
- `project_reference_harness` — used by all 13 scenarios (N1–N10, N12, N13, and the non-token
  parts of N11).
- `synthetic_enrichment` — used by N11 specifically for its two fabricated `gen_ai.usage.*`
  token-count values.

## Recommendation for later blocks

Before Block 4, re-check whether `@modelcontextprotocol/client`/`server` has shipped a release
implementing SEP-2663 in its current shape (`tasks/update`, no `tasks/list`,
`io.modelcontextprotocol/tasks` capability, `notifications/tasks` with a live runtime). If so,
prefer it for Task-related scenarios instead of this harness, and note the switch explicitly
rather than silently mixing SDK-captured and harness-generated shapes in one corpus.
