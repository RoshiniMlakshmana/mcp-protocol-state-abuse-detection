# Novelty Check

Performed 2026-09-13, before finalizing publication text. Searched: detections.ai, SigmaHQ,
Elastic `detection-rules`, GitHub generally, current MCP repositories/issues, and recent
security research, for direct public equivalents of this project's three detection tracks.

**Categories used (per the fixed instruction set):** `public equivalent found`,
`substantial overlap`, `no public equivalent found`, `uncertain`. No claim of "proven novel,"
"first," or "unique" is made anywhere in this document or elsewhere in this project.

---

## Detection 1 — MCP Task Routing Header/Body Desynchronization

**Result: no public equivalent found** (for detection *content*); **substantial overlap** for
the underlying *architectural risk discussion*.

- **Risk concept already publicly discussed:** a Tigera blog post ("The New MCP Headers Are a
  Gift to Gateways") discusses the header/body desynchronization risk at an architectural
  level, quoting the specification's own rationale ("Servers must reject requests where the
  headers and the body disagree") and framing defense-in-depth around it. Directly fetched and
  confirmed: **the article proposes no detection rule, SIEM query, log pattern, or monitoring
  signature** — it is a design-level discussion, not detection content.
- **SigmaHQ:** issue #5920 ("Add MCP security detection rules") proposes five MCP-related Sigma
  rules (unauthorized tool invocation, exposed server detection, tool-definition "rug pull,"
  excessive tool calls, unsigned messages). None address header/body routing consistency.
  Directly fetched and confirmed.
- **`MHaggis/Security-Detections-MCP`** (an MCP-server-based aggregator exposing ~8,200
  detections across 6 formats to LLM clients): confirmed, via direct query, to index
  general-purpose threat detections (ransomware, APT, endpoint/network) and contains **no rule
  addressing MCP protocol-layer header/body consistency.**
- **Elastic `detection-rules`:** no MCP-specific content found in the official repository at
  all (only unrelated third-party MCP *server* projects for interacting with Elasticsearch).

**Conclusion:** the risk class is discussed publicly at a design level (SEP-2243's own
rationale, echoed by at least one vendor blog); no public Sigma/KQL/SPL/equivalent detection
rule for it was found. This project's contribution is the detection content itself, not the
underlying architectural observation.

## Detection 2 — MCP Cross-Principal Task Authorization Violation

**Result: no public equivalent found** (for detection content); **public equivalent found**
for the underlying risk-class documentation (already credited, not claimed as discovered by
this project).

- **SEP-2663 itself** (the MCP Tasks extension specification) explicitly documents task IDs as
  bearer-token-like credentials and mandates a per-request authorization check because of this —
  this is a **public equivalent for the risk-class awareness**, cited throughout this project
  (`docs/threat-model.md` §10, every Detection 2 document) and never claimed as this project's
  discovery.
- A dev.to analysis ("Two normative sentences went missing when one tasks spec superseded
  another") separately discusses a specification-drafting gap around this same risk area —
  community discussion of the risk, still not detection content.
- **SigmaHQ, Elastic `detection-rules`, `MHaggis/Security-Detections-MCP`:** none contain a rule
  for cross-principal task/object-identifier authorization violations in MCP. Confirmed via
  direct queries against each.
- **`Agent-Threat-Rule/agent-threat-rules`** (683 executable AI-agent threat rules across 10
  categories, merged into several vendor frameworks): the closest-sounding rule,
  `ATR-2026-00074-cross-agent-privilege-escalation.yaml`, was fetched and read directly. It
  detects **prompt-based agent-to-agent social engineering** (regex matching phrases like "I am
  acting as the admin agent" or "forward my credentials to") in conversational content between
  autonomous agents (CrewAI/AutoGen/LangChain) — an entirely different detection surface
  (conversation content) from this project's Track 2 (server-side `mcp.authz.*` audit
  evidence for a specific protocol object, the task). No overlap in mechanism or telemetry.

**Conclusion:** the risk class is already documented by SEP-2663 and credited as such
throughout this project; no public detection rule (in any format, across the sources checked)
implements this specific server-side-evidence detection approach.

## Detection 3 — MCP Long-Lived Subscription Authorization Drift

**Result: no public equivalent found** (for detection content); **substantial overlap** for
the general monitoring *principle*.

- General authorization/revocation monitoring guidance exists broadly: a Red Hat MCP security
  blog notes servers "should detect token revocation using JWT introspection or by trying to
  use a token and handling a 401," and the Cloud Security Alliance's AI-agent framework
  specifies generic "permission drift tracking... ensure revocations propagate" as a monitoring
  *requirement* category. Both are generic principles applicable to any revocable-credential
  system, not MCP-`subscriptions/listen`-specific detection content, and neither proposes
  concrete query logic.
- No source found (SigmaHQ, Elastic, the two MCP-focused rule aggregators, or general search)
  proposing detection logic specifically for a `subscriptions/listen` stream continuing to
  deliver notifications after an authoritative revocation/expiry.
- One search result summary claimed the `2026-07-28` revision "removes long-lived streams"
  entirely. **This project does not rely on that claim and considers it unreliable**: it
  contradicts this project's own Block 1/3/5 primary-source verification (direct reading of the
  `2026-07-28` specification text, and direct inspection of the shipped
  `@modelcontextprotocol/server@2.0.0` source code, which both confirm `subscriptions/listen`
  is a genuine, functioning long-lived stream mechanism — see `docs/sdk-discrepancy.md`). The
  search summary most likely conflates SEP-2575's stream mechanics with SEP-2322's unrelated
  removal of server-initiated out-of-band requests (MRTR). Flagged here rather than silently
  ignored, per the standing instruction to record contradictions rather than guess.

**Conclusion:** the general principle ("check that revocation actually propagates") is
widely discussed in AI-agent/cloud-security guidance; no public detection content specific to
MCP subscription drift was found.

---

## Summary table

| Detection | Public equivalent found | Substantial overlap | No public equivalent found | Uncertain |
|---|---|---|---|---|
| 1 — Routing desync | — (for detection content) | Yes (architectural risk discussion) | Yes (detection content) | — |
| 2 — Cross-principal task auth | Yes (risk-class documentation, SEP-2663) | — | Yes (detection content) | — |
| 3 — Subscription drift | — (for detection content) | Yes (general revocation-monitoring principle) | Yes (detection content) | — |

## Permitted framing for publication text (derived from this check)

- "No public equivalent found during the documented research phase" — supportable for all
  three tracks' *detection content* specifically, and used with that qualifier throughout
  `README.md` and `publication/`.
- "Likely uncommon detection content" — supportable given the breadth of sources checked
  (SigmaHQ, Elastic, two major MCP-focused rule aggregators, general web search) turned up
  nothing matching.
- Never: "first," "novel," "unique," "proven novel," or any claim that the underlying risk
  classes (especially Track 2's) were discovered by this project.

## Search log (for reproducibility of this check)

- `MCP task routing header body desynchronization detection Sigma Mcp-Method Mcp-Name`
- `MCP cross-principal task authorization violation detection rule SEP-2663 taskId`
- `MCP subscription authorization drift detection long-lived subscriptions/listen revocation`
- `site:github.com SigmaHQ sigma "MCP" model context protocol detection rule`
- `detections.ai "Model Context Protocol" MCP detection rule library`
- `Elastic detection-rules github "Model Context Protocol" MCP`
- `Agent-Threat-Rule agent-threat-rules "privilege escalation" MCP task authorization OR "taskId" OR subscription rule yaml`
- Direct fetches: Tigera blog post; `SigmaHQ/sigma` issue #5920; `MHaggis/Security-Detections-MCP`
  README; `Agent-Threat-Rule/agent-threat-rules` README and its
  `ATR-2026-00074-cross-agent-privilege-escalation.yaml` rule file.
