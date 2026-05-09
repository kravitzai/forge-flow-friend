# Phase 6D — Cisco MDS → Brocade Migration Pseudo-Command Generator

## Status

- Engine: `toolchain-engine-cisco-to-brocade-migration-pseudo-commands`
- Output contract: `migration_pseudo_commands@v1`
- Lifecycle status: `beta-ui` / `defaultPath: legacy`
- Sibling of Phase 6C (`toolchain-engine-cisco-to-brocade-migration-readiness`) — does not modify or replace it.

## What this engine does

Consumes a Phase 6C readiness artifact (or sanitized raw Cisco MDS + Brocade FOS sections as a fallback) and produces a structured set of **pseudo-command descriptors** for operator review.

A pseudo-command descriptor is **not** a command. It is a structured record:

- `target` — `brocade` or `cisco-mds`
- `intent` — what the descriptor expresses (e.g. "create alias mapping", "activate target zoneset")
- `lineDescriptor` — a placeholder-bearing illustrative line (e.g. `create alias <ALIAS_DESCRIPTOR_1> for <WWN_DESCRIPTOR_1>`). MUST contain at least one `<PLACEHOLDER_TOKEN>`. Vendor-ready command syntax (`alicreate`, `cfgsave`, `zoneset activate`, `cfgenable`, `configure terminal`, etc.) is rejected by the local critic.
- `placeholders` — list of placeholder tokens referenced
- `sourceFinding` — id of the readiness finding/gap/risk this descriptor addresses (or `unresolved` with a reason)
- `rationale` — why this descriptor exists, anchored to readiness signals
- `validationRequirement` — what an operator MUST verify against an approved migration worksheet before any action

Descriptors are grouped by phase: `pre-cutover`, `cutover`, `post-cutover`, `rollback`.

## What this engine does NOT do

- Does **not** execute commands. The platform has no execution path for this output.
- Does **not** emit vendor-ready command syntax.
- Does **not** persist raw command output beyond descriptor-only `sourceArtifacts`.
- Does **not** include any real WWN, IPv4 address, FCID, alias, zone, cfg/zoneset, VSAN name, switch name, hostname, email, or token.

## Lifecycle

```
collect → normalize → validate → package → reason → critic → render
```

- **collect** — accept either `readinessArtifact` (preferred) or raw text fallback fields. Strip caller-supplied `governance`.
- **normalize** — derive a descriptor view of the readiness artifact (counts, posture, cutover-risk flag) and append capped raw sections. Reasoner content includes only counts and finding ids, not raw artifact JSON.
- **validate** — input present, raw cap (200,000 chars), readiness artifact cap (100,000 chars), readiness contract match (`report_cisco_to_brocade_readiness@v1`).
- **package** — build `OperationalContextPack` with descriptor-only `sourceArtifacts` and observed counts. No raw text in the pack.
- **reason** — router-backed (governed by `routerReasoningEnabled`, fallback by `routerFallbackEnabled`). Tool: `migration_pseudo_commands`.
- **critic** — runs an LLM critic AND a **local hard-rule critic** that runs even when the LLM critic is disabled:
  - identifier leakage scan (WWN / IPv4 / FCID / hostname / email / long token)
  - placeholder presence check (every `lineDescriptor` must match `<PLACEHOLDER_TOKEN>`)
  - vendor-ready syntax detection (regex-based reject list)
  - rollback presence when readiness reports cutover risk
  - any descriptor that fails redaction is rewritten to `<REDACTED_PSEUDO_COMMAND>` and counted
  When `criticBlocksRender` is true, any local blocker returns 422.
- **render** — final defensive scan; any descriptor still leaking identifiers is redacted before persistence.

## Governance and redaction

- Caller-supplied `governance` stripped at every step; only `__governance` cache honored.
- `INTERNAL_KEYS` (`governance`, `_governance`, `__governance`) filtered from persisted summaries.
- `lanOnlyEnforced` blocks the commercial gateway path.
- `commercialGatewayAllowed = false` blocks the gateway path.
- `output_summary.governance.source = "server_policy"`.

## HTTP responses

- 200 with `{ contract: "migration_pseudo_commands@v1", groups, unresolved, disclaimer, ... }` on success
- 400 on `missing-readiness-input`, `invalid-readiness-contract`, `input-too-large`, `non-cisco-source-input`, `non-brocade-target-input`
- 422 on `critic-blocked-render`
- 500 on unexpected engine failure

## Phase 6D.0 Hardening

- **Governance cache (verified):** `body.governance` is stripped; `body.__governance` is the sole cache key. `INTERNAL_KEYS = { "governance", "_governance", "__governance" }`.
- **Placeholder regex (verified):** `/<[A-Z][A-Z0-9_]*>/` accepts long descriptor tokens like `<ALIAS_DESCRIPTOR_1>`, `<WWN_DESCRIPTOR_1>`, `<ZONE_DESCRIPTOR_1>`.
- **Raw-fallback vendor evidence (added):** when no `readinessArtifact` is supplied, the validator requires Cisco-specific terms in `cisco*` raw fields and Brocade-specific terms in `brocade*` raw fields. Junk text fails before the reasoner with `non-cisco-source-input` / `non-brocade-target-input` (HTTP 400).

## Promotion path

This phase ships as `defaultPath: legacy` / `status: beta-ui`. Promotion to `defaultPath: engine` happens in **Phase 6D.1** after:

1. Real readiness artifacts from operator pilots have flowed through the engine
2. At least one critic-block scenario (identifier leak, vendor-ready syntax, missing rollback) has been validated end-to-end
3. This doc is updated with a hardening notes section (mirroring 6C.1)

## Related

- Phase 6A — Brocade Fabric Analyzer
- Phase 6B — Cisco MDS Fabric Analyzer
- Phase 6C — Cisco → Brocade Migration Readiness (sibling, prerequisite source of `readinessArtifact`)
- Phase 6E-A — Engine Registry + EngineActionPanel wiring
