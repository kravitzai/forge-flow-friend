# Phase 6C — Cisco MDS → Brocade Migration Readiness Engine

## What changed
- New edge function `supabase/functions/toolchain-engine-cisco-to-brocade-migration-readiness/index.ts`
  implementing the full context-first lifecycle:
  `collect → normalize → validate → package → reason → critic → render`.
- `supabase/config.toml` registers the function with `verify_jwt = false`
  (auth is enforced in code via `requireAuthenticatedUser`).
- `src/pages/ToolchainExecutionsPage.tsx` exposes a demo button
  **"Run Cisco → Brocade Migration Readiness Demo"**, gated by
  `FEATURES.toolchainEngineDemoRunner && isPrivileged`.
- `src/data/contextFirstTransition.ts` adds the engine row and
  Milestone **7.4 Cisco → Brocade Migration Readiness Engine (6C)**.

## Why Phase 6C is readiness only
Phase 6C produces a **migration readiness assessment** only. It analyzes a
Cisco MDS source side and a Brocade target side and reports gaps,
inconsistencies, and missing validation steps. It does **not** generate
executable commands, zoning command plans, or cutover scripts.

## Phase 6C vs Phase 6D
- **6C (this phase):** readiness analysis. Output is structured findings,
  risk flags, and missing-input descriptors. No commands.
- **6D (planned, separate phase):** Migration Pseudo-Command Generator.
  Will emit illustrative pseudo-commands for review only — still never
  executed by the platform.

## Input contract
Accepts a JSON body with optional, free-text fields:

- `migrationGoal`
- `ciscoShowVersionText`, `ciscoShowVsanText`, `ciscoShowZonesetActiveText`,
  `ciscoShowDeviceAliasDatabaseText`, `ciscoShowFlogiDatabaseText`,
  `ciscoShowFcnsDatabaseText`
- `brocadeSwitchshowText`, `brocadeFabricshowText`, `brocadeCfgshowText`,
  `brocadeZoneshowText`
- `vsanToFabricMappingNotes`, `zoningConversionNotes`, `rollbackNotes`,
  `operatorNotes`
- Pilot hints: `_routerReasoning`, `_criticPass`

## Output contract
- HTTP 200 with rendered findings on success.
- HTTP 400 with one of: `missing-cisco-source-input`,
  `missing-brocade-target-input`, `non-cisco-source-input`,
  `non-brocade-target-input`, `input-too-large`.
- HTTP 401 when unauthenticated.

## Lifecycle
1. **collect** — pulls raw text fields, never persists raw bodies.
2. **normalize** — extracts vendor terminology counts and structural flags.
3. **validate** — checks presence, vendor relevance, and `rawTotalChars`
   against the 200,000-character cap.
4. **package** — builds an `OperationalContextPack` with descriptor-only
   source artifacts and counts/flags-only observed facts.
5. **reason** — runs router-backed or direct reasoning, governed.
6. **critic** — optional self-critique (governed by `criticPassEnabled`).
7. **render** — emits structured findings; blocked by critic if configured.

## Normalization / parser approach
Parsers are intentionally lightweight and term-counting only. They do **not**
extract or persist WWNs, alias names, zone names, zoneset/cfg names, VSAN
names, switch names, hostnames, IPs, or serials.

## Validation rules
- Cisco source must contain at least one Cisco-MDS-specific keyword.
- Brocade target must contain at least one Brocade-specific keyword.
- `rawTotalChars` (sum of all incoming text lengths) capped at 200,000.

## rawTotalChars vs reasoner content
The 200,000-char cap is enforced against `rawTotalChars` (sum of all input
text fields), independently of the per-step reasoner content cap, which is
applied after summarization.

## Governance
- Caller-supplied `governance` is stripped. Only the internal `__governance`
  cache (populated by `resolveToolchainGovernance`) is honored.
- `INTERNAL_KEYS = { "governance", "_governance", "__governance" }` are
  filtered out of every persisted summary.
- `lanOnlyEnforced` blocks commercial gateway reasoning.
- `commercialGatewayAllowed = false` blocks the gateway path.

## Router behavior
When `routerReasoningEnabled` is true, the reasoner routes through the
AI Fabric router with `routerFallbackEnabled` controlling fallback.

## Critic behavior
When `criticPassEnabled` is true, the critic runs after `reason`. If
`criticBlocksRender` is true and the critic flags a block, the engine
returns a 422 with critic summary instead of rendered output.

## Sensitive identifier handling
Never persisted: WWNs, aliases, zone names, zoneset/cfg names, VSAN names,
switch names, hostnames, IPs, serials, tokens, credentials, prompt bodies,
or reasoner `userContent`.

## Descriptor-only source artifacts
Each source artifact persists only:
`{ kind, present: boolean, lengthChars: number }`. No content snippets.

## Summary-only trace
Trace entries persist step name, status, durations, counts, and codes —
never raw input or model output bodies.

## Demo-only UI state
The demo button is gated by `FEATURES.toolchainEngineDemoRunner` and admin
or beta role. Synthetic payload is built in-memory; nothing is written to
URL, localStorage, or route state.

## SQL validation queries
```sql
select id, started_at, execution_kind, status, integration_id, domain, intent,
       input_summary, output_summary, error_summary,
       context_pack->'observedFacts'  as observed_facts,
       context_pack->'sourceArtifacts' as source_artifacts,
       context_pack->'toolchainTrace' as trace
from public.toolchain_executions
where integration_id = 'toolchain-engine-cisco-to-brocade-migration-readiness'
order by started_at desc
limit 10;
```

## Known limitations
- Demo only; no production toolchain UI consumer wired yet.
- Shared `ToolchainStepDefinition<T>` variance warning surfaces under
  `deno check` identically to Brocade/Cisco MDS engines (non-blocking).
- Live validation requires an authenticated admin/beta user; preview
  iframes without a real Supabase JWT cannot drive the demo.

## Phase 6D handoff
Phase 6D will add a Migration Pseudo-Command Generator that consumes the
Phase 6C readiness output. It must remain pseudo-only — no executed
commands, no cutover scripts.

## Phase 6C.1 Hardening
- **Governance cache (verified):** `body.governance` is only deleted; `body.__governance` is the sole cache read/write path. Earlier prose lost double-underscores in rendering — raw grep confirms the pattern.
- **Internal key filter (verified):** `INTERNAL_KEYS = new Set(["governance", "_governance", "__governance"])` — all three filtered from `input_summary.topLevelKeys`.
- **Junk validation (fixed):** Validator now requires `ciscoTerms > 0` and `brocadeTerms > 0`; semantically empty content (e.g. "hello world", "AAAA") fails before the reasoner with `non-cisco-source-input` / `non-brocade-target-input`.
- **Oversize validation:** Temporary admin/beta dev button "Run Cisco → Brocade Oversize Validation (dev)" added to `/toolchains/executions`, gated by `FEATURES.toolchainEngineDemoRunner && isPrivileged`. Synthetic payload only; nothing persisted to URL/route/localStorage.
- **Spoof-resistance:** Caller-supplied `governance.spoofedByCaller` is stripped at `getGovernance`; persisted `output_summary.governance.source = "server_policy"`.
- **Audit/redaction:** Source artifacts descriptor-only, observed facts counts/flags only, trace summary-only, no raw vendor text or sensitive identifiers persisted.
