# Phase 5A — SRDF Engine Pilot

Phase 5A migrates the Dell PowerMax SRDF analyzer from the legacy single-shot
prompt path to the context-first `ToolchainExecutionEngine` already proven by
the Terraform and Proxmox pilots. The legacy
`toolchain-integration-srdf-analyzer` function remains deployed and untouched
to serve as a fallback / comparison path for any existing UI consumers
(PowerMax tier-0 toolchain still binds to it).

## Files

New
- `supabase/functions/toolchain-engine-srdf-analyzer/index.ts` — engine pilot
  implementing collect → normalize → validate → package → reason → critic →
  render → audit. Mirrors the Terraform engine module shape.

Edited
- `supabase/config.toml` — added `[functions.toolchain-engine-srdf-analyzer]`
  with `verify_jwt = false` (auth still validated in code via
  `requireAuthenticatedUser`).
- `src/pages/ToolchainExecutionsPage.tsx` — `runDemo` now accepts `"srdf"`
  and a third "Run SRDF Engine Demo" button is shown to admin/beta users.
- `docs/context-first-roadmap.md` — Milestone 7.0 / Phase 5A entry.
- `docs/context-first-documentation-index.md` — link to this notes doc.

Untouched (intentionally)
- `supabase/functions/toolchain-integration-srdf-analyzer/index.ts`
- `src/data/toolchainPowermaxTier0.ts` and `src/types/integration.ts` —
  no consumer rewiring in 5A.

## Engine contract

Input (aligned with legacy SRDF analyzer):
- `topologyDescription`
- `srdfGroupsText`
- `deviceGroupingText`
- `modeAndPolicyText`
- `failoverProcedureNotes`
- `contextNotes`

Validation:
- At least one of the six sections must contain content (legacy required
  `topologyDescription`; the engine relaxes that to "any section").
- Combined content must contain at least one SRDF/PowerMax-relevant term
  (`srdf`, `rdf`, `r1`, `r2`, `powermax`, `symmetrix`, `metro`, `failover`,
  etc.). Non-SRDF inputs are rejected.
- Combined content must not exceed 100 000 characters.

Output (strict superset of the legacy shape — backwards compatible):
```ts
{
  ok: boolean;
  summary: string;
  issues?: Array<{ severity: "info"|"warning"|"error"; message: string; field?: string }>;
  suggestions?: string[];
  // additive context-first fields, emitted only if the reasoner returns them:
  findings?: Array<{ severity: "info"|"warning"|"error"|"critical"; title: string; detail: string; evidence?: string; recommendation?: string }>;
  risks?: Array<{ severity: "low"|"medium"|"high"; description: string; mitigation?: string }>;
  validationSteps?: string[];
  stopConditions?: string[];
  assumptions?: string[];
  missingInputs?: string[];
}
```

## Lifecycle steps

| Step | Persisted in audit row | Notes |
| --- | --- | --- |
| `collect` | `inputSummary`, `outputSummary.artifactCount` | Body & artifacts pass through in-memory only. |
| `normalize` | counts + `redactionFlags` only | Builds `userContent` for the reasoner; raw text never persisted. |
| `validate` | `validationResults` | Section presence, SRDF-term presence, size cap. |
| `package` | observed counts and redaction flags | `buildEngineContextPack` — no raw content. |
| `reason` | mode, policy id/name, model name/runtime, counts | Router path when governance enables it; direct gateway otherwise. |
| `critic` | critic summary + governance summary | Skipped when governance disables critic. Only blocks render when `criticBlocksRender` is on. |
| `render` | counts (issue/finding/risk) | Returns the reasoner output as the public response. |

The engine never writes step `output` to the database (per
`toolchainEngine.ts` contract); only `inputSummary`, `outputSummary`,
`validationResults`, and trace entries are persisted.

## Redaction & safety

- Raw section text is never persisted to the audit row, the context pack,
  step output summaries, traces, or error summaries.
- Raw section text may be sent to the reasoner only when governance allows
  the selected model path. The direct commercial gateway path is blocked
  before any send when `governance.lanOnlyEnforced === true`
  (`lan-only-no-local-route`) or `governance.commercialGatewayAllowed === false`
  (`commercial-gateway-disabled`). In both cases the reason step records a
  `blocked_by_governance` outcome with no raw input in the audit row.
- The router-fallback path (`runRouterReasoning`) receives `lanOnlyMode` and
  `allowFallback` from governance. LAN-only enforcement prevents commercial
  fallback inside the router. Note: the current router shared module does
  not consume `commercialGatewayAllowed` directly, so the engine relies on
  LAN-only and explicit policy-driven model selection to bound commercial
  use through the router path. The pre-call guard above is the authoritative
  block for the direct-gateway path.
- Deterministic detection (in `normalize`) records counts only:
  `possibleIpAddress`, `possibleWwn`, `possibleSerial`, `possibleHostname`,
  `possibleEmail`. Matched values are not stored.
- The reasoner system prompt explicitly tells the model not to echo
  identifiers (WWNs, array serials, IPs, hostnames). Operators should still
  redact sensitive identifiers (WWNs, serials, IPs, hostnames, tokens,
  credentials) from inputs before submitting; reasoners and gateways may
  still see whatever raw text is sent on allowed paths.
- Caller-supplied `governance` fields on the request body are stripped on
  first access. Governance is always re-resolved server-side via
  `resolveToolchainGovernance` and cached only under the internal
  `__governance` key. Spoofing attempts have no effect.
- Schema name remains `report_analysis` for compatibility with the existing
  output-contract path. A dedicated `srdf_operational_analysis` schema is
  deferred until UI consumers are ready.

## Demo payload (admin/beta only)

```ts
{
  topologyDescription:
    "Two-site SRDF/A design. Primary site hosts R1 devices; DR site hosts R2 devices. Single RDF group per workload tier.",
  srdfGroupsText: "Group 10 — DB tier (R1→R2). Group 20 — App tier (R1→R2).",
  deviceGroupingText: "Storage groups DB_SG and APP_SG, each mapped 1:1 to its RDF group.",
  modeAndPolicyText: "SRDF/A async; 30s cycle target; RPO target ~1 minute.",
  failoverProcedureNotes: "Planned failover: suspend, swap, resume on DR.",
  contextNotes: "Demo payload — no production identifiers.",
  _routerReasoning: true,
  _criticPass: true,
}
```

No WWNs, array serial numbers, IPs, hostnames, tokens, or credentials.

## Manual validation matrix

1. Admin clicks "Run SRDF Engine Demo" → 200; new row appears in
   `/toolchains/executions` with `execution_kind=engine`, status `succeeded`.
2. Lifecycle steps render: collect → normalize → validate → package → reason
   → critic → render.
3. Governance summary present (router mode, model policy id, lan-only,
   critic).
4. Empty payload → 400 (`missing-srdf-input`); failed engine row recorded.
5. Non-SRDF text → 400 (`non-srdf-input`); failed engine row recorded.
6. Oversize input → 400 (`input-too-large`); failed engine row recorded.
7. Critic-blocked path (when governance permits) → 422.
8. Beta user can view results via `toolchainExecutionVisibility`/override.
9. Ordinary user sees no demo button.
10. No raw section text or secrets visible in the UI or audit row.
11. Legacy `toolchain-integration-srdf-analyzer` still responds.
12. `bunx tsc --noEmit` clean.

### Phase 5A.1 additional manual checks

13. Request body containing fake `governance: { lanOnlyEnforced: false, ... }`
    cannot spoof policy — the field is stripped, governance is always
    re-resolved server-side.
14. With LAN-only governance enabled and no router policy, the reason step
    records `lan-only-no-local-route`, `modeUsed=blocked_by_governance`,
    and the audit row contains a governance summary but no raw section text.
15. With `commercialGatewayAllowed=false` and router disabled, the reason
    step records `commercial-gateway-disabled` and no commercial gateway
    call is made.
16. Validation-failed engine rows (empty / non-SRDF / oversize) include
    `output_summary.governance` on the validate step.

## Known limitations

1. UI consumers (PowerMax tier-0 toolchain) still call the legacy function;
   switching defaults is deferred to a later phase.
2. The engine emits both legacy `issues`/`suggestions` and new
   `findings`/`risks`/`validationSteps`/`stopConditions`/`assumptions`/
   `missingInputs`, but the existing renderer is generic — the new fields
   appear in execution-detail audit JSON until a dedicated SRDF renderer is
   added.
3. No `ai_fabric_routes` / `ai_fabric_route_steps` rows are seeded for
   `srdf_analyzer` / `srdf_critic`. Without those, the engine falls back to
   the direct-gateway path (same default behavior as the Terraform pilot).
   Admins can wire role-key bindings via `/toolchains/policies` when ready.
4. Redaction detection is heuristic. If sensitive identifiers slip through,
   they are still excluded from the audit row because raw text is never
   persisted, but the reasoner sees them — operators should redact before
   pasting.
5. The shared `runRouterReasoning` does not consume `commercialGatewayAllowed`
   directly; LAN-only enforcement and explicit policy-driven model selection
   are the controls available on the router path. Phase 5B may push
   `commercialGatewayAllowed` into the router contract.
