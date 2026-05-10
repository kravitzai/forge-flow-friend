# Phase 6J-B — Cisco → Brocade Zoning Conversion Advisor Engine

Wraps the pure 6I-D → 6I-E → 6I-F pipeline as a registered Context-First **engine**. Consumes canonical Cisco zoning + canonical Brocade target + `MappingRules` and emits `ConversionPlan + ValidationReport + PseudoCommandReport` summaries. The pipeline runs entirely in the browser; the audit edge function writes a **descriptor-only** row.

## Hard boundary

```text
Engine                    : yes (registered in toolchainEngineRegistry)
Catalog visibility        : yes (Migration Advisor archetype)
Generic EngineActionPanel : NO — dedicated panel via hiddenFromActionPanel=true
Pipeline location         : client-side (src/lib/canonicalZoning/**)
Audit storage             : toolchain_executions, descriptor-only payload
Raw collection            : not in scope
Vendor normalizers        : not invoked from this engine
Edge function logic       : audit-only — accepts a sanitized descriptor envelope
Forbidden in audit row    : canonical models, MappingRules JSON, template lines,
                            WWPNs, aliases, zones, zonesets, switch/host names,
                            raw evidence
```

## Architecture

```text
browser
  ToolchainEngineDetailPage (advisor branch)
    └─ <CiscoToBrocadeAdvisorPanel/>
         ├─ <AdvisorInputs/>          (3 paste fields + Load demo + Clear)
         ├─ runCiscoToBrocadeZoningAdvisor(input)   (pure pipeline)
         ├─ <AdvisorSummary/>         (readiness + counts + top reasons)
         ├─ <AdvisorHandoff/>         (sessionStorage + navigate to 6J-A)
         └─ POST /functions/v1/toolchain-engine-cisco-to-brocade-zoning-conversion-advisor
              (descriptor-only AdvisorAuditEnvelope)

edge function (audit-only)
  toolchain-engine-cisco-to-brocade-zoning-conversion-advisor
    - 64 KB body cap
    - explicit shape validation
    - shared FORBIDDEN_KEYS deep-walk → 422 on hit
    - inserts one toolchain_executions row (engine kind)
    - never echoes payload
```

## Output contract

`cisco_to_brocade_zoning_advisor@v1` (see `src/data/contextFirstOutputContracts.ts`):

- `pipelineVersion` (always `6I-D/6I-E/6I-F`)
- `engineId` (always `cisco-to-brocade-zoning-conversion-advisor`)
- `validationReadiness`, `reportReadiness`, `generated`, optional `reason`
- `summary` — counts (blockers, reviewItems, findings, diffs, descriptors, reviewOnly), `perKind`, `inputSummary`
- `descriptors` — identity-only metadata (id, kind, intent, actionId, requiresHumanReview, optional logicalFabricId)
- `findingCodes` — codes only, no messages
- `reportHash` — deterministic SHA-256 of canonicalized PseudoCommandReport JSON

## Safety

- Browser walker (`src/lib/canonicalZoning/advisor/forbiddenKeys.ts`) and edge walker (`supabase/functions/_shared/advisorForbiddenKeys.ts`) share the same exact-key list.
- Allowed safe summary keys (`sourceAliases`, `sourceZones`, `mappingRulesCount`, `logicalFabricId`) pass because matching is exact equality, not substring.
- Audit failure never blocks the inline result. Operators see an `Audit failed` chip with `Retry audit`.
- The advisor surface safety test (`src/components/toolchains/advisor/__tests__/advisorSurfaceSafety.test.ts`) blocks forbidden labels (`Run`, `Apply`, `Execute`, `Push`, `Activate`, `Copy as CLI`, `Send to switch`) and forbidden imports (`@/lib/runtime`, `@/lib/adapters/*`, vendor normalizers).
- Permission key: `toolchain.advisor.cisco_to_brocade_zoning.run` (granted alongside `toolchain.engines.view`).

## 6J-A handoff

`<AdvisorHandoff/>` writes `{ report, validation, plan }` to `sessionStorage` under `forgeai:pseudo-command-review:last-report` and navigates to `/toolchains/san-migration/review`. The 6J-A `InputPanel` consumes that key on mount, removes it immediately, and seeds `ReviewState`. No other 6J-A change.

## Limitations

- No raw evidence collection (separate phase).
- No vendor normalizer invocation (canonical models are operator-supplied).
- No critic stage — the advisor wraps deterministic 6I-D/E/F logic only.
- Audit row is best-effort; operator sees a chip on failure but can still review and export inline.

## Phase status

Complete pending acceptance.

## 6J-B.1 — Toolchain ↔ Advisor cross-links

Presentation-only patch closing the discoverability gap between the legacy
6D pseudo-command generator and this advisor.

- `EngineResultPanel` now renders a **Next steps** block after a
  successful run, driven by `descriptor.nextSteps` on
  `ToolchainEngineDescriptor` (registry metadata only — never
  executable). The 6D `cisco-to-brocade-migration-pseudo-commands`
  descriptor and the 6G-C `cisco-mds-zoning-analyzer` descriptor surface
  links to **Open Pseudo-Command Review** and **Open Conversion
  Advisor**.
- The SAN migration toolchain page (`cisco-mds-to-brocade-san-migration-validation`)
  renders a `DedicatedEngineTeasers` card linking to the advisor's
  standalone detail route. This covers engines that are intentionally
  `hiddenFromActionPanel: true` but expose a `dedicatedPanel`.
- No runtime, audit, edge, pipeline, or business-logic change. Forbidden
  labels (`Run`, `Apply`, `Execute`, `Push`, `Activate`) remain absent
  from advisor surfaces; the new links are pure navigation.
