# Phase 6G-B — Brocade Zoning Analyzer

**Status:** Built (beta-ui) — read-only advisory engine
**Edge function:** `supabase/functions/toolchain-engine-brocade-zoning-analyzer/index.ts`
**Output contract:** `brocade_zoning_analysis@v1`
**Archetype:** `zoning-analysis` (Brocade)

## 1. Purpose

The Brocade Zoning Analyzer is the first dedicated engine for the
`zoning-analysis` archetype. It performs a **read-only** zoning hygiene,
consistency, and reconciliation review of a Brocade FC fabric using
sanitized command output (`cfgshow`, `zoneshow`, `nsshow`,
`switchshow`, `fabricshow`, `portshow`, `islshow`, `trunkshow`,
`firmwareshow`).

It is **advisory only**. It never produces executable commands, command
descriptors, change plans, or copy-pasteable syntax.

## 2. Why zoning-analysis is separate from fabric-health

The Brocade **Fabric Analyzer** (Phase 6A) reviews fabric-wide
operational posture (switch identity, ISL/trunk health, FOS/MAPS, port
posture). Zoning evidence is treated as one of many inputs for advisory
context, but the engine does not perform a structured zoning consistency
review.

The Brocade **Zoning Analyzer** (Phase 6G-B) is fabric-aware but its
sole responsibility is zoning hygiene: alias/zone/cfg consistency,
defined vs effective alignment, name-server reconciliation, single-
initiator patterns, duplicate WWN references, dark zones, orphan
aliases, and peer-fabric evidence.

The two engines complement each other and are independently audited.

## 3. Inputs

Required minimum (at least one):
- `cfgshowText`
- `zoneshowText`

Recommended:
- `cfgshowText` + `zoneshowText` + `nsshowText`

Optional fabric context:
- `switchshowText`, `fabricshowText`, `portshowText`,
  `islshowText`, `trunkshowText`, `firmwareshowText`

Operator metadata:
- `analysisGoal` (required)
- `environmentContext`, `operatorNotes`

Caps:
- Total raw chars ≤ 200,000 (returns 400 `input-too-large` otherwise).

## 4. Output contract

`brocade_zoning_analysis@v1`:

```
{
  contract, ok, summary,
  zoningHealth: { posture, score?, evidenceQuality, activeDefinedAlignment, nameServerReconciliation },
  findings: [{ id?, severity, category, title, description, evidenceDescriptor?, impact?, recommendation? }],
  risks: [{ severity, title, rationale, affectedArea? }],
  hygieneChecks: [{ check, status, summary }],
  validationSteps[], stopConditions[], assumptions[], missingInputs[],
  issues[], criticReview?: { passed, blockers[] }
}
```

## 5. Safety boundary

- Advisory only.
- **No executable command syntax** (alicreate, zonecreate, zoneadd,
  zonedelete, zoneobject*, cfgcreate, cfgadd, cfgremove, cfgsave,
  cfgenable, cfgdisable, portenable, portdisable, switchdisable,
  firmwaredownload).
- No copy-pasteable change scripts or directives ("run this command",
  "copy and paste", "apply this config", "commit this change").
- No zoning change plans or pseudo-command descriptors.
- No cfgsave/cfgenable guidance.

## 6. Governance and audit

- Server-resolved governance via `resolveToolchainGovernance` with the
  hardened cache pattern (caller-supplied `governance` is stripped;
  only the internal `__governance` cache is honored).
- Critic stage is enabled by default. The critic blocks render on:
  - executable command syntax in output;
  - leaked specific identifiers (WWNs, aliases, zone names, cfg names,
    switch names, hostnames, IPs, serials);
  - recommending changes without change-control validation;
  - missing stop conditions for high-risk findings;
  - claims of authoritativeness.
- Audit row is written to `public.toolchain_executions` with
  `execution_kind = engine`, descriptor-only `sourceArtifacts`, counts/
  flags `observedFacts`, summary-only `toolchainTrace`. Internal cache
  keys are filtered from `topLevelKeys`.

## 7. Identifier redaction

- Defensive render-time redaction replaces detected WWNs and IPv4
  addresses in any string-valued field of the output with
  `[redacted-wwn]` / `[redacted-ip]`.
- This is a belt-and-suspenders pass on top of the system-prompt
  instruction and critic block.

## 8. Critic blockers

A reasoner output is blocked from render when:
- Local safety scan matches any forbidden command-syntax pattern.
- LLM critic returns `shouldBlockRender = true`.
- Governance has `criticBlocksRender = true` (request hints can tighten
  but never weaken this).

The HTTP response on block is **422 critic-blocked-render**.

## 9. Registry and portfolio changes

- New descriptor `brocadeZoningAnalyzer` in
  `src/data/toolchainEngineRegistry.ts`, attachable to
  `brocade-6510-lifecycle-ops` and `san-health-fabric-hygiene`.
- `contextFirst`: `status: "beta-ui"`, `defaultPath: "legacy"`,
  governance + audit + critic enabled.
- `portfolio`: `platform: "brocade"`, `archetype: "zoning-analysis"`,
  `lifecycleStage: "built-beta"`, `status: "built"`.

## 10. Planned override handling

The previous **Brocade / zoning-analysis** planned override in
`ENGINE_COVERAGE_OVERRIDES` has been removed so the matrix does not
double-count Brocade zoning as both built and planned.

The other zoning-analysis planned overrides are unchanged:
- Cisco MDS / zoning-analysis — still **Planned**.
- Cisco → Brocade / zoning-analysis — still **Planned**.

## 11. Demo behavior

A privileged-only demo button on `/toolchains/executions`
("Run Brocade Zoning Analyzer Demo") sends a synthetic payload with
`demo_*` placeholder aliases and zones. No real infrastructure is
contacted and no real identifiers are sent.

## 12. Known limitations

- No agent collector wired in this phase (Brocade read-only collection
  exists in the Fabric Analyzer; this engine intentionally defers
  enabling collectors until live validation).
- Output is advisory; it does not produce remediation commands.
- Critic LLM is best-effort; the local safety scan is the authoritative
  gate against forbidden command syntax leaking through.

## 13. Future

- Cisco MDS Zoning Analyzer (next Phase 6G-C candidate).
- Cross-vendor (Cisco → Brocade) zoning reconciliation analyzer.
- Live read-only collection hardening + agent collector wiring.
- Zoning scorecards / longitudinal hygiene tracking.
- Migration worksheet export (read-only, advisory).

## 14. Phase 6G-B.1 — Hardening Patch

This sub-phase patches the Brocade Zoning Analyzer before acceptance to
close two governance / safety gaps that surfaced during 6G-B review.

### 14.1 Governance cache fix

The per-request governance cache previously read/wrote the caller-visible
`body.governance` key. That coupling let callers spoof a resolved
governance object. The hardened pattern is now used:

- Strip any caller-supplied `body.governance` defensively
  (`try { delete body.governance; } catch {}`).
- Cache resolved governance under the internal key `body.__governance`
  only.
- Never read `body.governance` after deletion.

### 14.2 INTERNAL_KEYS fix

The audit / input-summary filter now uses exactly:

```ts
const INTERNAL_KEYS = new Set(["governance", "_governance", "__governance"]);
```

This removes the duplicated `"governance"` entry and adds the
`"__governance"` cache key, ensuring no internal governance object
appears in `topLevelKeys` of the audit row.

### 14.3 Identifier-leak safety expansion

The local safety scan was expanded beyond command-syntax to also detect
identifier leakage in any string-valued field of the reasoner output.
Patterns added:

- WWN (existing)
- IPv4 (existing)
- Email address
- Hostname / FQDN (heuristic, multi-label, alphabetic TLD)
- Long opaque token / secret-looking string (>=24 chars)
- Serial-like token (uppercase + digits, 6–20 chars)
- Object-name leakage: `alias <name>`, `zone <name>`, `cfg <name>`
- Quoted / backticked object name leakage

Behavior:

- **Command-syntax hits** still block render with
  `critic-blocked-render` (422) when `criticBlocksRender` is true. The
  local critic remains the authoritative gate for command syntax.
- **Identifier-leak hits** also block render when `criticBlocksRender`
  is true, with a message that lists the leaked categories.
- Render-time redaction is now extended to cover the same set of
  identifier patterns and acts as a final defense-in-depth pass on top
  of the critic gate.

### 14.4 Validation

- `bunx vitest run src/data/__tests__/contextFirstRegistry.test.ts` →
  9/9 pass.
- `bunx tsc --noEmit` → clean.


---

## Phase 6G-B.2 — Sample + Agent Parity

Brings the Brocade Zoning Analyzer to UX parity with the Brocade Fabric
Analyzer. Registry metadata only — no engine, edge function, governance,
critic, output-contract, or CMS changes.

### Added

- **Load Full Zoning Sample** (`full-brocade-zoning`) — covers
  `analysisGoal`, `cfgshowText`, `zoneshowText`, `nsshowText`,
  `switchshowText`, `fabricshowText`, `portshowText`, `islshowText`,
  `trunkshowText`, `firmwareshowText`, `environmentContext`, and
  `operatorNotes` with synthetic `DEMO_*` aliases and placeholder WWNs.
- **Read-only agent collector** `brocade-zoning-readonly`:

```
platform:           brocade
mode:               read-only
enabled:            true
requiredCapability: agent.collect.brocade.readonly
operationIds:       brocade-api-switch-status, brocade-api-fabric-switches,
                    brocade-api-fc-ports, brocade-api-name-server,
                    brocade-api-zone-defined, brocade-api-zone-effective
outputMap:          fc-ports → portshowText (NOT switchshowText);
                    other ops map 1:1 to their evidence fields.
```

The collector reuses the existing read-only Brocade operations consumed
by the Fabric Analyzer's collector — no new operation IDs and no
write/change operations.

### Behavior

- EngineActionPanel renders both sample buttons (Minimal / Full) plus
  Clear, no component changes required.
- EngineAgentCollectorPanel renders the new collector card; collector
  preview/redaction step runs before any field is populated; the engine
  is never auto-run after collection.
- Output contract remains `brocade_zoning_analysis@v1`.

### Tests

`src/data/__tests__/contextFirstRegistry.test.ts` adds a
"Phase 6G-B.2 sample + agent parity" suite asserting both samples,
field coverage, the exact `operationIds` and `outputMap`, mode
`read-only`, and the absence of any write/change operation tokens.
