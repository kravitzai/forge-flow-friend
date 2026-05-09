# Toolchains Phase 6H-G — Phase Doc Resolver + SRDF Analyzer Surface Promotion

Phase 6H-G is split into two small, low-blast-radius patches:

- **6H-G.0** — fix the broken "Phase doc" links on engine cards.
- **6H-G.1** — promote the Dell PowerMax SRDF Analyzer into the same
  standalone/catalog runner surface every other built engine uses.

No engine logic, edge function, governance, critic, output contract, or
CMS rows change.

---

## 6H-G.0 — Phase doc resolver

### Problem
`ToolchainEnginesPage.tsx` and `ToolchainEngineDetailPage.tsx` rendered
`contextFirst.phaseDoc` (e.g. `docs/toolchains-phase-5a-notes.md`)
directly as an `href`. The repo's `docs/` folder is **not** served as a
static asset, so the browser resolved the link relative to the current
route → `/toolchains/engines/docs/...` → 404.

### Fix
New helper `src/lib/phaseDocLink.ts`:

```ts
resolvePhaseDocHref(phaseDoc: string | undefined | null): string | null
```

- Absolute `https://…` / `//…` URLs pass through unchanged.
- Repo-relative `docs/…` paths are prefixed with
  `import.meta.env.VITE_SOURCE_DOCS_BASE_URL` (no trailing slash).
- When no base is configured, returns `null` — callers hide the link
  rather than rendering a broken one.

Configure with e.g.

```
VITE_SOURCE_DOCS_BASE_URL=https://github.com/<owner>/<repo>/blob/main
```

### Call sites updated
- `src/pages/ToolchainEnginesPage.tsx`
- `src/pages/ToolchainEngineDetailPage.tsx`

Registry `phaseDoc` values are unchanged.

---

## 6H-G.1 — Dell PowerMax SRDF Analyzer surface promotion

### Problem
The `srdf-analyzer` descriptor was registered as `built` +
`promoted-default` but flagged `hiddenFromActionPanel: true` with
`attachableTo: []`. Its only entry point was the Phase 5B admin/beta
toggle inside the PowerMax Tier-0 SRDF play. The Engine Catalog showed
the card but the "Open Engine" CTA was suppressed (per
`getEngineOpenRoute`), and `/toolchains/engines/srdf-analyzer` rejected
the engine as "not available".

### Fix (registry-only)
In `src/data/toolchainEngineRegistry.ts`:

- Removed `hiddenFromActionPanel: true`.
- Set `attachableTo: ["powermax-tier0-change-windows"]` (the existing
  toolchain that hosts the SRDF play).
- Dropped the `roadmapNote` saying it is only rendered by the dedicated
  play. The legacy SRDF play remains untouched.
- Added Phase 6H-F parity assets:
  - `samplePayloads`: `minimal` + `full` (all six input fields covered
    in the full sample).
  - `agentCollectors`: a single read-only `powermax-srdf-readonly`
    collector that reuses existing PowerMax operation IDs.

### Collector mapping

```
pmax-api-rdf-groups       → srdfGroupsText
pmax-api-storage-groups   → deviceGroupingText
pmax-api-masking-views    → deviceGroupingText
pmax-api-host-groups      → deviceGroupingText
pmax-api-initiators       → deviceGroupingText
pmax-api-array-summary    → modeAndPolicyText
pmax-api-version          → contextNotes
pmax-api-health           → contextNotes
pmax-api-alerts           → contextNotes
pmax-api-directors        → contextNotes
```

`topologyDescription` is the operator goal field and intentionally not
populated by the collector.

All operation IDs already exist in `src/data/apiOperations/powermax.ts`.
None of them appear in the Phase 6H-F forbidden-token list (no
`commit`, `cfgsave`, `shutdown`, etc.).

### Coexistence with the SRDF play
The Phase 5B admin/beta toggle in `ToolchainActionPanel.tsx` is
unchanged. Operators still launch the engine from the dedicated SRDF
play. The standalone catalog runner is an additional surface, not a
replacement.

### Output / behavior
Unchanged. `report_analysis@v1`, governance on, critic on, audit
logged. The edge function `toolchain-engine-srdf-analyzer` is not
modified.

---

## Validation

- `bunx vitest run src/data/__tests__/contextFirstRegistry.test.ts`
  → **79/79 pass** (75 prior + 4 new Phase 6H-F parity assertions for
  `srdf-analyzer`).
- `bunx tsc --noEmit` clean.
- Browser smoke:
  - `/toolchains/engines` → `Dell PowerMax SRDF Analyzer` card now
    renders a working "Open Engine" CTA. Phase doc link only renders
    when `VITE_SOURCE_DOCS_BASE_URL` is set, and points at the repo
    source view when it is.
  - `/toolchains/engines/srdf-analyzer` → input form expanded, both
    samples loadable, Pull from Agent collector visible.
  - PowerMax Tier-0 SRDF play unchanged.

## Out of scope

- Engine logic / edge function changes.
- A separate Run history view for SRDF.
- Copying `docs/*.md` into `public/` for offline serving (kept GitHub
  source as the canonical doc surface).
