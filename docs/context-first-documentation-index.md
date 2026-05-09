# Context-First Documentation Index

This is the canonical reading path for the context-first toolchain
architecture. Phase notes remain authoritative for implementation
history; the context-first docs are authoritative for direction.

## Reading Order

1. [`context-first-current-state-assessment.md`](./context-first-current-state-assessment.md)
   — what is real today.
2. [`context-first-architecture.md`](./context-first-architecture.md)
   — canonical architecture and core principles.
3. [`context-first-roadmap.md`](./context-first-roadmap.md)
   — capability milestones (replaces phase-only thinking).
4. [`context-first-analyzer-migration-map.md`](./context-first-analyzer-migration-map.md)
   — per-analyzer migration plan and sequence.
5. [`toolchains-llm-gap-analysis.md`](./toolchains-llm-gap-analysis.md)
   — original gap analysis that motivated the migration.
6. [`toolchains-phase-1-notes.md`](./toolchains-phase-1-notes.md)
   — analyzer helper centralization.
7. [`toolchains-phase-2-notes.md`](./toolchains-phase-2-notes.md)
   — shadow logging and `OperationalContextPack` foundations.
8. [`toolchains-phase-3-notes.md`](./toolchains-phase-3-notes.md)
   — `ToolchainExecutionEngine` pilots.
9. [`toolchains-phase-4a-notes.md`](./toolchains-phase-4a-notes.md)
   — model policies and route-step schema.
10. [`toolchains-phase-4b-notes.md`](./toolchains-phase-4b-notes.md)
    — router reasoning in pilots.
11. [`toolchains-phase-4c-notes.md`](./toolchains-phase-4c-notes.md)
    — critic pass (and 4C.1 correctness).
12. [`context-first-demo-validation.md`](./context-first-demo-validation.md)
    — Phase 4D-C demo + manual validation guide.
13. [`toolchains-phase-4d-notes.md`](./toolchains-phase-4d-notes.md)
    — server-side governance + execution & policy visibility (Phase 4D-A/4D-B).

## Who Should Read What

| Role | Start with | Then read |
|---|---|---|
| Product owner | Roadmap, Current State Assessment | Architecture |
| Developer (new to toolchains) | Architecture, Current State Assessment | Phase 2 → Phase 4C notes |
| Developer (migrating an analyzer) | Migration Map, Architecture | Phase 3 + Phase 4A notes |
| Security reviewer | Architecture §10–§12, Current State Assessment | Phase 4A + 4C + 4D notes |
| AI/LLM engineer | Architecture §5–§9 | Phase 4A + 4B + 4C notes |
| Platform admin | Roadmap, Current State Assessment | Architecture §10–§11 |
| Future maintainer | Index (this file), Architecture | Phase notes in order |
14. [`toolchains-phase-4e-notes.md`](./toolchains-phase-4e-notes.md)
    — admin policy CRUD UI (Phase 4E-A).
15. [`toolchains-phase-5a-notes.md`](./toolchains-phase-5a-notes.md)
    — SRDF engine pilot migration (Phase 5A).
16. [`toolchains-phase-5b-srdf-ui-integration.md`](./toolchains-phase-5b-srdf-ui-integration.md)
    — SRDF toolchain UI integration / engine opt-in toggle (Phase 5B).
17. [`toolchains-phase-6a-brocade-fabric-engine.md`](./toolchains-phase-6a-brocade-fabric-engine.md)
    — Brocade fabric analyzer engine (Phase 6A, edge function only).
18. [`toolchains-phase-6b-cisco-mds-fabric-engine.md`](./toolchains-phase-6b-cisco-mds-fabric-engine.md)
    — Cisco MDS fabric analyzer engine (Phase 6B, edge function only, demo-only).
19. [`toolchains-phase-6c-cisco-to-brocade-migration-readiness.md`](./toolchains-phase-6c-cisco-to-brocade-migration-readiness.md)
    — Cisco MDS → Brocade migration readiness engine (Phase 6C, readiness only, demo-only). Phase 6D pseudo-command generator is planned.
20. [`toolchains-phase-6e-engine-registry-and-toolchain-wiring.md`](./toolchains-phase-6e-engine-registry-and-toolchain-wiring.md)
    — Engine registry + generic toolchain action panel (Phase 6E-A). Wires Brocade engine into BR6510 Lifecycle and SAN Health + Fabric Hygiene toolchain pages without refactoring edge functions.
21. [`toolchains-phase-6e-b-cisco-migration-toolchain-wiring.md`](./toolchains-phase-6e-b-cisco-migration-toolchain-wiring.md)
    — Cisco MDS → Brocade SAN Migration canonical toolchain page (Phase 6E-B).
22. [`toolchains-phase-6e-c-engine-input-ux-samples-agent-ready.md`](./toolchains-phase-6e-c-engine-input-ux-samples-agent-ready.md)
    — Engine input UX: sample payloads, clear form, agent-ready collector metadata (Phase 6E-C).
23. [`toolchains-phase-6e-d-agent-backed-readonly-collection.md`](./toolchains-phase-6e-d-agent-backed-readonly-collection.md)
    — Agent-backed read-only collection via existing api-operation-executor and operationIds (Phase 6E-D). Brocade + Cisco MDS leaf collectors enabled; composite Cisco→Brocade deferred.
24. [`toolchains-phase-6f-b-context-first-engine-portfolio-tracker.md`](./toolchains-phase-6f-b-context-first-engine-portfolio-tracker.md)
    — Context-First Engine Portfolio Tracker (Phase 6F-B). Replaces the flat tracker in `/admin/dev-tools` with a registry-derived Platform Matrix / Archetype Catalog / Lifecycle Pipeline.
25. [`toolchains-phase-6f-c-public-context-first-polish.md`](./toolchains-phase-6f-c-public-context-first-polish.md)
    — Public Context-First Polish + Tracker-Derived Roadmap Visibility (Phase 6F-C). Polishes `/context-first`, refreshes the `/how-it-works` callout, and adds a derived Context-First badge on toolchain cards.
26. [`toolchains-phase-6g-a-zoning-analysis-archetype-roadmap.md`](./toolchains-phase-6g-a-zoning-analysis-archetype-roadmap.md)
    — Zoning Analysis archetype roadmap visibility (Phase 6G-A). Adds `zoning-analysis` archetype + Brocade / Cisco MDS / Cisco → Brocade planned overrides. No new engine built.
27. [`toolchains-phase-6g-b-brocade-zoning-analyzer.md`](./toolchains-phase-6g-b-brocade-zoning-analyzer.md)
    — Brocade Zoning Analyzer (Phase 6G-B). First built `zoning-analysis` engine. Read-only advisory; never emits executable command syntax. Brocade planned override removed.
28. [`toolchains-phase-6g-c-cisco-mds-zoning-analyzer.md`](./toolchains-phase-6g-c-cisco-mds-zoning-analyzer.md)
    — Cisco MDS Zoning Analyzer (Phase 6G-C). Read-only Cisco MDS zoning hygiene engine; advisory only.
29. [`toolchains-phase-6h-a-engine-contract-inspector.md`](./toolchains-phase-6h-a-engine-contract-inspector.md)
    — Engine Contract Inspector (Phase 6H-A). Read-only admin tab in `/admin/dev-tools` exposing every engine descriptor, input/output contract, lifecycle/portfolio metadata, sample payloads, and recent execution summaries.
30. [`toolchains-phase-6h-c-engine-catalog.md`](./toolchains-phase-6h-c-engine-catalog.md)
    — Public Engine Catalog + Contextual Toolchain CTAs (Phase 6H-C). New `/toolchains/engines` page (registry-derived), Context-First Engines section injected into `/toolchains/:slug`, no CMS rows seeded.
31. [`toolchains-phase-6h-d-engine-surface-parity.md`](./toolchains-phase-6h-d-engine-surface-parity.md)
    — Engine Surface Parity (Phase 6H-D). Auto-derives `engineActions` from registry `attachableTo` so built, non-hidden engines render via `EngineActionPanel` on attached toolchain pages without CMS edits. Phase 6H-D.1 adds an admin-only CMS notice; Phase 6H-D.2 routes catalog "Open Engine" to `#engine-action-<id>`.
32. [`toolchains-phase-6h-e-standalone-engine-pages.md`](./toolchains-phase-6h-e-standalone-engine-pages.md)
    — Standalone Engine Pages (Phase 6H-E). New route `/toolchains/engines/:engineId` renders a single-engine runner independent of any toolchain. `getEngineOpenRoute` now points the catalog "Open Engine" CTA at the standalone page; attached-toolchain chips keep the in-context anchor flow.
33. [`toolchains-phase-6h-f-engine-catalog-parity-standard.md`](./toolchains-phase-6h-f-engine-catalog-parity-standard.md)
    — Engine Catalog Sample + Agent Parity Standard (Phase 6H-F). Standardizes Load Minimal/Full Sample + Pull from Agent (or machine-readable `agentCollectorExemption.reason`) across every built (Beta) and Promoted Default engine. Registry metadata + test enforcement only — no runtime, edge function, or CMS changes.
34. [`toolchains-phase-6h-g-srdf-surface-promotion.md`](./toolchains-phase-6h-g-srdf-surface-promotion.md)
    — Phase Doc Resolver + SRDF Analyzer Surface Promotion (Phase 6H-G). 6H-G.0 fixes broken Engine Catalog "Phase doc" links via a configurable `VITE_SOURCE_DOCS_BASE_URL` resolver. 6H-G.1 promotes the Dell PowerMax SRDF Analyzer into the standalone/catalog runner surface (un-hidden, attached to `powermax-tier0-change-windows`, with minimal/full samples and a real PowerMax read-only agent collector). Registry + UI link wiring only — engine logic, edge function, governance, critic, and the legacy SRDF play are unchanged.
35. [`toolchains-phase-6h-g-3-public-docs-publishing.md`](./toolchains-phase-6h-g-3-public-docs-publishing.md)
    — Public Docs Publishing for Phase Doc Links (Phase 6H-G.3). Adds whitelist-driven mirroring of referenced phase docs into the existing public repo `kravitzai/forge-flow-friend` via the same private→public sync workflow. Whitelist (`scripts/public-docs-whitelist.txt`) + export script (`scripts/export-public-docs.sh`) + registry-drift test in `contextFirstRegistry.test.ts`. No app runtime, registry, edge function, or CMS changes.
36. [`toolchains-phase-6i-a-canonical-san-zoning-model.md`](./toolchains-phase-6i-a-canonical-san-zoning-model.md)
    — Canonical SAN Zoning Model (Phase 6I-A). Vendor-neutral foundation for upcoming Cisco MDS / Brocade zoning normalizers and the Cisco → Brocade conversion plan engine. Pure types, helpers, invariants, fixtures, and tests under `src/lib/canonicalZoning/`. No vendor parsers, no conversion logic, no command generation, no UI/registry/CMS/edge changes.
37. [`toolchains-phase-6i-b-cisco-mds-canonical-normalizer.md`](./toolchains-phase-6i-b-cisco-mds-canonical-normalizer.md)
    — Cisco MDS → Canonical Zoning Normalizer (Phase 6I-B). Pure parser/composer layer that turns NX-OS `show` outputs into `canonical-san-zoning@v1`. Per-command parsers, deterministic ID minting, alias placeholder + VSAN logical-fabric synthesis for partial evidence. No registry, runtime adapter, edge function, CMS, or UI changes.

## Operator Tracker

`/admin/dev-tools` renders a read-only **Context-First Transition** section
(milestone strip, analyzer matrix, live signals, governance counts).
The typed mirror of this doc set lives at
`src/data/contextFirstTransition.ts` — update it alongside any future phase
note so the admin tracker stays in sync.
