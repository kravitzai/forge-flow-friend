# Context-First Architecture

_Canonical architecture document for ForgeAI / FilterREX toolchains._

## 1. Why the Platform Is Moving from Prompt-First to Context-First

Prompt-first analyzers concatenated user input into a prompt and asked an
LLM to interpret it. That pattern is brittle: it conflates "what the user
gave us" with "what the model should reason over", it provides no audit
surface, no validation surface, no governance surface, and no consistent
output contract. As ForgeAI grew across SAN, Proxmox, Terraform, Helm,
observability, and AI-fabric domains, the prompt-first pattern stopped
scaling — both technically and operationally.

Context-first inverts the relationship: the platform _builds and governs_
the context, then asks the model to reason over a structured pack with a
declared output contract.

## 2. Core Principle

> AI quality depends on the quality, structure, freshness, and safety of
> the context supplied to the model.

Everything else — routing, critic, governance, UI — exists to protect that
principle.

## 3. Old Pattern: Prompt-First Analyzer

```
User input → Prompt → LLM → Response
```

No validation. No structured facts. No routing policy. No critic. No
audit. Output shape depends on the model's mood.

## 4. New Pattern: Context-First Toolchain

```
Collect → Normalize → Validate → Package → Reason → Critic → Render → Audit
```

Each step is a typed `ToolchainStepDefinition`. Each step's output feeds
the next. The pack is the contract between deterministic infrastructure
and the model.

## 5. OperationalContextPack

Defined in `src/types/operationalContextPack.ts`. It carries:

- `intent` and `domain` — task identity.
- `observedFacts` — structured, machine-readable facts.
- `assumptions` — explicit, with rationale.
- `missingInputs` — known gaps the engine could not fill.
- `sourceArtifacts` — safe descriptors (size/excerpt), never raw.
- `validationResults` — pass/fail per check.
- `constraints` — `lan-only`, `no-write-ops`, etc.
- `riskFlags` — surfaced to UI and logs.
- `outputContract` — schema name + version returned to caller.
- `llmRouting` — provider/model/runtime + policy ref.
- `toolchainTrace` — per-step status + duration.

The pack is what the model sees. It is also what the audit row summarizes.

## 6. ToolchainExecutionEngine

Defined in `src/types/toolchainEngine.ts` and implemented in
`supabase/functions/_shared/toolchainEngine.ts`. Engine plays differ from
legacy analyzer functions in three ways:

1. **Lifecycle.** Steps are explicit and ordered, not implicit inside one
   handler.
2. **Contract.** Each step declares a typed input/output and feeds a
   shared `ToolchainStepContext`.
3. **Auditability.** Every run writes one `toolchain_executions` row with
   safe summaries, model routing, and trace.

Engine pilots today: Terraform analyzer, Proxmox cluster health.

## 7. Shadow Logging vs Engine Execution

Shadow logging (Phase 2) wraps legacy prompt-first analyzers and writes a
`toolchain_executions` row with `execution_kind='shadow'`. Engine
execution (Phase 3+) writes the same table with `execution_kind='engine'`.

Shadow logging was introduced first because it gave us:

- A single audit table that survives the migration.
- Real-traffic data on which analyzers matter.
- A safe, behavior-preserving wedge to start the rest of the migration.

## 8. Router Reasoning and Model Policy

`ai_fabric_model_policies` resolves a `(preferred_model, fallback_model,
preferred_runtime, allowed_runtime_types,
commercial_escalation_allowed, capabilities)` tuple. Scoping is
`global | org | domain | toolchain | play | role`, scored by specificity
with `priority` as a tiebreaker.

`ai_fabric_route_steps` lets a route fan out into ordered steps with
`step_type ∈ {reason, critic, summarize, validate, render}`. A step may
pin its own `model_policy_id`. Phase 4B/4C wired `reason` and `critic`
overrides into the engine pilots; the legacy dispatcher still uses the
two-role chain.

Runtime preferences:

- `local_only` — never reach commercial gateway.
- `local_first` — prefer local, allow commercial fallback.
- `commercial_first` — prefer commercial, allow local fallback.
- `commercial_only` — only commercial.
- `manual` — caller specifies.

LAN-only mode strips commercial runtimes, overrides `commercial_*` to
`local_only`, forces `commercial_escalation_allowed = false`, and
degrades to a synthetic local-only default if needed.

Policy override behavior: a route step's `model_policy_id` takes
precedence over a role-level policy when present and matched for the
correct `step_type`.

## 9. Critic Pass

The critic re-evaluates reasoner output before render. It runs only for
the engine pilots today.

- The critic sees a safe summary of the reasoner output and the context
  pack — never raw HCL, raw Proxmox payloads, or secrets.
- The critic returns `verdict`, `confidence`, structured `issues`, and
  `shouldBlockRender`.
- **Non-blocking by default.** Infrastructure failures in the critic step
  succeed at the engine level (`status: succeeded`, `stop: false`).
- **Blocking** is the explicit composition:
  `criticPassEnabled && criticBlocksRender && shouldBlockRender === true`
  → HTTP 422 with `error.code = 'critic-blocked-render'`.
- The critic respects `step_type='critic'` policy overrides.

## 10. Governance

`toolchain_governance_policies` centralizes engine controls (router on/off,
critic on/off, critic-blocks-render, LAN-only, runtime constraints).

Precedence (highest to lowest authority):

1. **Server Policy** — `toolchain_governance_policies` row.
2. **Env Force-Flags** — operational overrides (e.g.
   `TOOLCHAIN_ENGINE_CRITIC_PASS=true`).
3. **Request Hints** — pilot/dev hints in the request body or headers.
4. **Synthetic Default** — preserves pre-governance behavior.

Request hints can _tighten_ behavior (opt in to critic, etc.) but cannot
_weaken_ security controls — they cannot disable LAN-only or override a
server-enforced critic block.

## 11. Execution Visibility (planned)

The intended UI surfaces what the audit row already captures:

- Execution list (filter by toolchain, status, domain, intent).
- Execution detail with the context pack viewer.
- Trace viewer with per-step status and duration.
- Model routing card (provider, model, runtime, policy ref).
- Critic summary (verdict, counts, blocked yes/no).
- Governance summary (resolved policy id, source, LAN-only state).
- Errors and risk flags.

Today these are visible only in DB rows.

## 12. Redaction and Safety

- Raw prompts: not logged.
- Raw HCL: not logged.
- Raw Proxmox payloads: not logged.
- Secrets/tokens/credentials: not logged.
- Source artifacts: descriptors only (`id`, `kind`, `size`, optional safe
  excerpt).
- Logged shape: counts, identifiers, validation outcomes, model
  identifiers, critic counts, governance summary, trace step names.

## 13. Migration Path

```
Legacy analyzer
  → Centralized helper (Phase 1)
  → Shadow logging (Phase 2)
  → Engine pilot (Phase 3+)
  → Governed context-aware toolchain (Phase 4)
```

See `docs/context-first-analyzer-migration-map.md` for the per-analyzer
status and recommended sequence.

## 14. Future Direction

- Execution visibility UI.
- Policy visibility UI.
- Server-side governance completion (governance summary on every step,
  app-side types/hooks, admin controls).
- Local-runtime HTTP transport (Ollama / vLLM / OpenAI-compatible local
  endpoints) for true local-only execution.
- Broader analyzer migration off prompt-first.
- Reusable persisted context packs and agentic multi-step workflows with
  task handoff.
