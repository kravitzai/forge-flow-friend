# Phase 6E-D — Agent-backed Read-Only Collection

Status: shipped (live collection partial — gated on registered Brocade /
Cisco MDS targets being present in the workspace).

## Goal

Let an operator pull read-only evidence from a registered agent target
into a context-first engine's input form, review what was collected,
optionally redact obvious identifiers, and **manually** click *Run engine*.
No auto-run. No new credential or execution path.

## Why operationIds replaced CLI command strings

The earlier 6E-C metadata listed CLI command strings (`switchshow`,
`show vsan`, …) as a placeholder for a future agent-side CLI executor.
Building that path would have created a parallel — and weaker — execution
surface alongside the existing `api-operation-executor` pipeline:

- Every Brocade and Cisco MDS API operation in
  `src/data/apiOperations/{brocade,cisco-mds}.ts` is already declared
  `safetyLevel: "read-only"`.
- `api-operation-executor` already enforces a max safety level, resolves
  credentials from `connector_target_profiles` via Supabase Vault
  (`get_target_credentials` SECURITY DEFINER), and supports both direct
  LAN and via-agent relay.
- `executeApiOperation` (`src/lib/apiExecution/executor.ts`) is the
  single shared entry point used by every dashboard.

Pivoting the collector to reference existing `operationId`s reuses all
of that hardening with zero new infrastructure.

## What did NOT change

- No new edge function.
- No CLI / SSH executor.
- No new credential schema.
- No analyzer / governance / router / critic behavior change.
- No registry schema additions beyond renaming `commands` → `operationIds`.

## Collector metadata schema

`ToolchainEngineAgentCollector` in
`src/data/toolchainEngineRegistry.ts`:

```ts
{
  id: string;
  label: string;
  description?: string;
  platform: string;            // matches ApiOperation.platform AND target_type
  requiredCapability: string;
  mode: "read-only";
  operationIds?: string[];     // every id MUST resolve to a read-only op
  outputMap: Record<string, string>; // operationId -> engine input field key
  enabled?: boolean;
}
```

## Active leaf collectors

**Brocade (`brocade-readonly-basic`, enabled)** maps:

| operationId | field |
|---|---|
| `brocade-api-switch-status` | `switchshowText` |
| `brocade-api-fabric-switches` | `fabricshowText` |
| `brocade-api-fc-ports` | `switchshowText` (concatenated) |
| `brocade-api-name-server` | `nsshowText` |
| `brocade-api-zone-defined` | `cfgshowText` |
| `brocade-api-zone-effective` | `zoneshowText` |

Documented gaps (no read-only catalog entry today; not invented):
`firmwareshow` (covered by `brocade-api-switch-status` payload),
`islshow`, `trunkshow`, `errdump`. Future: extend the Brocade catalog,
then wire here.

**Cisco MDS (`cisco-mds-readonly-basic`, enabled)** maps eight
`mds-api-show-*` operations 1:1 to `show*Text` fields.

**Cisco → Brocade composite (`cisco-to-brocade-readonly-composite`,
disabled)** — kept as visible placeholder. UI shows a deferred message:
*"Composite two-target collection is deferred until single-target
Brocade and Cisco MDS leaf collectors are validated."* No two-target
picker shipped.

## UI behavior

`EngineAgentCollectorPanel.tsx` (rendered inside `EngineActionPanel`):

1. **Picker** — collector (skipped when only one is enabled).
2. **Target picker** — queries `connector_target_profiles` filtered by
   `target_type = collector.platform AND enabled = true`. If none:
   inline empty state ("No compatible read-only agent target available").
3. **Operation preview** — title, method, mapped engine field, plus a
   "all read-only" banner. Any unresolved or non-read-only operation
   blocks Collect with an explicit reason.
4. **Collect** — sequential `executeApiOperation` calls (one target,
   ≤ 8 ops; sequential avoids the relay claim-lease contention; the
   browser-side multi-target parallelism cap doesn't apply here).
5. **Redaction preview** — shows per-op summary (status, char/line
   counts, durationMs) and aggregate detected-identifier counts (WWN,
   IPv4, hostname, email, opaque token, vendor-style serial).
6. **Three actions** — `Cancel`, `Populate sanitized output`,
   `Populate original output…` (the third requires an explicit confirm
   step). Cancel preserves existing form values.
7. **Populate** — single `update(engine.id, { values, result: null,
   error: null, inputsCollapsed: false })`. Engine does not auto-run.

## Read-only safety enforcement (browser side)

Belt-and-suspenders in `EngineAgentCollectorPanel`:

- Every `operationId` is resolved against the catalog. Missing → block.
- Any `safetyLevel !== "read-only"` → block.
- Any `platform !== collector.platform` → block.

Server-side enforcement is unchanged: `api-operation-executor` rejects
anything above its `MAX_SAFETY_LEVEL` and validates the target_profile.

## Redaction (heuristic, partial)

`src/lib/toolchainAgentRedaction.ts`:

- WWN `xx:xx:xx:xx:xx:xx:xx:xx` → `WWN_n`
- IPv4 → `IP_n`
- Email → `EMAIL_n`
- FQDN-ish (≥2 labels, alphabetic TLD 2-24) → `HOST_n`
- Opaque token (≥32 chars `[A-Za-z0-9_-]`, not WWN-shaped) → `[REDACTED_TOKEN]`
- Vendor serial (`^[A-Z]{2,4}[0-9]{6,}$`, or value following `serial:`) →
  `SERIAL_n`

Honestly labeled in the UI: heuristic, not a guarantee of anonymization.

## Browser-state safety

- Raw and sanitized outputs live only in `EngineAgentCollectorPanel`
  component state.
- Per-operation `console.log` records `op · status · durationMs · chars
  · lines` only — never response bodies.
- No URL, localStorage, sessionStorage, route state, CMS, or analytics
  writes. Verified by inspection of the panel and of
  `EngineActionPanel` (which already has a Phase 6E-C zero-storage
  guarantee).

## Auto-run prevention

The Populate path writes only to `EngineActionPanel`'s per-engine
`values` and resets `result`/`error`. There is no code path that calls
`handleRun` as a side effect of populating. A `/toolchains/executions`
row is only produced when the operator clicks **Run engine**.

## Known limitations

- Live collection requires a registered Brocade or Cisco MDS target in
  the current workspace. Without one, the panel shows the empty-state
  message — UI shell + guard logic still validate, but end-to-end live
  collection is **partial** in that environment.
- Composite Cisco → Brocade collector remains deferred.
- Redaction is heuristic (see above).
- Two Brocade ops currently map to the same `switchshowText` field —
  outputs are concatenated with a `--- <opId> ---` separator. A more
  granular schema (e.g. `fcPortsText`) is a future improvement.

## Future

- Two-target composite collector with explicit two-target picker.
- Stronger deterministic redaction (reversible token mapping,
  structured-output-aware).
- Agent-side redaction before output ever reaches the browser.
- Saved sanitized evidence packages (operator-approved attachments).
- Catalog additions for ISL / trunk / errdump / firmware to close
  Brocade gap.

---

## Phase 6E-D.1 — Brocade Live Validation

Single-platform leaf rollout. No composite, no Cisco MDS live, no SSH/CLI, no
new edge function, no auto-run.

### Pre-flight (code + DB audit)

- **Brocade target available**: yes — one row in `connector_target_profiles`
  with `target_type = brocade`, `enabled = true`, `status = active`
  (id `3615ab8d-c848-4796-a5bc-90bc9abdf5a3`). Live validation is not blocked
  by missing target.
- **Collector → operationIds mapping** (`brocade-readonly-basic` in
  `src/data/toolchainEngineRegistry.ts`):
  - `brocade-api-switch-status` → `switchshowText`
  - `brocade-api-fabric-switches` → `fabricshowText`
  - `brocade-api-fc-ports` → `switchshowText`
  - `brocade-api-name-server` → `nsshowText`
  - `brocade-api-zone-defined` → `cfgshowText`
  - `brocade-api-zone-effective` → `zoneshowText`
- **Catalog audit** (`src/data/apiOperations/brocade.ts`): every referenced
  operationId exists with `platform: "brocade"` and
  `safetyLevel: "read-only"`. No registry/outputMap fixes required.
- **Composite Cisco→Brocade collector** (`cisco-to-brocade-readonly-composite`)
  remains `enabled: false` — untouched in this phase.

### Static checks

- `bunx tsc --noEmit` — clean (no diagnostics).
- No new files added; no analyzer / governance / edge-function code changed.

### Operator checklist (in-loop validation)

The following gates require an operator on the FilterREX UI with the lab
Brocade target reachable. Each gate must pass before phase acceptance:

| Gate | Expected result |
|---|---|
| Pull from Agent visible on `/toolchains/brocade-6510-lifecycle-ops` and `/toolchains/san-health-fabric-hygiene` | Yes |
| Brocade target selectable in collector | Yes (one target) |
| Operation preview lists 6 operations, all read-only | Yes |
| Click Collect → routes through `executeApiOperation` / `api-operation-executor` | Yes |
| Per-op `status`, `chars`, `lines`, `durationMs`, `errorSummary` returned | Yes |
| Analyzer not invoked during collection | Yes |
| Redaction preview shows counts (WWN / IPv4 / hostname / email / token / serial) without raw output | Yes |
| Cancel → form unchanged, no execution row | Yes |
| Populate sanitized → 5 mapped fields populate, previous result clears, no auto-run | Yes |
| Populate original → requires explicit confirm, no auto-run | Yes |
| Manual Run engine → inline result/safe error + new `toolchain_executions` row | Yes |
| Audit row: `execution_kind=engine`, `domain=san`, descriptor-only context_pack | Yes |
| Browser state (URL / localStorage / sessionStorage / route state / console / CMS) free of raw collected output | Yes |

If FOS on the lab switch rejects any of the 6 ops, the per-op error surface is
the correct outcome — the failure is reported in the collection result and no
SSH/CLI workaround is added.

### Audit query

```sql
select id, started_at, execution_kind, status, integration_id, domain, intent,
       input_summary, output_summary, error_summary,
       context_pack->'observedFacts'  as observed_facts,
       context_pack->'sourceArtifacts' as source_artifacts,
       context_pack->'toolchainTrace'  as trace
from public.toolchain_executions
where integration_id = 'toolchain-engine-brocade-fabric-analyzer'
order by started_at desc
limit 5;
```

Reject the run and revert if any audit row contains raw switch text, raw WWNs,
raw IPs, raw serials, raw hostnames, or credentials.

### Known limitations

- Lab switch FOS level may not implement every REST endpoint; partial-success
  collections are expected and acceptable.
- Cisco MDS live pull and Cisco→Brocade composite collection remain deferred.
- Agent-side redaction (so raw output never reaches the browser) is still a
  follow-up; client-side redaction is what 6E-D.1 validates.

### Acceptance

- Code-side gates: **pass** (operationIds mapped, all read-only, tsc clean,
  composite still disabled, no scope expansion).
- Live operator gates: **pending operator walkthrough** against the registered
  Brocade target. Phase status flips to `accepted` once all checklist gates
  above are satisfied; `partial` if any in-loop gate fails; `blocked` only if
  the registered Brocade target becomes unreachable before validation.

### Bootstrap fix (post-validation)

First live attempt against the registered Brocade target returned
`No runtime adapter registered for platform "brocade"` for all 6 ops.

**Root cause**: `bootstrapPlatformRuntimes()` (in
`src/lib/apiExecution/platforms/index.ts`) is only triggered via
`ensureSnapshotAdaptersRegistered()`, which is invoked by snapshot /
workbench / dashboard hooks. `EngineAgentCollectorPanel` did not call it,
so reaching a toolchain page directly left the runtime registry empty.
The Brocade adapter (and every other platform's adapter) was already
registered in code — just never executed on this navigation path.

**Fix**: `EngineAgentCollectorPanel.tsx` now calls
`ensureSnapshotAdaptersRegistered()` at module load. Same pattern used by
`useSnapshotFeed`, `FilterWorkbenchPage`, `AgentRecommendations`, etc. No
new bootstrap function, no executor change, no adapter change.

`bunx tsc --noEmit` clean after the fix.

### Name Server 404 → empty-list handling (FOS 8.2.x)

**Investigation**: Per Broadcom's FOS REST API Reference, `brocade-name-server`
is supported on FOS 8.2.0a and later, and `/rest/running/brocade-name-server/fibrechannel-name-server`
is the documented path on both 8.2.x and 9.x. The path in our catalog is
correct; the lab switch (FOS `v8.2.3b`) is hitting the well-known FOS 8.2.x
quirk where the REST API returns **HTTP 404 instead of 200 + empty list** when
the Name Server has zero registered entries. FOS 9.x corrected this to return
an empty list. The user's switch is sparsely populated (2 fabric switches,
mostly disabled G-ports, no F-port logins), which matches an empty NS state.

**Fix (collector-localized, single op)**: `EngineAgentCollectorPanel.handleCollect`
now treats the specific tuple `(operationId === "brocade-api-name-server" &&
httpStatus === 404)` as a successful empty collection (`{ items: [] }`).
Every other op, every other 404, and every other platform continues to
report the upstream error as before. No catalog change, no runtime adapter
change, no executor change, no edge function change.

This keeps the engine input populated with a descriptor field instead of an
error, and the audit row remains descriptor-only.

`bunx tsc --noEmit` clean after the change.
