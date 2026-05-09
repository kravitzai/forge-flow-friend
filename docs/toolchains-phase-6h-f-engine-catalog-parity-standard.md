# Phase 6H-F — Engine Catalog Sample + Agent Parity Standard

## Purpose

Standardize the standalone engine runner UX so every built (Beta) and
Promoted Default engine offers the same operator affordances:

- A `Load Minimal Sample` button.
- A `Load Full Sample` button (covers every input field).
- A `Pull from Agent` read-only collector — OR a machine-readable
  `agentCollectorExemption.reason` when the engine's input is not
  device-collectible.

This is registry metadata only. No engine runtime, edge function,
governance, critic, output-contract, or CMS changes.

## The Standard

For every engine where `portfolio.status === "built"` and
`hiddenFromActionPanel !== true`:

1. `samplePayloads` MUST contain at least one entry whose id/label
   includes `"minimal"` and one whose id/label includes `"full"`.
2. The full sample MUST populate every key in `inputFields`.
3. Either `agentCollectors` MUST contain at least one enabled read-only
   collector OR `agentCollectorExemption.reason` MUST be set with an
   operator-readable explanation.
4. Collector `outputMap` keys MUST exist in the engine's `inputFields`.
5. Collector operation IDs MUST NOT contain write/change tokens
   (`cfgsave`, `cfgenable`, `portdisable`, `firmwaredownload`,
   `zonecreate`, `commit`, etc.).
6. Samples MUST NOT contain real IPv4 addresses, emails, or secret
   keywords.

The `Phase 6H-F — engine catalog sample + agent parity standard` test
suite in `src/data/__tests__/contextFirstRegistry.test.ts` enforces all
of the above.

## Engines updated

| Engine | Sample added | Collector / Exemption |
|---|---|---|
| `cisco-mds-fabric-analyzer` | `full-cisco-mds-fabric` | (existing collector) |
| `cisco-mds-zoning-analyzer` | `full-cisco-mds-zoning` | new `cisco-mds-zoning-readonly` collector |
| `cisco-to-brocade-migration-readiness` | `full-cisco-to-brocade-readiness` | exemption (composite collector deferred) |
| `cisco-to-brocade-migration-pseudo-commands` | `full-cisco-to-brocade-pseudo-commands` | exemption (consumes readiness artifact) |
| `proxmox-cluster-health` | `minimal-` + `full-proxmox-cluster-health` | new `proxmox-readonly` collector |
| `terraform-analyzer` | `minimal-` + `full-terraform` | exemption (HCL/plan paste only) |

`brocade-fabric-analyzer` and `brocade-zoning-analyzer` already met
parity and were used as the reference shape.

## Exemptions

- **`terraform-analyzer`** — Terraform HCL and plan input is operator-provided
  text, not device-collected evidence.
- **`cisco-to-brocade-migration-pseudo-commands`** — Consumes a readiness
  artifact and operator descriptors rather than directly collecting device
  evidence.
- **`cisco-to-brocade-migration-readiness`** — Cross-vendor composite
  collector deferred until single-target Brocade and Cisco MDS leaf
  collectors land. The disabled composite descriptor is preserved for
  traceability.
- **`srdf-analyzer`** — `hiddenFromActionPanel: true`; rendered by the
  dedicated SRDF play and excluded from the parity standard entirely.

## Out of Scope

- Engine runtime, edge functions, output contracts, critics, governance.
- New API operation IDs or capabilities.
- `EngineActionPanel` / `EngineAgentCollectorPanel` component changes
  (already descriptor-driven).
- CMS rows.

## Validation

- `bunx vitest run src/data/__tests__/contextFirstRegistry.test.ts` — 74/74 passing.
- `bunx tsc --noEmit` — clean.
- Standalone engine pages at `/toolchains/engines/<id>` render the
  expected `Load Sample ▾` (with both entries) and `Pull from Agent`
  affordances.
