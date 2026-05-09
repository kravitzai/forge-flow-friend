# Phase 6G-C — Cisco MDS Zoning Analyzer (Context-First Engine)

## 1. Purpose
Read-only advisory analyzer for Cisco MDS Fibre Channel zoning evidence.
Reviews device-alias hygiene, zone/zoneset hygiene, VSAN scoping,
FLOGI/FCNS reconciliation, and active-vs-full zoneset alignment.

## 2. Why zoning-analysis is separate from fabric-health
Fabric-health evaluates port/ISL/firmware posture across the fabric.
Zoning-analysis evaluates the zoning database, name-server, and
membership consistency. The two share evidence types but answer
different questions and have different safety surfaces.

## 3. Differences from Brocade zoning analyzer
- Inputs are NX-OS show-command outputs, not Brocade CLI sections.
- Adds VSAN scoping, FLOGI/FCNS reconciliation, and active vs full
  zoneset alignment as first-class hygiene checks.
- Forbidden-output set covers both NX-OS and Brocade syntax (drift
  defense). Brocade analyzer's forbidden set is Brocade-only.

## 4. Inputs
At least one of: `showZonesetActiveText`, `showZonesetText`,
`showZoneText`, `showDeviceAliasDatabaseText`. Strong evidence also
includes FLOGI/FCNS/VSAN/interface-brief. Cap: `rawTotalChars ≤ 200,000`.

## 5. Output contract
`cisco_mds_zoning_analysis@v1` — `zoningHealth` (posture, evidenceQuality,
activeFullAlignment, nameServerReconciliation, vsanCoverage), `findings`,
`risks`, `hygieneChecks`, `validationSteps`, `stopConditions`,
`assumptions`, `missingInputs`, `issues`, optional `criticReview`.

## 6. Safety boundary
Advisory only. No executable commands, no command descriptors, no
zoning changes, no `zoneset activate`, no `device-alias commit`, no
`configure terminal`, no copy-paste directives.

## 7. Governance and audit
Hardened cache pattern with `body.__governance` + `INTERNAL_KEYS = {governance, _governance, __governance}`. Every run writes a `toolchain_executions` row with `execution_kind=engine`,
`integration_id=toolchain-engine-cisco-mds-zoning-analyzer`,
descriptor-only artifacts and observed counts/flags.

## 8. Identifier redaction
Local scan + render-time redaction for: WWN, IPv4, email, FQDN, long
opaque token, serial-like, FCID (`0x[0-9a-f]{6}`), interface
(`fcN/M`), object-name leakage (`device-alias|alias|zone|zoneset|vsan
<name>`), quoted/backticked names.

## 9. Critic blockers
Blocks render (HTTP 422 `critic-blocked-render` when
`criticBlocksRender=true`) on NX-OS or Brocade command syntax,
copy-paste directives, identifier leakage, change recommendations
without change control, missing stop conditions on high-risk findings,
or claims of authoritativeness.

## 10. Registry & portfolio changes
Added `ciscoMdsZoningAnalyzer` descriptor to
`src/data/toolchainEngineRegistry.ts`. Portfolio: platform `cisco-mds`,
archetype `zoning-analysis`, lifecycleStage `built-beta`, status
`built`.

## 11. Planned override handling
Removed the `cisco-mds / zoning-analysis` planned override from
`src/data/contextFirstEngineCoverage.ts` to avoid double-counting.
The `cisco-to-brocade / zoning-analysis` planned override remains.

## 12. Demo behavior
`/toolchains/executions` exposes "Run Cisco MDS Zoning Analyzer Demo"
gated by `FEATURES.toolchainEngineDemoRunner && isPrivileged`. Synthetic
payload uses placeholders only (`DEMO_INITIATOR_ALIAS`,
`DEMO_TARGET_ALIAS`, `DEMO_ZONE_NAME`, `DEMO_ZONESET_NAME`,
`DEMO_VSAN_ID`, `DEMO_HOST_PWWN`, etc.) — no real WWNs/IPs.

## 13. Known limitations
- Heuristic counts (zone/zoneset/alias) are best-effort regexes; not a
  strict NX-OS parser.
- Agent collector metadata intentionally omitted in 6G-C; documented
  as future work pending validation of read-only Cisco MDS API
  operations.

## 14. Future
- Cross-vendor zoning reconciliation (Cisco→Brocade, planned).
- Live read-only collection hardening via existing API operations.
- Zoning scorecards.
- Migration worksheet export.
