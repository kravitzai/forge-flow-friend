# Toolchains Phase 6H-G.3 — Public Docs Publishing for Phase Doc Links

## Purpose

The Engine Catalog renders a "Phase doc" link for each Context-First
engine, resolved by `src/lib/phaseDocLink.ts` against
`VITE_SOURCE_DOCS_BASE_URL`. For those links to actually resolve, the
referenced `docs/*.md` files have to exist at the configured base URL.

Phase 6H-G.3 wires up automated, whitelist-driven publication of those
docs into the existing public repo `kravitzai/forge-flow-friend`, so
links produced by the resolver land on real files instead of 404s.

## Why the existing public repo

- The repo is already the public surface for the connector agent and
  has a working private→public sync workflow
  (`.github/workflows/sync-connector-to-public.yml`) using a single PAT
  (`PUBLIC_REPO_PUSH_TOKEN`).
- Adding a second public repo, a second PAT, or GitHub Pages is more
  surface area for the same outcome.
- The resolver already produces `blob/main/...` links — these match
  GitHub source view exactly when the docs live under `docs/` in the
  same repo.

## Why manual docs commits are rejected

The connector export script wipes the public working tree (everything
except `.git`) before each sync. Anything committed manually to the
public repo's `docs/` folder would be deleted on the next connector
sync. Docs publication therefore has to be owned by the same pipeline.

## Whitelist-based publishing model

The set of public docs is explicit, reviewable, and enforced:

- **Whitelist file**: `scripts/public-docs-whitelist.txt`
  - One repo-relative `docs/<file>.md` path per line.
  - Comments (`#`) and blank lines are ignored.
  - Adding a doc to the public surface = add a line.
  - Removing a doc from the public surface = remove a line; the next
    sync deletes it from the public repo (mirror semantics).
- **Export script**: `scripts/export-public-docs.sh`
  - Reads the whitelist.
  - Fails loudly if any whitelisted file is missing from the private
    repo.
  - Resets `<public-repo>/docs/` and copies whitelisted files in.
  - Writes a generated `<public-repo>/docs/README.md` so direct readers
    know the folder is generated.
- **Drift test**: `src/data/__tests__/contextFirstRegistry.test.ts`
  - Asserts every `phaseDoc` value in `toolchainEngineRegistry.ts` that
    starts with `docs/` is present in the whitelist.
  - Asserts every whitelisted doc exists on disk.
  - Future engine descriptors that add a new `phaseDoc` will fail this
    test until the whitelist is updated.

## Sync workflow order

`.github/workflows/sync-connector-to-public.yml` runs two export steps
in this order on the same checkout:

1. `scripts/export-connector-public.sh` — wipes the public tree, writes
   connector-agent assets.
2. `scripts/export-public-docs.sh` — writes the curated `docs/` mirror
   into the freshly cleaned tree.

Then the workflow commits and pushes the combined diff.

The workflow path triggers were extended to include `docs/**`,
`scripts/export-public-docs.sh`, and `scripts/public-docs-whitelist.txt`
so doc-only changes also trigger a sync.

## Sanitization policy

The export script runs two pattern groups against every whitelisted
file before it writes anything. The exact list lives in
`scripts/export-public-docs.sh`.

- **Hard-fail patterns** (block publish): private key markers, the
  Supabase service role identifier, and common credential assignment
  forms (password / secret / token / api key style key=value pairs).
- **Soft-warn patterns** (logged, do not block initial sync): RFC1918
  IPv4 address ranges, WWN-like identifiers, the internal Lovable
  preview hostname, and `localhost`.

Initial syncs may legitimately mention example IPs / placeholder WWNs
in protocol explanations, so warns are not gated. A follow-up phase can
promote individual warns to hard-fails once the public corpus is
known-clean.

## Environment variable

After the first successful sync, set in production frontend env:

```
VITE_SOURCE_DOCS_BASE_URL=https://github.com/kravitzai/forge-flow-friend/blob/main
```

`.env.example` ships blank so unconfigured CI / dev builds hide the
link rather than render a placeholder URL.

## Validation checklist

1. `bash scripts/export-public-docs.sh "$(pwd)" /tmp/public-test`
   succeeds locally with 0 hard-fail hits.
2. `bunx vitest run src/data/__tests__/contextFirstRegistry.test.ts`
   passes — including the three new whitelist-drift assertions.
3. `bunx tsc --noEmit` clean.
4. After the next sync, `https://github.com/kravitzai/forge-flow-friend/tree/main/docs`
   lists the whitelisted files.
5. From the running app `/toolchains/engines/srdf-analyzer` Phase doc
   link resolves to
   `https://github.com/kravitzai/forge-flow-friend/blob/main/docs/toolchains-phase-6h-g-srdf-surface-promotion.md`
   without 404.

## Out of scope

- Resolver changes (already correct — Phase 6H-G.0 / 6H-G.2).
- Engine registry, output contracts, edge functions, governance,
  critic.
- CMS rows.
- A docs site / GitHub Pages.
- Publishing internal-only assessments (4d readiness, gap analysis,
  unreleased roadmap docs). Those stay private.
