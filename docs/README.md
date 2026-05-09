# Public Phase Docs

This folder is generated from the private ForgeAI / FilterREX source
repo by `scripts/export-public-docs.sh` and is published from a
curated whitelist (`scripts/public-docs-whitelist.txt`).

Do not edit these files directly in the public repo — changes here
are overwritten on the next sync. To update a doc, edit it in the
private repo and let the
`Sync Connector to Public Repo` workflow republish it.

The phase-doc links surfaced in the FilterREX engine catalog resolve
through `VITE_SOURCE_DOCS_BASE_URL` to:

```
https://github.com/kravitzai/forge-flow-friend/blob/main/docs/<file>.md
```
