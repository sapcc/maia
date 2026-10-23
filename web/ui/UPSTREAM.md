<!--
SPDX-FileCopyrightText: 2025 SAP SE or an SAP affiliate company
SPDX-License-Identifier: Apache-2.0
-->

# Vendored UI — Upstream Provenance

The Maia React UI under `web/ui/` is a **hard fork** of the Prometheus
`mantine-ui` web frontend, with Maia-specific patches applied inline. It is
**not** an npm/Go dependency — it is copied source. Renovate and `go.mod` do
**not** track it. Keeping it current is a manual, tooling-assisted process
described below.

## Pinned upstream

<!-- renovate: the line below is watched by a customManager in renovate.json5.
     Keep the exact `UPSTREAM_VERSION=vX.Y.Z` format on its own line. -->
```
UPSTREAM_REPO=https://github.com/prometheus/prometheus
UPSTREAM_VERSION=v3.15.1
UPSTREAM_SHA=2a20609389fa1f0221e4fa8f6c7e1e4817b5c284
SYNCED_ON=2025-08-13
```

## What was forked

Copied verbatim from upstream at the pinned tag, then patched:

- `web/ui/mantine-ui/**` — the React SPA (`@prometheus-io/mantine-ui`)
- `web/ui/module/**` — `@prometheus-io/lezer-promql`, `@prometheus-io/codemirror-promql`
- `web/ui/package.json`, `pnpm-workspace.yaml`, `pnpm-lock.yaml`, `build_ui.sh`

Upstream's `react-app/` (the old 2.x UI) was **not** forked. Maia ships a
single React UI; the old-UI feature flag from upstream does not apply.

## Maia patch points

These are the areas modified from upstream. When re-syncing, expect merge
conflicts here and re-apply intent (see `git log` on `web/ui/mantine-ui/` for
the authoritative list):

| Area | Files (approx.) | Intent |
|------|-----------------|--------|
| Auth / identity | `src/context/MaiaProjectContext.tsx`, `src/lib/maiaFetch.ts` | whoami/projects fetch, 401→`/{domain}/graph` redirect, `credentials: same-origin`, JS-readable domain cookie |
| Scope injection | `src/api/api.ts` (`useAPIQuery`) | inject `project_id` from the current project into every API call |
| Base path | `src/state/settingsSlice.ts` (`getPathPrefix`), `src/App.tsx` | app served under `/ui/`; absolute `/api/v1` calls |
| Removed surfaces | `src/App.tsx`, routing | Alerts / Rules / Explain(parse_query) / notifications SSE removed or redirected to `/query` |
| Branding | templates, wordmark, "Try it →" banner | Maia branding; classic-UI banner points here |

Server-side glue that depends on this fork (not part of the fork itself):
`pkg/api/server.go` (`serveReactApp`, `/ui/*` routes), `web/ui/assets_embed.go`,
`web/ui/ui.go`, `pkg/api/v1api.go` (`/whoami`, `/projects`, `/metadata`).

## How to update

1. Run `web/ui/sync-mantine-ui.sh <new-tag>` — fetches the new upstream tag and
   reports the upstream diff since the pinned baseline for the forked paths.
2. Re-apply the Maia patch points above onto the new upstream (three-way merge;
   the script leaves the fetched upstream tree in a temp dir for reference).
3. Update the pinned block above (version + SHA + date).
4. `make generate && make check` — rebuild assets and run the full suite.
5. Commit with the upstream version in the message.

## Why this is tooling-assisted, not automated

The Maia patches are interleaved with upstream code in the same files, so an
automated merge is unsafe. The sync script's job is to make the human merge
**fast and reviewable** (surface the exact upstream delta), not to merge for you.
CVE exposure in the fork's JS dependency tree is surfaced separately by the
weekly `osv-scan` workflow (see `.github/workflows/`).
