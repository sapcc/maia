<!--
SPDX-FileCopyrightText: 2024 SAP SE or an SAP affiliate company
SPDX-License-Identifier: Apache-2.0
-->

# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- Add `GET /api/v1/whoami` endpoint returning caller identity (user, project, domain, roles)
- Add `GET /api/v1/projects` endpoint returning caller's scoped project list
- Add modern React UI (Prometheus mantine-ui fork) now always served at `/ui/`
- Add go:embed-based asset embedding for the new UI, replacing go-bindata
- Add sentinel label value for global metric visibility (`maia.label_value_for_global_visibility` config option, disabled by default)

### Changed

- The web UI now resolves its API calls relative to the path it is served from, so Maia's UI works both at its own address and when served behind a reverse proxy under a sub-path (no change when served at its own root)
- `/{domain}/graph` is now a login-only stub: authenticates via all supported methods (cookie, Basic Auth, application credentials) then redirects to `/ui/query`
- Root path `/` always redirects to `/ui/query`

### Removed

- Removed: Legacy jQuery/Bootstrap 3 expression browser UI (`web/templates/`, `web/static/`)
- Removed: go-bindata dependency; assets now embedded via Go `embed.FS`
- Removed: `maia.new_ui_enabled` feature flag — the new React UI is now always on

### Security

- Prevent cross-tenant metric access: strip client-supplied `X-Project-Id`/`X-Domain-Id` scope headers on authentication so scope is always derived from the validated token
- Verify project membership before honoring the `project_id` query parameter, so an authenticated user cannot read another tenant's metrics by supplying a foreign project ID
- Bump `github.com/prometheus/prometheus` to v0.311.3 (CVE-2026-42151, CVE-2026-42154, CVE-2026-44903)
- Enforce upstream host equality on Prometheus storage requests as defense-in-depth against SSRF (CodeQL `go/request-forgery`)
