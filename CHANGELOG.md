# Changelog

All notable changes. Format: Keep a Changelog; versioning: semantically ordered pre-releases.

## Unreleased

### Added

- Live LLM-session enforcement checklist results (docs/verification-log.md) — pending environment access.

## 0.1.0-rc.1 — 2026-08-25

Complete rebuild of the initial scaffold into a working release candidate targeting **OpenCode V2 only**.

### Added

- Single-source policy (`policy/policy.jsonc`): stable rule IDs, rationales, baseline/strict profiles.
- Generated OpenCode V2 configuration: 69-rule ordered `permissions` array (broad allows → denies → asks → safe exceptions), 27 watcher ignores, honest `share` marker.
- Real V2 plugin (`plugin/security-guard.js`): zero dependencies, verified object-export API, pure decision engine (path classification, semantic shell analysis, env-dump/secret-variable detection, indirection + temp-copy provenance), value-free diagnostics, setup heartbeat for liveness monitoring.
- Adversarial regression corpus (65 cases: 43 block / 6 ask / 16 negatives) incl. incident replay; 101 automated tests total.
- Safe installer with backups, refusal-on-conflict, merge mode, printed rollback.
- Doctor (`scripts/doctor.mjs --live`) verifying binary/version, plugin integrity, heartbeat liveness, config invariants, log load records.
- Dependency-free secret scanner and repository validator.
- CI: least-privilege workflows with SHA-pinned actions (tests, validation, secret scan, CodeQL); Dependabot.
- Documentation set: architecture, threat model, limitations, MCP risk area, installation/rollback, verification log; full Apache-2.0 license text.

### Removed

- Placeholder plugin that matched neither the V1 nor V2 API (could be mistaken for working enforcement).

### Fixed

- License file contained only the Apache-2.0 preamble, not the license.

### Verified against opencode2 `0.0.0-beta-18219`

Plugin object-export requirement, autoload directories, fail-open load behavior, config acceptance via `debug config`, installer→heartbeat→doctor lifecycle end-to-end. See docs/verification-log.md for scope and open items.
