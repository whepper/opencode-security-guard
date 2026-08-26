# Changelog

All notable changes. Format: Keep a Changelog; versioning: semantically ordered pre-releases.

## Unreleased

Nothing yet.

## 0.2.0 — 2026-08-26

MCP connector security, external-testing hardening, and the tooling that lets users verify their own installations. Supersedes `v0.2.0-rc.1` (identical scope plus the hardening items below). Targets **OpenCode V2 (`opencode2`)**; verified against betas `0.0.0-beta-18219`, `0.0.0-beta-18230`, and `0.0.0-beta-18269`.

### Added — MCP connector security (Layer 4b)

- Native per-tool permission addressability documented and mirrored: explicit policy denies are emitted as native `<server>_<tool>` rules so they hold even without the plugin.
- MCP trust taxonomy — trusted / restricted / untrusted / blocked / unlisted-server (fail-conservative) — with required rationale for restrictive tiers. Transport is explicitly NOT a trust signal.
- Token-based tool classification into semantic classes (read-only, local-data, external-write, network, credential-related, destructive, unknown) with false-positive discipline: `tokenize_dataset` is not a credential hit; ambiguous verbs never guess.
- Argument-level rules: protected-path tiers reuse the filesystem classifier (incl. resolved-target checks); secret-named value shapes (`KEY=value`, bare names) blocked.
- Dual-channel enforcement: `permission.evaluate` escalation (primary; prompts interactively, auto-rejects headlessly) plus `execute.before` hard blocks (backstop).
- Doctor reports configured MCP servers with transport + trust posture and warns on orphaned MCP rules.

### Fixed

- Symlink/benign-alias bypass (`BYP-FS-LINK`): a symlink like `mynotes.txt → .env` previously passed every layer because classification saw only the literal name. Resolved targets are now reclassified across shell tokens, read/edit paths, and MCP arguments, escalating to the worst tier. Discovered and fixed during pre-release external-testing hardening on this branch; **never present in any tagged release**, so no CVE is filed.
- Unlisted-server ask skip: when MCP inventory discovery returned no servers, approval-tier decisions for unlisted tools were silently skipped. Underscored non-native actions are now classified conservatively without inventory. Found via live demo; regression-tested.

### Added — external-testing support

- `scripts/security-test.mjs`: offline self-test of an installed plugin (environment header, adversarial spot-checks, false-positive spot-checks, MCP tier check) producing a pasteable bug-report summary.
- `scripts/uninstall.mjs`: safe removal preserving drifted configs; lists install-time backups.
- README "Security guarantees & non-guarantees" section: every protected claim traced to executed tests; explicit non-guarantee list.
- SECURITY.md bypass-report template and private-reporting workflow.
- Adapter integration tests through real `setup()` (hook registration, heartbeat, deny/ask paths, real-filesystem symlink case).

### Changed

- Compatibility metadata lists all verified builds; doctor and installer warn on untested runtimes.
- False-positive corpus expanded (+10 cases across token/secret/credential/password/key/auth/config/certificate classes; zero FPs).
- Provenance experiment shipped opt-in (`mcp.provenance.enabled`, default off): session-scoped marker tripwire for cross-tool relay of approval-gated content. Explicitly a detection aid — paraphrase, re-encoding, chunking, and summarization evade it (test-enforced).

### Verified against OpenCode V2 betas

`0.0.0-beta-18219`, `0.0.0-beta-18230`, `0.0.0-beta-18269`: config acceptance, plugin lifecycle (load → heartbeat → doctor), live enforcement demos (native read deny `GG-ENV-001`; shell block `GGR-READ-001` with heartbeat attribution; sanitized-example allow; grep-path block `GG-ENV-001+GREP`; MCP ask auto-rejection; MCP argument-rule block `MCP-ARG-SEC-003`). Full method and scope: docs/verification-log.md.

### Security posture statement

This release reduces likelihood and adds observable enforcement points. It does not prevent data exfiltration, is not a sandbox or DLP system, does not control network egress, and cannot protect against compromised hosts, compromised OpenCode binaries, malicious plugins, or secrets already sent to a provider. All fixtures use dummy data only; no real credentials were used or exposed during development or verification.

---

## 0.2.0-rc.1 — 2026-08-25

Release candidate containing the initial MCP security work later finalized in 0.2.0. See the git history for its exact contents; superseded by 0.2.0 above.

## 0.1.0-rc.1 — 2026-08-25

Initial hardening baseline: single-source policy (`policy/policy.jsonc`), generated OpenCode V2 configuration, execution-time guard plugin, adversarial bypass corpus, installer/doctor, CI with pinned actions, documentation set, Apache-2.0 licensing.
