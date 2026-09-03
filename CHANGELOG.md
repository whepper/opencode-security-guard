# Changelog

All notable changes. Format: Keep a Changelog; versioning: semantically ordered pre-releases.

## 0.3.3 — 2026-09-03

### Added — MCP per-tool overrides in `security-guard.config.json`

- **`mcpToolOverrides` key**: per-tool effect overrides (e.g.
  `"outline_update_document": { "effect": "allow" }`) merged into
  `policy.mcp.tools` at load time. Enables allowing specific write tools
  on trusted servers without prompts, bypassing the verb-class heuristic.
- **Example config template**: `plugin/security-guard.config.example.json`
  with all supported keys commented out.
- **Install guide docs**: new Configuration section in `docs/installation.md`
  covering all override keys with a quick-reference table.
- Documented the full `security-guard.config.json` override format in
  `docs/mcp.md`, with a cross-reference to the example template.

## 0.3.2 — 2026-09-02

### Fixed — false-positive reduction

- **`git commit -m` / `git tag -m` with `.env`-like message text no longer blocks.**
  A path-shaped token inside a commit or tag message (e.g. `discvault.env`) is
  narrative prose, not a file reference — `-m` values are now excluded from path
  classification.

## 0.3.1 — 2026-09-02

### Fixed — false-positive reduction

- **Multi-dot identifiers no longer trigger GG-KEY-002.** Bare strings with three
  or more dot-separated segments and no path separators (e.g.
  `discvault.backup.b2.key`) are naming conventions (BWS secrets, reverse-domain
  identifiers, Java packages), not file paths. `looksLikePath` and `formMatches`
  now both skip suffix matching for these. Single- and double-dot bare names
  (`server.key`, `my.backup.key`) and slashed paths remain fully protected.

## 0.3.0 — 2026-09-01

Circumvention-focused release: the classes an LLM could use to walk around
Layer 4 without ever touching a denied path. Every item below was confirmed as
a live bypass against the v0.2 engine before being fixed, and each now has a
corpus entry in `tests/bypass/cases.jsonc`.

### Fixed — bypass classes

- **Case-insensitive filesystems.** The path classifier compared case, while
  APFS/NTFS do not: `cat .ENV`, `cat ID_RSA`, `cat ~/.SSH/config` all read the
  secret unnoticed. Classification now folds case (documented cost: `FOO.PEM`
  on ext4 gets asked about). Closes `BYP-CAS-001..005`.
- **Shell quoting artifacts.** `cat .e''nv`, `cat .e"nv"` and `cat .e\nv` reach
  `.env` in the kernel but classified as different filenames. Tokens are now
  shell-normalized (quotes removed, backslash escapes collapsed) before
  classification. Closes `BYP-QTE-001..004`.
- **Re-entry wrappers.** `bash -c`, `sh -lc`, `eval`, `env CMD`, `sudo`, `nohup`,
  `time`, `watch`, `xargs`, `command` and friends hid the real verb, so printer,
  sender and environment-dump rules never fired (`bash -c 'echo $AWS_SECRET…'`
  was silent). Wrapper payloads are now analyzed as commands, recursively, with
  a depth bound. Closes `BYP-WRP-001..007`.
- **Deeper indirection.** Bash indirect expansion (`${!A}`) and `$IFS`-as-separator
  (`cat$IFS.env`) are resolved; multi-hop assignment chains are followed.
- **Git global flags.** `git -C repo show HEAD:.zshenv` hid the subcommand behind
  `-C`; subcommand detection now skips global flags and their values.
- **Script bodies at write time.** Writing `deploy.sh` containing `cat .env` was
  fully invisible, and executing it later references only a benign filename.
  Write-content scanning now raises a single approval at the one moment the body
  is visible (`GGW-CONTENT-001`, ask-only).
- **Symlink resolution for `~/` paths.** `realpathSync` does not expand tilde, so
  the symlink defense silently no-opped on the most common path form. Home
  expansion happens before resolution, and the read/edit permission channel now
  resolves too (it previously classified literals only).
- **MCP argument depth.** Protected references embedded inside longer argument
  strings (`"cd /srv/app && cat .env"`) are now caught by the same scan the
  shell engine uses, and MCP writes onto guard-owned files are blocked.
- **Alias definitions.** `alias rc='cat .zshenv'` was a *documented* blind spot;
  alias bodies are now analyzed at definition time (`unalias` and function
  bodies remain invisible — see limitations).

### Added — guard self-protection

- New `selfProtectPaths` policy class (`GG-SLF-*`): writes to
  `security-guard.config.json` and the heartbeat file are denied, writes to the
  plugin source and `policy.jsonc` require approval; **reads stay free** so the
  guard remains auditable. Mirrored as native Layer-1 rules (`SG-WRT-008..011`)
  so it holds even without the plugin loaded. Write-shaped tamper is caught
  across edit/write tools, `>`/`>>` redirections, `rm`, `tee`, `dd of=`,
  `cp`/`install`/`rsync` destinations, `mv` sources *and* destinations
  (removal-shaped tamper — `mv plugin.js /tmp/x` — found during post-
  implementation review and closed before release), and `sed -i`. Ordinary
  renames and in-place edits of non-guard files stay silent.
- `doctor.mjs` treats a non-`active` heartbeat as a **failure** (was a warning),
  verifies the recorded pid is a live process, and warns on stale heartbeats.
- `security-test.mjs` covers the new classes plus a self-protection false-positive
  check; heartbeat phase is now asserted, not just reported.
- Interpreter secret-variable detection (`GGE-VAR-020`) derives from
  `envVarNamePattern` instead of a hardcoded copy that could drift from policy.

### Changed

- Native rule count 69 → 73; test suite 163 → 217; adversarial corpus 93 → 137 cases (60 new positive/regression cases, 13 new benign false-positive cases).
- Transformer verb list extended (`base32`, `uuencode`, compressors); all
  backtick substitutions are extracted, not just the first pair.

### Still not guaranteed

Case-folding adds false positives, not coverage: interpreter string
obfuscation (`open(chr(46)+'env')`), stdin-delivered filenames, function bodies,
and arbitrary binaries remain out of reach for a one-pass command heuristic. No
network egress control ships. See [docs/limitations.md](docs/limitations.md).

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
