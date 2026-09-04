# Changelog

All notable changes. Format: Keep a Changelog; versioning: semantically ordered pre-releases.

## 0.4.8 — operator content-write allowlist

0.4.7's write-path downgrade (ask → block) is correct for untrusted
locations but made the guard's own development impractical: test corpora
legitimately mention protected names, and every such write blocked. New
operator-controlled escape hatch, default off:

- **`contentWriteAllowlist`** in `security-guard.config.json`: path
  prefixes (directory or exact file) whose SCRIPT WRITES skip the content
  ask (`GGW-CONTENT-001/002`). Parsed by `applyGuardOverride`, matched
  case-insensitively with directory semantics. Operator-only by
  construction: the override file is agent-write-denied (`GG-SLF-001`),
  so allowlisting can never be performed by the agent it would weaken.
  Everything outside the allowlist still blocks; ask-tier path writes
  (`GG-RC-008`, `GG-SLF-004`) are NOT allowlistable — use the shell form,
  which prompts.

## 0.4.7 — live-verification fix: write-tool asks enforce as blocks

Live verification of the 0.4.4 carrier fix on beta-19086 showed the
write-time ask (`GGW-CONTENT-001`) never reached the user: a `package.json`
whose script dumps `.env` **wrote silently** (no prompt). Root cause, same
family as the 0.4.5/0.4.6 gaps: tool-hook asks are unenforced for path-kind
tools, and the permission channel sees only the file path — never the
written content — so content-based asks cannot reach it. The same mechanism
silently allowed write-tool calls to ask-tier paths (e.g. writing
`~/.zshrc` or `.envrc` directly).

### Fixed

- Write-tool ask verdicts (`norm.kind === "path"`, mode write) downgrade to
  **block** in the tool hook: script-body/carrier content asks
  (`GGW-CONTENT-001/002`) and ask-tier path writes (`GG-RC-008`,
  `GG-SLF-004`, …) now enforce instead of silently allowing. The direct
  shell form of the same write is cd-less and single-segment, so it still
  prompts through the permission channel — the legitimate approval path
  survives (e.g. `vim policy/policy.jsonc` asks and can be approved; the
  write-tool form blocks).
- Behavior change vs the documented design ("ask, never block, for script
  bodies"): on this beta the ask was unverifiable, and a prompt the platform
  may not deliver is worse than a block with a clear message. Agents writing
  legitimate scripts that mention `.env` paths should use sanitized names
  (`.env.example` stays excepted) — the block message says so.

## 0.4.6 — 2026-09-04 live-verification fix: cd-led commands skip the permission channel

Instrumented live investigation (temporary hash tap in the permission hook,
removed in this release) on `opencode2` `0.0.0-beta-19086`: the plugin's
`permission.evaluate` hook **fires for every shell command except those
whose leading verb is `cd`** — verified with SHA-256 resource matching
(`cd /tmp/rt2/.secrets && cat tok.txt`, brand-new path and text, produced
no hook event at all while every adjacent command paired correctly with its
own command text). Consequence: every ask-tier rule on a cd-led command
(`cd .secrets && cat tokens.txt` — the 2026-09-04d finding) was silently
unenforceable; deny-tier is unaffected because the tool hook always sees
the true command text.

### Fixed

- Shell tool-hook asks now downgrade to **block** when the command is led
  by `cd` (same mechanism as the `GGH-STDIN-001` downgrade). Where the
  permission channel cannot see the command, an ask is unenforceable and
  block is the only tier that means anything; the direct form of the same
  read still prompts, so the legitimate approval path survives.
- Also confirmed live on 0.4.5: `echo id | zsh -i` now **blocks**
  (`GGH-STDIN-001`); saved shell approvals did not exist — the earlier
  cd-shape silences were the missing events, not approvals. A project-
  scoped saved approval **`read` / `*`** was found in the V2 permission
  store, which is why native read-tier asks never surface — see the
  approval-fatigue warning in README (review saved approvals periodically).

## 0.4.5 — 2026-09-04 live-verification fix: piped-shell asks enforce as blocks

Live verification of 0.4.4 on `opencode2` `0.0.0-beta-19086` (dummy data,
guard active in the probing session) confirmed every block-tier fix and the
ask channel for single-segment commands — but exposed that the permission
channel does not carry **pipe context** on this beta: `echo id | zsh -i`
(fresh command text, no saved approval) executed silently, although the
engine computed `ask GGH-STDIN-001` on the full command. Tool-hook asks are
not enforced for shell tools by design, so the ask degraded to a silent
allow exactly for pipe-dependent rules.

### Fixed

- `GGH-STDIN-001` now downgrades to **block** in the tool hook for shell
  calls (same mechanism as the grep/glob ask downgrade). `GGH-STDIN-001` is
  the only pipe-dependent rule; single-segment asks (`GGD-DEF-002`
  BASH_ENV, `GGR-OTHER-002`, credential CLIs, write-time carriers)
  demonstrably prompt via the permission channel and stay ask.
- Verified live on 0.4.4 (blocked as expected): `cp .env keyfile && cat
  keyfile` (bare-name copy tracking), `cp -r ~/.ssh /tmp/s && cat
  /tmp/s/config` and `ln -s ~/.ssh cfg && cat cfg/config` (dir identity),
  `jq -n 'env.FAKE_RT_TOKEN'` and `awk 'BEGIN{system("printenv …")}'`
  (string-level env), `su -c 'printenv …'` (payload extraction). Ask-tier
  prompts surfaced live for `BASH_ENV` and `bash /tmp/cmds` (user declined
  both). Engine-`ask` shapes matching **saved approvals** (exact command
  text approved "always" earlier in the session) skip the prompt by design —
  perturb the command text when re-testing.

## 0.4.4 — 2026-09-04 fourth evasion set (verified engine-level, live restart pending)

Fourth adversarial re-probe found eight classes silent on 0.4.3; four of
them were also verified live-silent (dummy data only). All flipped with
must-stay-silent negatives; `npm test` 413 pass, `npm run check` clean.

### Fixed

- **Interactive-shell stdin injection (`GGH-STDIN-001`).** `echo printenv |
  zsh -i`, `printf … | bash -i`, `… | su`, `… | script -q /dev/null`,
  `printf … | sudo bash` (piped context propagates through wrapper
  recursion), and unknown-carrier operands (`bash /tmp/cmds`) now ask. The
  payload carries no token, so the pipe itself is the gate — same class as
  the heredoc rule `GGH-DOC-001`. Bonus bug fixed: `su -c 'printenv X'` /
  `runuser -c '…'` payloads were swallowed as flag values and silently ran.
- **String-level environment access (`GGE-VAR-021`, extended accessor).**
  `jq -n env` / `jq -rn '$ENV["X"]'` (jq/yq are now interpreter verbs),
  perl bare `%ENV`, and `printenv`/`env` inside interpreter exec strings
  (`awk 'BEGIN{system("printenv X")}'`) dump values no verb-level rule
  reached. Path mentions inside exec strings were already blocked and
  remain the boundary: `awk 'BEGIN{system("cat .env")}'` blocks.
- **Guard self-protection writers (GG-SLF via editors/output flags).**
  `vim`/`nvim`/`ed`/`patch`/`code`/`emacs` on guard-owned paths, in-place
  `perl -i`/`ruby -i`/`awk -i`, sender output flags (`curl -o`, `wget -O`,
  `--output`, `sort -o`), and remote-copy destinations (`scp host:cfg
  security-guard.config.json`) now block/ask like redirections did.
- **File-identity tracking (E2 completion).** Copy destinations no longer
  need to look path-like (`cp .env keyfile && cat keyfile` blocks), and
  directory sources carry dir semantics: members of a copied or symlinked
  protected directory inherit its tier (`cp -r ~/.ssh /tmp/s && cat
  /tmp/s/config`), same-command and cross-call (session store + read/grep
  tools + permission channel). Same-command `rm` of a dest clears
  pre-execution so `rm keyfile && cat keyfile` does not over-block.
- **Script carriers (`GGW-CONTENT`).** `package.json` scripts, Makefiles,
  justfiles, Taskfiles, Dockerfiles, and `.github/workflows` YAML now get
  write-time body inspection; `write package.json → npm run dump` asked at
  write instead of executing silently. `.envrc` joined the script-body
  extension list and got native/guard ask rules (`SG-RC-008`/`GG-RC-008`).
- **Secret-retrieval CLIs (`GGE-CLI-006..011`).** `aws secretsmanager
  get-secret-value`, `gcloud secrets versions access`, `kubectl get
  secret … [-o yaml]`, `az keyvault secret show`, `vault kv get`, `docker
  exec … env` now ask, matching the gated `gh auth token` / `git credential
  fill` shapes. Listing forms (`kubectl get secrets`, `vault kv list`,
  `gcloud secrets list`, `aws secretsmanager list-secrets`) stay silent.
- **Ask-tier unknown verbs (`GGR-OTHER-002`).** `tr < ~/.zshenv`,
  `while read … < ~/.zshenv`, `fold ~/.zshenv`, and `cd .secrets && cat
  tokens.txt` now ask like `awk 1 ~/.zshenv` already did. Metadata verbs
  (`ls`/`stat`/`file`/`du`/`wc`/`find`/`git`) and printers stay silent.
- **Glob-tool discovery (`GGR-GLOB-001+GLOB`).** `**/*rsa`, `**/?env`,
  `**/*env`, `**/*.zsh*` ask via exemplar matching instead of passing after
  wildcard stripping; `**/*.log`/`**/id_rsa.pub` stay silent.
- **Precision fixes.** `formMatches` now honors `withinDir` on `basename`
  forms: bare `credentials` (GG-CLOUD-007) and bare `health.json` (GG-SLF-002)
  outside their directories no longer false-positive. `xargs` payload
  construction keeps `sh -c '…'` flags instead of eating them.
- **`BASH_ENV` gate (`GGD-DEF-002`).** `BASH_ENV=/tmp/rc bash -c true` asks;
  `ENV=prod make build` stays silent.

### Live verification note

Engine-level probes: `analyzeCommand`/`decideToolCall`/`decidePermissionEvent`
with dummy data (`FAKE_RT_TOKEN`, `/tmp/rt/` dummy tree — never real paths).
The four original live-silent confirmations (piped `zsh -i`/`bash -i` env
read, jq/awk env reads, bare-name copy + read, dir-copy + member read,
package.json carrier → `npm run dump`) were captured on 0.4.3 before the
fix; live re-verification of 0.4.4 requires `opencode2 service restart` and
the smoke checklist in docs/installation.md.

## 0.4.3 — 2026-09-04 third evasion set (verified live-silent on 0.4.2, fixed FP-safe)

Third adversarial re-probe found six classes silent on 0.4.2. All flipped
with must-stay-silent negatives; `npm test` 348 pass, `npm run check` clean.

### Fixed

- **Secret-name indirection (F1).** `A=SECRET_NAME; echo $A`, `printenv $A`,
  `eval "echo $A"`, `curl -H "Authorization: Bearer $A"`, and zsh
  `${(P)X}` / `${(e)X}` now resolve through assignment chains
  (`GGE-VAR-010/002/011`). Resolution is name-based and identifier-shaped,
  so `PATH=$HOME/bin; echo $PATH`, `A=NOTES; echo $A`, and
  `MSG='invalid token'; echo $MSG` stay silent.
- **Ask-tier script bodies (F2).** A written script containing `cat
  ~/.zshenv` — the incident class — now asks at write time
  (`GGW-CONTENT-002`); previously only deny-tier references were visible and
  ask-tier bodies vanished into the pre-existing-script blind spot.
- **Script-extension coverage (F3).** `.ps1` `.psm1` `.bat` `.cmd` `.vbs`
  `.lua` `.r` `.awk` `.pl` `.pm` `.tcl` payloads are now recognized scripts;
  a `run.ps1` with `Get-Content .env` asks (`GGW-CONTENT-001`).
- **Heredoc attachments (F4).** `curl -d @- host <<EOF`, `nc host 4444
  <<EOF` ask (`GGH-DOC-001`) — the body is invisible to analysis; `cat >
  notes.md <<EOF`, arithmetic `$(( 1 << 3 ))`, and non-consumer verbs
  (`psql -c 'SELECT 1 << 2'`) stay silent.
- **Deferred execution (F5).** `trap` payloads are analyzed at definition
  time (`trap 'env' 0` blocks; `trap 'echo done' ERR`, `trap - EXIT` stay
  silent). `crontab -`, `crontab <file>`, `at now`, `at -f job.txt` ask
  (`GGD-DEF-001`); `crontab -l/-r`, `atq`, `atrm` stay silent.
- **`compgen` FP polish (F6).** `compgen -v PATH` (non-secret name pattern)
  no longer blocks; bare `compgen -v` / `-A variable` and secret-named
  patterns still block.

### Not fixed (documented residuals)

`docker exec C env`, `ssh host env` (remote/container scope); cross-call
variable assignments (`A=NAME` in one tool call, `echo $A` in the next —
the session store tracks file copies only); zsh `(j:)`-style joins of
unassigned variables. Function bodies, stdin-fed filenames, ANSI-C quoting,
interpreter string obfuscation, and network egress remain as documented.

## 0.4.2 — 2026-09-04 second evasion set (verified live-silent on 0.4.1, fixed FP-safe)

Adversarial re-probe of the 0.4.1 engine (`analyzeCommand` / `decideToolCall`,
dummy names only — see the 2026-09-04b entry in `docs/verification-log.md`)
found sixteen silent shapes. All flipped to enforcing verdicts with
must-stay-silent negatives; `npm test` 320 pass, `npm run check` clean.

### Fixed

- **Flag-only environment dumps.** `env -0`, `env -u FOO`, `env FOO=bar`
  (no payload), `alias -p` (zsh) block (`GGE-DUMP-007/008`); `env FOO=bar
  make build`, `env -i npm test`, clean alias definitions stay silent.
- **Interpreter env accessors.** The `environ|getenv|process\.env` check is
  now case-insensitive and covers ruby `ENV[...]`/`ENV.fetch`, perl
  `$ENV{}`/`%ENV`, awk `ENVIRON[..]`, php `$_ENV[..]`, deno `Deno.env`,
  AppleScript `system attribute` (`GGE-VAR-020`; whole-env forms ask via
  `GGE-DUMP-010`). Clean awk/ruby code stays silent.
- **Process substitution bodies.** `<( )` / `>( )` are extracted like `$()`
  and backticks: `cat <(env)`, `curl -d @- < <(env)` block; clean
  `diff <(sort a) <(sort b)` stays silent.
- **Sender glob operands.** `curl --data @.e*`, `-F upload=@.e*`,
  `--data=@.e*`, `--data @.[e]nv` ask (`GGR-GLOB-001`): the `@`/`flag=@`
  prefix no longer defeats exemplar matching.
- **git grep.** Added to the content subcommands; unscoped `git grep
  PATTERN` asks (`GGG-HIST-001`), scoped pathspecs (`git grep TODO src/`)
  stay silent. `git stash show -p` asks; `git stash list`/plain
  `stash show` stay silent. `git credential fill` asks (`GGG-CRED-001`).
- **Backup/autosave names.** `.env~`, `#.env#`, `id_rsa~` classify as their
  originals (read-tool and MCP shapes were silent at both layers where the
  native dialect could not match `~`/`#`); `.env.example~` stays silent.
- **Tool-adapter gaps.** Glob-tool bracket classes normalize before
  classification (`[.]env`, `[.]e[n]v` ask; ranges collapse to wildcards);
  the grep tool asks on broad/empty search roots (`GGR-SEARCH-002`).
- **Credential-printing CLIs.** macOS `security find-*-password -w/-g`
  blocks, `security dump-keychain` asks (`GGS-KEY-*`); `gh auth token`,
  `gcloud auth print-*-token`, `aws ecr get-login-password`,
  `npm config get <secret-key>`, `launchctl getenv <secret-name>` ask
  (`GGE-CLI-001..005`); metadata-only / non-secret variants stay silent.
- **Policy coverage.** New: `/etc/environment` deny (engine `GG-ENV-004`,
  native `SG-ENV-005`; the old BYP-DIR-004 "native handles system files"
  note was wrong — no such rule existed), `~/.zsh_history` / `~/.bash_history`
  ask (`GG-HIS-*`, `SG-HIS-*`), `~/.secrets/` ask (`GG-SEC-001`,
  `SG-SEC-001`), native `*.env~` deny (`SG-ENV-003`). Native rules 75 → 81.

### Not fixed (documented residuals)

`docker exec C env` and `ssh host env` (remote/container environment) and
gcloud legacy-credential cookies outside `~/.config/gcloud` remain
filename/class-coverage gaps, not engine bugs — the threat model scopes
remote hosts and containers out. Live smoke on a running `opencode2` build
still pending (see `docs/verification-log.md`).

## 0.4.1 — 2026-09-04 evasion set (E1–E10, FP-safe)

Implements `docs/evasion-2026-09-04.md`. Engine-level verified (`npm test`
266 pass, `npm run check` clean); live smoke on a running `opencode2` build
still pending before user-facing claims are repeated.

### Fixed — bypass classes (ask-where-uncertain, block-where-certain)

- **Glob/pattern expansion (E1).** `cat .e*`, `cat .[e]nv`, `cat *key`,
  `for f in .e*; do cat $f; done`, `find -name '.e*' …` now `ask GGR-GLOB-001`
  via exemplar matching; `*.log`/`*.js` stay silent (`NEG-FP-023`).
- **Cross-call temp copies (E2).** Bounded session store (32-entry FIFO,
  `createCopyProvenanceStore` + `detectCopyTracks`, populated post-execution,
  cleared on `rm`/overwrite); consumers mirror single-command verdicts
  (`GGN-SEND-001`/`GGR-READ-001`, `GGR-COPY-001` for read/grep tools).
- **Directory-operand archives (E3).** Broad-root creation asks
  (`GGA-DIR-001`); extraction and `dist/` stay silent.
- **Bare history / full-tree git (E4).** Patch-displaying bare access asks
  (`GGG-HIST-001`); `--stat`/`--oneline`/`--` stay silent.
- **Broad-root recursive search (E5).** Narrow `ask GGR-SEARCH-001`;
  scoped `src/`/`docs/` stays silent.
- **procfs environment (E6).** `GG-PROC-001` deny (`environ`) + native
  `*proc/*environ*` deny, `GG-PROC-002` ask (`cmdline`) + native ask;
  `docs/environ.md` stays silent by `/proc/` scoping. Native rules 73 → 75.
- **Bare dumps (E7).** `export`/`declare`/`readonly`/`local` bare and
  flag-only forms block (`GGE-DUMP-004/005`); `compgen -e/-v/-A variable`
  blocks (`GGE-DUMP-006`); assignments and `compgen -c` stay silent.
- **Parameter expansion (E8).** `${VAR:-x}`/`${VAR:+x}`/`${#VAR}` etc.
  resolve to the secret name (`GGE-VAR`); `${PATH:-x}` stays silent.
- **Ask-tier viewers (E9).** `bat`/`batcat`/`delta`/`tac`/`rev` read
  (`bat ~/.zshenv` asks); `ls`/`stat` stay silent.
- **Glob discovery (E10).** `glob **/.zshenv` asks; `**/*.log` stays silent.

## 0.4.0 — 2026-09-03

### Changed — project renamed to Security Guard for OpenCode

The repository has been renamed from `opencode-security-guard` to `security-guard-for-opencode` and the display name from "OpenCode Security Guard" to "**Security Guard for OpenCode**". This applies to:

- **Runtime data directory**: `~/.local/share/opencode-security-guard/` → `~/.local/share/security-guard-for-opencode/`
- **npm package name**: `opencode-security-guard` → `security-guard-for-opencode`
- **Documentation**: all headers, descriptions, and path references across README, SECURITY.md, docs, scripts, and tests
- **Native permission rules**: `*opencode-security-guard/health.json` → `*security-guard-for-opencode/health.json`
- **Guard self-protection**: `withinDir: "opencode-security-guard"` → `withinDir: "security-guard-for-opencode"`

### Added — automated migration path

- `scripts/install.mjs` now auto-migrates the old runtime data directory to the new name on install (rename, not copy).
- `scripts/doctor.mjs` warns if the old data directory is found (either as a leftover alongside the new one, or as the only location).

### Migration from v0.3.x

Existing installations upgrading to v0.4.0 need two steps:

1. **Re-run the installer** so the plugin and config are replaced with the new paths: `node scripts/install.mjs --scope project --merge --yes` (or `--scope global`).
2. **Restart the service**: `opencode2 service restart && node scripts/doctor.mjs --live`

The installer handles the data directory migration automatically. If you prefer to do it manually: `mv ~/.local/share/opencode-security-guard ~/.local/share/security-guard-for-opencode`.

See `docs/installation.md#upgrading-from-v03x-to-v040` for details.

---

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
