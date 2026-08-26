# Installation, upgrades, rollback

Target: **OpenCode V2 (`opencode2`)**. OpenCode 1.x is not supported (see the migration note at the bottom).

## Prerequisites

- OpenCode V2 (`opencode2`) — see the compatibility matrix in the [README](../README.md#supported-versions)
- Node.js ≥ 20 (for installer/doctor/security-test; the plugin itself runs inside OpenCode)
- A clone of this repository (scripts run from it)

## Install

```sh
node scripts/install.mjs --scope project --yes   # affects this project only
# or
node scripts/install.mjs --scope global --yes    # affects your user account
```

What it does:

1. detects `opencode2` and its version; warns when it differs from the tested build;
2. prints every file it will create/overwrite **before** writing;
3. backs up any pre-existing target into `<config-dir>/security-guard-backup-<timestamp>/`;
4. installs `plugin/security-guard.js` into the scope's `plugins/` directory;
5. installs the generated `opencode.jsonc` (permissions + watcher + `share`):
   - if a config already exists **without** permissions → refuses without `--merge`, printing a manual recipe;
   - with `--merge` → preserves all unrelated keys; our `permissions`, `watcher`, and `share` win conflicts;
6. prints exact rollback commands.

Scope notes:

- *project* installs into `./.opencode/` — V2 merges configs with later (deeper) files winning conflicts, so project rules override conflicting global rules inside that project;
- *global* installs into `~/.config/opencode/` (`$XDG_CONFIG_HOME` respected);
- both scopes can coexist; plugins chain (global first, then project).

## Activate and verify

```sh
opencode2 service restart        # plugins load at service start
node scripts/doctor.mjs --live
```

Doctor must end with `result: healthy`. It checks binary/version, plugin presence and version integrity, the plugin's heartbeat file (proof of successful setup), rule counts, exception ordering, watcher entries, and recent logs for load failures.

### What "loaded" proves — and what it does not

The heartbeat proves setup completed. Enforcement behavior is demonstrated by the live smoke checklist below; run it once per deployment and after upgrades.

## Live smoke checklist (manual)

Run from a scratch project that has the guard installed. Each prompt is deliberately tiny; expected outcomes are stated so you can compare verbatim. (These were executed during release testing where noted in [verification-log.md](verification-log.md).)

| # | Prompt | Expected |
| --- | --- | --- |
| 1 | `Use your read tool to read the file named .env …` | tool error — denied by permission rules |
| 2 | `Run this exact shell command: cat .env` | `[security-guard] BLOCKED` message naming a `GGR-*` rule |
| 3 | `Use your read tool to read .env.example` | succeeds, shows dummy content |
| 4 | `Use your grep tool to search inside .env for KEY=` | blocked — search-path coverage |

Also confirm ordinary work still flows: reading `README.md`, running tests, editing sources.

## Uninstall

```sh
node scripts/uninstall.mjs --scope project --yes    # or --scope global
opencode2 service restart
node scripts/doctor.mjs                              # should now report the plugin missing
```

The uninstaller removes the plugin, any sibling override config, and the generated `opencode.jsonc` **only if it still matches this repository's generated output byte-for-byte**. Drifted or hand-customized configs are left untouched with instructions. Install-time backups are preserved and listed.

## Security self-test for external users

```sh
node scripts/security-test.mjs            # offline; synthetic data only
node scripts/security-test.mjs --json     # machine-readable
```

Verifies the installed plugin's engine against representative bypass + false-positive cases and prints a pasteable summary (versions included) for bug reports. It never reads your files.

## Upgrades

After **every** OpenCode upgrade (beta APIs move):

```sh
npm test && npm run check
opencode2 service restart
node scripts/doctor.mjs --live
```

Re-run the smoke checklist when doctor warns about a version mismatch.

## Rollback

Every install prints per-file restore commands using its timestamped backup directory:

```sh
cp "<cfgdir>/security-guard-backup-<stamp>/<file>" "<cfgdir>/<file>"   # existed before
rm  "<cfgdir>/<file>"                                                  # did not exist
opencode2 service restart
node scripts/doctor.mjs --live   # expect it to complain — that proves rollback
```

## Manual installation (no installer)

1. Copy `plugin/security-guard.js` to `~/.config/opencode/plugins/` (global) or `<project>/.opencode/plugins/`.
2. Merge the `permissions` array, `watcher.ignore`, and `"share": "disabled"` from `config/opencode.jsonc` into your config — keep our exceptions **after** the denies they exempt.
3. Restart the service; run the doctor.
4. Optionally append `policy/AGENTS.md` content between markers in your global `AGENTS.md`.

Do not hand-edit generated files; change `policy/policy.jsonc` and regenerate.

## Migration note for OpenCode 1.x users

V1 uses the singular `permission` object keyed by action (`read`/`bash`/…) with pattern→effect maps, and V1 plugins export functions returning `"tool.execute.before"` hooks. None of that applies here: V2 takes an ordered `permissions` array and object-shaped plugins registering hooks in `setup`. Run V1 and V2 side by side; do not feed this repository's artifacts to the `opencode` V1 binary.
