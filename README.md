# OpenCode Security Guard

Defense-in-depth controls that reduce the risk of an LLM coding agent running through **OpenCode V2** reading, exposing, modifying, or transmitting sensitive local data such as API keys, SSH material, cloud credentials, or Terraform state.

> **What this is not:** this is not a sandbox, not a complete DLP boundary, and not a guarantee against data exfiltration. An agent with shell and network access operates with your privileges. See [docs/limitations.md](docs/limitations.md).

## What problem does it solve?

LLM agents are useful because they can read files and run commands. Those same capabilities can leak secrets into model context — accidentally (`cat ~/.zshenv` during a PATH debug, see [the incident case study](docs/incident-2026-08-21.md)) or through prompt injection. Once a secret reaches the model provider it must be considered compromised. This project stacks several imperfect layers so that no single mistake is sufficient.

## What it protects — and what it does not

| Protected (risk reduced) | Not protected |
| --- | --- |
| Reads of `.env`-style files, private keys, keystores | A compromised OS, root kit, or malicious OpenCode binary |
| Cloud/SSH/kube credential directories, Terraform state | Unrestricted network exfiltration by other means |
| Package-manager auth files (`.npmrc`, `.netrc`, …) | Secrets already present in model context |
| Shell commands that combine reader/sender verbs with secret paths | Every possible side channel, alias, or obfuscation |
| Environment dumps and printing of secret-named variables | Complete MCP coverage (see [docs/mcp.md](docs/mcp.md)) |

The full statement is in [docs/threat-model.md](docs/threat-model.md).

## Security guarantees & non-guarantees

Every claim below traces to an executed test in `tests/` and, where marked "live", to runs recorded in [docs/verification-log.md](docs/verification-log.md).

### Currently protected

- **Protected-file reads** via the native read tool — hard-denied for high-confidence secrets (`.env*`, key material, cloud/SSH/kube/GPG stores, Terraform state, package-manager auth), with sanitized exceptions (`.env.example` et al.) explicitly allowed. Matching is **case-insensitive**, because APFS/NTFS are: `cat .ENV` is `cat .env` on a Mac.
- **Shell-based secret reads** — `cat`/`head`/`tail`/`less`/`grep`/`awk`/`sed` and friends aimed at protected paths are blocked by the execution-time guard, including env-var (`$HOME/.env`) and alternate-separator constructions (`cat$IFS.env`), shell-quoting artifacts that the kernel resolves to a secret name (`cat .e''nv`, `cat .e\nv`), temp-copy provenance (`cp .env /tmp/x && curl -d @/tmp/x`), and benign-named symlinks resolving onto protected files (including `~/`-relative ones).
- **Interpreter bypasses** — inline `python3`/`node`/`ruby`/`perl`/`php` code touching protected paths or secret-named environment variables.
- **Re-entry wrappers** — payloads of `bash -c`, `sh -lc`, `eval`, `env CMD`, `sudo`, `nohup`, `time`, `watch`, `xargs` are analyzed as commands, so a printer or dump cannot hide behind an unclassified outer verb.
- **Indirection** — single and chained variable assignment (`F=.env; cat $F`), bash indirect expansion (`cat ${!A}`), command/process substitution, and alias definitions (`alias rc='cat .zshenv'` is checked at definition time).
- **Transformations & packing** — `base64`/`base32`/`xxd`/`od`/`openssl` input-flag misuse and archive creation (`tar`/`zip`/`jar`/`7z`) containing protected members.
- **Network senders consuming protected data** — `curl --data @…`, `-F …@…`, `wget --post-file`, `nc` stdin redirection, `scp`.
- **Environment exposure** — `env`/`printenv`/`set`/`export -p`/`declare -p`/`alias` dumps; echoing secret-named variables; interpreter `environ`/`process.env` access.
- **Search & discovery gaps closed** — grep/glob tool calls whose paths/patterns target protected material (native permissions cannot express this).
- **Git history/object access** — `git show`/`cat-file`/`archive`/`log -p` naming protected paths, behind global flags (`git -C repo show …`) included.
- **Deferred execution** — writing a script whose body references protected material raises an approval at write time, the only moment the guard can see it.
- **Guard self-protection** — writes to the plugin's override file and heartbeat are denied, writes to plugin/policy sources require approval, and reads stay free so the guard is auditable; `doctor` fails (not warns) on a non-active or dead-pid heartbeat.
- **MCP tools** — per-tool permission rules natively; trust-tier defaults, semantic classes (read-only / external-write / destructive / credential-related / unknown), argument-level protected-path rules (including references embedded inside longer argument strings) and secret-value rules via the guard.
- **Observable failure** — plugin liveness heartbeat + doctor; a silently absent guard is treated as a release defect.

### Not guaranteed

- **Not network egress control**: nothing here stops transmission through channels the agent's shell already has (curl to arbitrary hosts, DNS, cloud CLIs). No proxy/firewall/namespace isolation ships in v0.2.
- **Not protection against malicious MCP servers**: policy gates *tool calls*, but a compromised server can lie in descriptions, return poisoned content, or exfiltrate server-side. Trust statements are operator assertions.
- **Not protection against arbitrary native binaries** that read secrets directly and exfiltrate out-of-band; unknown-verb coverage is heuristic.
- **Not host/OS security**: root kits, keyloggers, disk access outside OpenCode.
- **Not protection against a compromised OpenCode binary or malicious plugins** — anything loaded as a plugin runs with your authority.
- **No complete semantic data-flow tracking**: cross-call content tracking is an opt-in tripwire (`mcp.provenance.enabled`) that paraphrase, re-encoding, chunking, and summarization evade by construction.
- **No recovery of already-exposed secrets**: if a secret reached a provider, rotate it; controls cannot retract transmissions.

We do not use the phrase "prevents data exfiltration." The accurate claim: *reduces likelihood and adds observable enforcement points*.

## How it works — four layers

1. **Native OpenCode permissions** (`config/opencode.jsonc`, generated from `policy/policy.jsonc`): 73 ordered V2 rules — deny high-confidence secrets, ask on ambiguous names, deny/ask on the guard's own files, allow ordinary work.
2. **Watcher exclusions**: reduce accidental discovery/indexing. *Not* a security boundary.
3. **Agent policy** (`policy/AGENTS.md`): behavioral guidance only, never enforcement.
4. **Execution-time guard** (`plugin/security-guard.js`): inspects tool calls semantically — interpreter reads, `base64`/`xxd` transforms, `curl @file`, environment dumps, git-history access, temp-copy provenance — where path rules cannot reach.

Details: [docs/architecture.md](docs/architecture.md).

## Install

```sh
node scripts/install.mjs --scope project --yes   # this repository/session only
# or
node scripts/install.mjs --scope global --yes    # your user account
opencode2 service restart                        # plugins load at service start
node scripts/doctor.mjs --live                   # verify everything
```

The installer detects OpenCode V2, shows exactly what it will change, backs up every file it touches, refuses to clobber an existing permission setup, and prints rollback commands. Full guide including the manual path: [docs/installation.md](docs/installation.md).

## Test

```sh
npm test        # unit tests + adversarial bypass corpus (no OpenCode needed)
npm run check   # syntax + structure validation + dependency-free secret scan
```

After installing into a real scope, verify your deployment:

```sh
node scripts/security-test.mjs          # offline self-test of the installed
                                        # plugin (safe: synthetic data only)
node scripts/security-test.mjs --json   # machine-readable output for reports
```

The output ends with a pasteable summary (guard/opencode/os versions + pass/fail counts) intended for bug reports. It never reads your files or requires live secrets; behavioral checks against a running session are documented in [docs/installation.md](docs/installation.md).

## Supported versions

| Component | Status |
| --- | --- |
| OpenCode V2 (`opencode2`) `0.0.0-beta-18219` | **tested** — config accepted, plugin loads, native enforcement demonstrated |
| OpenCode V2 (`opencode2`) `0.0.0-beta-18230` | **tested** — full matrix incl. MCP enforcement |
| OpenCode V2 (`opencode2`) `0.0.0-beta-18269` | **tested** — release smoke matrix (native + MCP) |
| OpenCode V2 (`opencode2`) `0.0.0-beta-18743` | **unverified for v0.3.0 rules** — engine tests pass; live enforcement matrix not yet re-run (see verification log, 2026-09-01 entry) |
| Other V2 betas | unverified — **run `scripts/doctor.mjs` and the smoke checklist after every upgrade**; plugin/config APIs are beta and may break |
| OpenCode 1.x (`opencode`, V1 dialect) | unsupported; the V1 `permission` object syntax and `tool.execute.before` hooks differ fundamentally — see migration notes in [docs/installation.md](docs/installation.md) |

V2 currently parses but does **not act** on the `share` config field; this repo sets `"share": "disabled"` as intent, not as a working control.

## Reporting vulnerabilities

See [SECURITY.md](SECURITY.md). Please report privately; never include real credentials.

## License

[Apache License 2.0](LICENSE).
