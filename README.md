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

## How it works — four layers

1. **Native OpenCode permissions** (`config/opencode.jsonc`, generated from `policy/policy.jsonc`): 69 ordered V2 rules — deny high-confidence secrets, ask on ambiguous names, allow ordinary work.
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

## Supported versions

| Component | Status |
| --- | --- |
| OpenCode V2 (`opencode2`) `0.0.0-beta-18219` and `0.0.0-beta-18230` | **tested** — config accepted, plugin loads, enforcement demonstrated end-to-end on both builds |
| OpenCode V2 beta line in general | expected to work; **re-run `scripts/doctor.mjs` after every upgrade** — the plugin API is beta and may break |
| OpenCode 1.x (`opencode`, V1 dialect) | unsupported; the V1 `permission` object syntax and `tool.execute.before` hooks differ fundamentally — see migration notes in [docs/installation.md](docs/installation.md) |

V2 currently parses but does **not act** on the `share` config field; this repo sets `"share": "disabled"` as intent, not as a working control.

## Reporting vulnerabilities

See [SECURITY.md](SECURITY.md). Please report privately; never include real credentials.

## License

[Apache License 2.0](LICENSE).
