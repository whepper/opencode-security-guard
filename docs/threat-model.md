# Threat Model

## Objective

Reduce the probability that an LLM agent operating through OpenCode reads, modifies, or transmits sensitive local data. Risk reduction, not elimination.

## Assets

- API keys, bearer tokens, OAuth/refresh tokens
- SSH private keys and `authorized_keys` trust stores
- Cloud CLI credentials (`~/.aws`, `~/.azure`, `~/.config/gcloud`, `~/.kube`)
- TLS private keys and keystores (`.pem/.key/.p12/.pfx/.jks`)
- Terraform state (embeds provider secrets)
- Package-manager auth (`.npmrc`, `.pypirc`, `.netrc`, `.git-credentials`, Docker `config.json`)
- Shell startup files that export credentials (`~/.zshenv` et al.)
- Dedicated secret stores (`~/.config/secrets/`, OpenCode's own `auth.json`)
- Production logs and other sensitive operational data
- The process environment of anything the agent executes

## Adversary

An LLM agent that may be:

- **mistaken** — debugging a PATH issue and reading `~/.zshenv` (this happened: [incident-2026-08-21.md](incident-2026-08-21.md));
- **manipulated / prompt-injected** — repository content or tool output steering it toward secrets;
- **over-permissioned** — broad allow rules plus saved approvals accumulating over time;
- **deliberately malicious** — attempting known bypass shapes (interpreters, encodings, network senders, git history).

The model provider is an external recipient of everything that reaches model context. Once transmitted, exposure is irreversible locally; rotation is the only remedy.

## Trust boundaries

```
developer workstation
        │  user privileges, full filesystem, full network
        ▼
OpenCode service (plugins, permission engine, tools)   ← trusted computing base
        │  tool execution inherits user authority
        ▼
tool executions (shell, read/edit, grep, webfetch, MCP servers)
        │  any content a tool returns enters model context
        ▼
LLM provider  ──►  irreversibility boundary
```

Everything below OpenCode in this diagram runs with the user's authority; nothing here can contain a determined process that OpenCode itself spawns. That is why the project claims risk reduction only.

## Security goals

1. Deny direct reads/writes of high-confidence secret resources (Layer 1).
2. Require human approval for ambiguous resources (Layers 1+4).
3. Detect common semantic shell bypasses (Layer 4).
4. Reduce accidental discovery/indexing (Layer 2).
5. Make residual failure observable — heartbeat + doctor instead of silent fail-open (Layer 4).
6. Keep every claim testable; ship a bypass corpus with negatives (`tests/bypass/`).

## Out of scope

This project does not protect against:

- compromised OS / kernel / root-level attackers;
- a malicious or backdoored OpenCode binary;
- malicious plugins (a loaded plugin has the host's authority);
- arbitrary native code execution with unrestricted privileges;
- unrestricted network egress (no firewall/proxy layer ships here);
- provider-side compromise, logging, or training use;
- secrets already exposed before deployment of these controls;
- side channels in general (timing, cache, crash dumps…);
- complete MCP protection — connector-specific policy is an explicit future milestone ([mcp.md](mcp.md));
- function indirection beyond alias definitions (`f() { cat .env; }; f`) — invisible to one-pass command analysis;
- interpreter string obfuscation (`open(chr(46)+'env')`) and `$'\x2e…'` ANSI-C quoting;
- filenames arriving through stdin, heredoc bodies, scripts that already exist on disk, and `cp`-glob staging (file-management exempt by design — see [evasion-2026-09-04.md](evasion-2026-09-04.md) E2);

## Posture statement

Defense-in-depth: each layer assumes the others fail. The project must never describe itself as a sandbox or DLP system unless a future architecture genuinely provides those guarantees.
