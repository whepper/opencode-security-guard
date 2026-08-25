# Architecture

## Four-layer model

### Layer 1 — OpenCode permissions

Native OpenCode permission rules provide the primary policy boundary.

Typical actions:

- `deny` for high-confidence secrets;
- `ask` for ambiguous resources;
- `allow` for normal development files.

Rules should be evaluated using OpenCode's documented semantics for the supported version.

### Layer 2 — watcher exclusions

Watcher exclusions reduce accidental discovery and indexing of sensitive data.

Examples:

- `.env*`
- private key material
- cloud credential directories
- Terraform state
- `.git`
- generated/build directories

Watcher exclusions are **not** an authorization boundary.

### Layer 3 — agent policy

`AGENTS.md` provides behavioral guidance:

- do not read or print secrets;
- do not circumvent permissions;
- do not use alternative tools to bypass a protected path;
- ask for sanitized substitutes;
- treat production logs as sensitive;
- minimize context sent to the model.

Policy is advisory and must never be relied upon as the sole security control.

### Layer 4 — execution-time security guard

The plugin inspects tool executions for semantic combinations that path-based rules cannot reliably express.

Examples include:

- Python/Node/etc. reading a protected file;
- `base64` or `xxd` applied to protected data;
- `openssl` consuming private keys;
- environment dumps;
- secret-named environment variables being printed or transmitted;
- `curl`/similar senders consuming sensitive files.

## Future fifth layer: network control

The major architectural gap is unrestricted network egress.

A stronger deployment could place agent execution behind:

- an allow-listed proxy;
- a network namespace;
- a container/VM boundary;
- OS-level firewall policy;
- another independently enforced egress-control mechanism.

This repository does not currently claim to implement that layer.
