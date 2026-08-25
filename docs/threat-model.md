# Threat Model

## Objective

Reduce the probability that an LLM coding agent accidentally or intentionally reads, modifies, or transmits sensitive local data.

## Protected assets

Examples include:

- API keys and access tokens
- cloud credentials
- SSH private keys
- TLS private keys and keystores
- package-manager credentials
- Terraform state
- shell configuration containing credentials
- production logs and other sensitive operational data
- local configuration stores containing secrets

## Adversary

The primary adversary is an LLM agent operating through OpenCode.

The agent may be:

- mistaken;
- over-permissioned;
- manipulated by prompt injection;
- induced to execute a dangerous command;
- deliberately attempting to access data it should not access.

The model provider is considered an external recipient of any content that reaches the model context.

## Security goals

1. Prevent direct reads of high-confidence secret resources.
2. Prevent writes/edits that create or alter protected resources.
3. Detect common shell-based bypasses.
4. Require explicit approval for ambiguous sensitive resources.
5. Reduce accidental discovery through watcher/indexing controls.
6. Make residual risks explicit.

## Out of scope

This project does not attempt to protect against:

- a compromised host or operating system;
- root-level compromise;
- a malicious OpenCode binary;
- a malicious or compromised plugin;
- arbitrary native code with unrestricted privileges;
- unrestricted network egress;
- secrets already present in model context;
- all possible side channels;
- all possible MCP exfiltration paths.

## Trust boundaries

The most important boundary is:

**local workstation -> OpenCode tools -> LLM provider**

Once sensitive data crosses that boundary, local controls cannot retract it.

## Security posture

The project uses defense-in-depth. A failure of one layer should not automatically imply exposure, but several layers can fail together.

The project must never describe itself as a complete sandbox or DLP system unless a future architecture genuinely provides those guarantees.
