# Limitations

This project intentionally documents what it cannot guarantee.

## Not a sandbox

The agent still operates with the privileges granted by the surrounding OpenCode process and operating system.

## Network egress

An unrestricted shell can communicate with arbitrary network destinations. Preventing a file read does not guarantee that a secret cannot be obtained indirectly and transmitted.

## Semantic bypasses

Command inspection is heuristic. Agents can construct equivalent operations through:

- aliases;
- scripts;
- compiled programs;
- archives;
- process substitution;
- command indirection;
- Git object access;
- unusual encodings;
- other tools not recognized by the guard.

The goal is risk reduction, not formal proof of non-exfiltration.

## Plugin availability

If the execution-time plugin fails to load, the protection it provides is absent. Deployments should verify that the plugin is loaded after OpenCode upgrades.

A future version should prefer an explicit fail-closed operational mode where supported.

## Approval prompts

The `ask` tier depends on the human making a correct decision. Blanket "allow always" approvals can weaken the policy.

## Existing exposure

If a secret was already placed in model context, changing the policy cannot undo the transmission. Rotate the credential.

## MCP

MCP tools may have access paths that do not map cleanly onto local filesystem rules. MCP-specific controls require additional testing and potentially connector-specific policy.
