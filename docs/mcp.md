# MCP (Model Context Protocol) — a separate risk area

Status: **investigated, not solved.** This page records what OpenCode V2 currently offers, where MCP bypasses filesystem-focused assumptions, and what remains unbuilt. Do not assume MCP protection that has not been tested.

## What V2 permissions can express today

Verified from the V2 permissions documentation:

- MCP tools surface under permission actions named `<server>_<tool>` (`.` and other unsupported characters become `_`), resource `*` or more specific;
- rules are ordinary ordered rules, e.g.

```jsonc
{
  "permissions": [
    { "action": "filesystem_read_file", "resource": "*", "effect": "ask" },
    { "action": "my_server_execute", "resource": "rm *", "effect": "deny" }
  ]
}
```

- the plugin context can enumerate servers (`ctx.mcp.list()`) and connect/disconnect them.

## Where MCP breaks filesystem assumptions

1. A filesystem-type MCP server reads files through its own tool actions — native `read` denies do **not** apply. `SG-ENV-001` stops OpenCode's read tool; it says nothing about `acme_fs_read_all`.
2. Remote MCP servers receive whatever arguments the model sends — arguments themselves can carry secrets already in context.
3. Local MCP servers run with user authority; their tool results enter model context exactly like shell output.
4. Permission names depend on server/tool naming: renaming a server silently changes the action name your policy targets.

## Practical guidance until connector policy exists

- Treat every configured MCP server as a trust decision equal to installing software.
- Prefer servers you operate or vet; pin versions where possible.
- Add explicit `<server>_<tool>` ask/deny rules per sensitive capability before connecting anything.
- Remember Layer 4's engine sees only OpenCode-native tools; MCP calls do not flow through `bash`/`read` hooks.

## Future milestone (explicitly unbuilt)

Connector-specific policy:

- per-server profiles (filesystem servers inherit path tiers; web-capable servers get URL tiers);
- argument inspection for known connector schemas via `ctx.tool.hook`;
- tests against real connectors before any claim is made.

No MCP protection claim in this repository should be trusted until those exist.
