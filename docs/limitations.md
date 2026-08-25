# Limitations

Read this page as the honest price list of the design.

## The plugin can fail open

If `plugin/security-guard.js` throws while loading, OpenCode logs a WARN and continues **without Layer 4** (verified on beta-18219). Nothing in V2 lets a plugin make its own absence fatal. Mitigations, not solutions:

- the plugin writes a heartbeat file before anything else;
- `scripts/doctor.mjs --live` fails loudly when the heartbeat is missing/stale or logs show load failures;
- **run the doctor after every OpenCode upgrade** — beta APIs change.

## Network egress is uncontrolled

No firewall, proxy, or namespace isolation ships here. A secret that reached context can leave via any channel the agent's shell already has. See the reserved future-layer notes in [architecture.md](architecture.md).

## Command analysis is heuristic, not parsing

The engine tokenizes and pattern-matches; it does not implement a shell grammar. Known blind spots (each has a corpus entry or rationale in `tests/bypass/cases.jsonc`):

- aliases and functions (`alias rc='cat .zshenv'; rc`) — invisible to one-pass analysis;
- deep indirection beyond one variable hop or one copy hop;
- scripts on disk whose *content* is never visible to the guard;
- heredoc bodies, exotic encodings, custom tools with unknown verbs;
- unknown verbs touching protected names ask only on explicit credential flags, otherwise stay silent — deliberate false-positive control that trades coverage.

New bypass shapes belong in the corpus first, then the engine.

## Ask-tier depends on humans

Approval fatigue is real: "allow always" saves durable project-scoped patterns which may be broader than what was displayed (several tools propose `*`). Review saved approvals periodically. Deny rules cannot be weakened this way — that is why high-confidence items deny instead of ask.

## Filename signals are insufficient by definition

`.zshenv` taught this ([incident](incident-2026-08-21.md)): any file can carry secrets regardless of name. The layers reduce but do not close this class; treat any tool output as potentially sensitive.

## Watcher exclusions are comfort, not control

Excluded paths are still fully readable by anything the agent executes.

## `share: "disabled"` is currently inert

V2 parses the field but implements no sharing feature yet. It records intent only.

## MCP is a separate risk area

MCP tool calls surface under `<server>_<tool>` actions, so filesystem-focused denies do not apply to them. See [mcp.md](mcp.md); connector-specific policy is unbuilt and untested.

## Existing exposure is forever

Controls added after a leak cannot retract data already sent to a provider. Rotate first, harden second.

## Version drift

The target is a **beta** with explicitly unstable plugin/configuration APIs. Behavior verified on `0.0.0-beta-18219` may change under you. The doctor + test suite exist precisely to make re-verification cheap.
