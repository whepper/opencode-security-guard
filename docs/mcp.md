# MCP (Model Context Protocol) — measured behavior and enforcement

Status: **implemented against measured runtime behavior** (probe results in [verification-log.md](verification-log.md), 2026-08-26 entries). This page replaces the earlier hypothesis that MCP tools simply bypass the four layers. That hypothesis was **partly wrong**, and the difference matters.

## What OpenCode V2 actually does with MCP calls

Verified on `opencode2` beta-18230 (and native-tool paths identically on beta-18219):

- Every MCP tool surfaces under an action name `` `${server}_${tool}` `` (characters normalized to `_`) — e.g. server `web-search-prime`, tool `web_search_prime` → action `web_search_prime`.
- `permission.evaluate` fires **per MCP call** with that action and `resources: ["*"]`, pre-execution.
- `tool.execute.before` fires per MCP call with the **full argument object**.
- `tool.execute.after` fires with the **result content**.
- A plugin throwing in `execute.before` blocks an otherwise-allowed MCP call mechanically (it even preempts permission evaluation).
- Native `deny` rules make an MCP tool unavailable to the model outright; native `ask` rules produce a real permission prompt (auto-rejected in non-interactive `run` mode).
- In this build, MCP tools are exposed to the model **only through the Code-Mode `execute` dispatcher** (`tools.<server>.<tool>(...)`). Enforcement composes per nested call — but diagnostic messages thrown for inner calls flatten to generic failure text in the wrapper result.

## The five-layer picture for MCP

| Layer | What it does for MCP |
| --- | --- |
| Layer 1 — native permissions | Per-tool `<server>_<tool>` rules (deny survives saved approvals). The generator mirrors explicit policy denies as native rules so they hold even if the plugin is absent. |
| Layer 4a — guard, permission channel | Trust × class defaults and explicit tool rules escalate `allow → ask/deny`; asks become real prompts (auto-rejected headlessly). Arguments are not visible on this channel. |
| Layer 4b — guard, tool channel | Argument-level analysis where inputs ARE visible: protected-path tiers reuse the filesystem classifier; secret-named value shapes are flagged. Deny-tier hits hard-block; approval-tier hits block with a pointer to allowlisting (same no-prompt-channel trade-off as grep/glob). |
| Layer 4c — provenance experiment | Opt-in tripwire: results of approval-gated calls are sampled; later arguments embedding that content are blocked. A heuristic, never a guarantee. |
| Layers 2–3 | Watcher exclusions don't apply to remote servers; AGENTS.md guidance demonstrably steers models away from misuse but remains advisory. |

## Policy

Configured in `policy/policy.jsonc` under `mcp`:

- `servers`: explicit trust statements — `trusted | restricted | untrusted | blocked`, each with a reason. **Transport is not a trust signal**: a local stdio wrapper can proxy a remote service (real-world example in the verification log).
- `tools[]`: explicit per-tool overrides (`id`, `server`, `tool`, `class`, `effect`, `reason`). Explicit denies are mirrored into native rules by the generator.
- `verbClasses` + `defaults`: token-based name classification for unlisted tools, resolved through a trust×class default table. Ambiguous verbs (`fetch`, `run`, …) map to `unknown` and never guess.
- `argRules`: protected-path tiers and secret-named value shapes.
- False-positive discipline is codified in tests: `tokenize_dataset` is not credential-related; `get_updates` is not a write.

Unlisted servers run fail-conservative defaults (read/local-data/write/network/credential asks; destructive denies) rather than blanket denial — matching the project's deny-certain/ask-ambiguous philosophy.

## Remaining gaps (measured, not speculative)

1. **Code-Mode message flattening**: inner-call block reasons surface to the model as generic failure text; rule IDs land in the heartbeat and doctor instead of the chat transcript.
2. **Name ambiguity**: `${server}_${tool}` parsing is ambiguous when server names contain `_`; resolved by longest-known-prefix and degraded conservatively otherwise.
3. **Provenance evasions**: paraphrase, re-encoding, summarization, chunking defeat the marker store by construction (tests assert this honesty).
4. **Destination opacity**: wrapper servers hide true endpoints; per-call network destinations are invisible unless an argument carries them. Only OS/network-level egress controls close this ([limitations.md](limitations.md)).
5. **Policy drift**: renaming a server silently orphans its rules; doctor warns.
6. A malicious server can lie in descriptions/names; classification of unlisted tools is heuristic by necessity.

## Future milestone (unchanged)

Connector-specific profiles driven by capability discovery (tools/list introspection at setup), per-server argument schemas, and TUI-surfaced rule messages for Code-Mode nesting — each requires another round of empirical probes before any claim.
