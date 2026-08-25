# Verification log

Every claim in this repository should trace to an entry here. Newest first. "Verified" always means *executed against the stated build*, never inferred from documentation.

## 2026-08-25 — initial release candidate (opencode2 `0.0.0-beta-18219`)

Platform facts probed live:

- **Plugin shape**: default export must be an object `{id, setup}`; a bare async function fails schema validation (`SchemaError(Expected object at ["default"])`). Probe plugin loaded cleanly with the object form, no imports required → zero-dependency plugin viable.
- **Autoload directories**: V2 loads plugins from `~/.config/opencode/plugins/` **and** `<project>/.opencode/plugins/`.
- **Fail-open on load errors**: a plugin throwing in `setup` produces `WARN … failed to load plugin` while `/api/health` stays green — Layer 4 absence is silent unless monitored; heartbeat + doctor added as countermeasure.
- **Config acceptance**: generated config (ordered `permissions`, `watcher.ignore`, `share`) accepted by the beta (`debug config` exit 0). Unknown rule fields (e.g. `reason`) are schema-stripped → IDs/reasons emitted as comments.
- **console.log from plugins does not reach server logs** → file-based heartbeat design.
- **ctx surface** confirmed: `app{version}`, `tool.hook`, `permission.hook`, `shell.hook`, `storage`, etc.

Automated verification (runs in CI):

- 101 tests: engine unit tests (V2 wildcard semantics incl. last-match-wins and trailing-`" *"` behavior), policy structure/ordering invariants, drift checks between policy source and both derived artifacts, adversarial corpus (block/ask/negative cases incl. incident replay).
- Dependency-free secret scanner over all tracked files; validator for structure/license/metadata.
- Installer + doctor exercised end-to-end in a scratch project: install → service start → heartbeat `phase=active` → doctor `result: healthy`; refusal path (existing permissions) and `--merge` path both executed.

Live LLM-session enforcement demos:

- **PENDING** — blocked during release testing by provider data-policy settings (OpenRouter refused session requests: *"No endpoints available matching your guardrail restrictions"*). The four prepared prompts and expected outcomes are in [installation.md](installation.md#live-smoke-checklist-manual); results are to be recorded below once executed.

| Checklist item | Expected | Result |
| --- | --- | --- |
| 1 read tool on `.env` | denied natively | PENDING |
| 2 shell `cat .env` | `[security-guard] BLOCKED` with `GGR-*` rule | PENDING |
| 3 read `.env.example` | allowed, dummy content returned | PENDING |
| 4 grep tool inside `.env` | blocked (search-path coverage) | PENDING |

Until those rows are filled, end-to-end enforcement is verified at these levels only: unit level (engine decisions) + configuration acceptance (rules present and ordered) + plugin liveness (setup completed). That is deliberately short of a demonstration claim.
