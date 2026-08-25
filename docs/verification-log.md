# Verification log

Every claim in this repository should trace to an entry here. Newest first. "Verified" always means *executed against the stated build*, never inferred from documentation.

## 2026-08-25 — live LLM-session enforcement demos (opencode-go/deepseek-v4-flash)

Method note: `opencode2 run` reuses the shared background service, which was booted under the maintainer's real global config (their own deployed guard loads first and its hooks short-circuit ours). Clean attribution required isolated runs:

```sh
XDG_CONFIG_HOME=<empty-dir> opencode2 run --standalone -m <model> "<prompt>"
```

…which boots a private server with only the scratch project's `.opencode/` plugins (ours). All four checks then executed mechanically, with results attributed by rule ID and the heartbeat's `lastDecision`:

| # | Probe | Expected | Result |
| --- | --- | --- | --- |
| 1 | read tool on `.env` (forced-call prompt) | denied at tool layer | ✅ `[security-guard] BLOCKED (GG-ENV-001): environment secret file. Matched: ".env"` |
| 2 | shell `cat .env` (forced-call prompt) | blocked with `GGR-*` rule | ✅ `[security-guard] BLOCKED (GGR-READ-001) [matched rule GG-ENV-001]`; heartbeat `lastDecision=GGR-READ-001` |
| 3 | read tool on `.env.example` | allowed, content returned | ✅ first line of dummy fixture returned unblocked |
| 4 | grep tool inside `.env` | blocked (search-path coverage) | ✅ `[security-guard] BLOCKED (GG-ENV-001+GREP): content search over environment secret file …` |

Additional observations from the same session:

- With the shared (non-isolated) service, the model repeatedly **self-refused** `.env` access citing installed policy text — Layer 3 demonstrably steering behavior before any tool call.
- The standalone runs auto-updated to **beta-18230** mid-testing; plugin load, heartbeat, and enforcement behaved identically on **both beta-18219 and beta-18230**, and the doctor heartbeat recorded the new version string.
- Provider-side blocker encountered earlier ("No endpoints available matching your guardrail restrictions", OpenRouter data policy) is an example of upstream policy independent of this project; routing through another configured provider avoided it.

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

- Completed later the same day after routing around a provider data-policy block (see the next entry). All four checks passed with rule-level attribution; the isolated-standalone methodology and full results are recorded in the newer entry below.

Until those rows are filled, end-to-end enforcement is verified at these levels only: unit level (engine decisions) + configuration acceptance (rules present and ordered) + plugin liveness (setup completed). That is deliberately short of a demonstration claim.

> Superseded same-day: the table in the newer entry above closes these rows.
