# Limitations

Read this page as the honest price list of the design.

## The plugin can fail open

If `plugin/security-guard.js` throws while loading, OpenCode logs a WARN and continues **without Layer 4** (verified on beta-18219). Nothing in V2 lets a plugin make its own absence fatal. Mitigations, not solutions:

- the plugin writes a heartbeat file before anything else;
- `scripts/doctor.mjs --live` fails loudly when the heartbeat is missing/stale, when its phase is not `active` (setup died partway → hooks unregistered), or when the recorded pid is not a running process;
- **run the doctor after every OpenCode upgrade** — beta APIs change.

## Network egress is uncontrolled

No firewall, proxy, or namespace isolation ships here. A secret that reached context can leave via any channel the agent's shell already has. See the reserved future-layer notes in [architecture.md](architecture.md).

## Command analysis is heuristic, not parsing

The engine tokenizes and pattern-matches; it does not implement a shell grammar. v0.3 closed the confirmed classes (case variants, quote/backslash artifacts, re-entry wrappers, indirect expansion, `$IFS` separators, git global flags, alias definitions — each pinned by corpus cases), and each fix was verified as a live bypass first. What remains (each with a corpus entry or rationale in `tests/bypass/cases.jsonc`):

- **string-obfuscated filenames inside interpreter code** — `open(chr(46)+'env')`, hex/unicode escapes, runtime concatenation: no literal ever appears in the argument list;
- **`$'\x2e…'` ANSI-C quoting**, which decodes escapes the shell understands but the normalizer does not;
- **function bodies** (`f() { cat .env; }; f`) and `unalias`, which define behavior beyond a single assignment value;
- **filenames arriving through stdin** (`xargs -I{} sh -c 'base64 {}' < list`) — pinned as `BYP-WRP-008` so the residual is asserted, not assumed;
- **heredoc bodies** and custom tools with unknown verbs;
- **scripts that already exist on disk**, or arrive via `git pull`/package install: the v0.3 write-content check sees content only at the moment the agent writes it, never afterwards;
- **unknown verbs touching protected names** ask only on explicit credential flags, otherwise stay silent — deliberate false-positive control that trades coverage;
- **case-folding false positives on Linux**: `FOO.PEM` is a different file than `foo.pem` there, and gets asked about anyway. Accepted: the alternative is a universal bypass on macOS/Windows.

New bypass shapes belong in the corpus first, then the engine.

## The guard can be weakened only by a human, not by the agent

The guard's own files are attack surface: rewriting `security-guard.js`, its
`security-guard.config.json` override, `policy.jsonc`, or the heartbeat JSON
would disarm or falsify Layer 4. v0.3 gates these (`GG-SLF-*` in the guard,
`SG-WRT-008..011` natively): writes to the override file and heartbeat are
denied, writes to plugin/policy sources require explicit approval, and **reads
stay unrestricted** so the guard can always be audited.

Honest limits: this raises the tamper bar from "any tool call" to "a human must
approve an obviously suspicious edit, or the user's own shell must be trusted
not to edit files outside OpenCode." It also means guard development produces
approval prompts on purpose — that friction is the control working.

Write-shaped tamper is covered for the paths an agent actually uses: edit/write
tools, `>` / `>>` redirections, `rm`, `tee`, `dd of=`, `cp`/`install`/`rsync`
destinations, `mv` in **both** directions (its destination *and* the sources it
unlinks), and `sed -i`. What is *not* covered is any write that does not name a
guard file in an observable argument: an interpreter that assembles the path at
runtime (`open(os.path.expanduser("~/.con" "fig/opencode/plu" "gins/" + name)`,
`'w')`) is the interpreter-obfuscation class above, and out-of-band edits made
by the user or by software outside OpenCode are outside the model's threat
surface by definition.

## Ask-tier depends on humans

Approval fatigue is real: "allow always" saves durable project-scoped patterns which may be broader than what was displayed (several tools propose `*`). Review saved approvals periodically. Deny rules cannot be weakened this way — that is why high-confidence items deny instead of ask.

## Filename signals are insufficient by definition

`.zshenv` taught this ([incident](incident-2026-08-21.md)): any file can carry secrets regardless of name. The layers reduce but do not close this class; treat any tool output as potentially sensitive.

## Watcher exclusions are comfort, not control

Excluded paths are still fully readable by anything the agent executes.

## `share: "disabled"` is currently inert

V2 parses the field but implements no sharing feature yet. It records intent only.

## MCP is now policy-addressable, not policy-exempt

OpenCode V2 exposes every MCP tool as its own permission action and fires guard hooks (with arguments and results) per call — measured behavior, enforcement shipped in v0.2. Remaining MCP limits: Code-Mode flattens inner-call block messages; provenance is an opt-in tripwire that paraphrase/encoding defeats; wrapper servers hide true destinations. Details in [mcp.md](mcp.md).

## Existing exposure is forever

Controls added after a leak cannot retract data already sent to a provider. Rotate first, harden second.

## Version drift

The target is a **beta** with explicitly unstable plugin/configuration APIs. Behavior verified on `0.0.0-beta-18219` may change under you. The doctor + test suite exist precisely to make re-verification cheap.
