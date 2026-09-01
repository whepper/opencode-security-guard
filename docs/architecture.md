# Architecture

Four independent, individually imperfect layers. No layer is trusted to work alone; several can fail together (see [limitations.md](limitations.md)).

```
                     ┌─────────────────────────────────────────────┐
                     │ Layer 3: AGENTS.md policy (advisory only)   │
                     └─────────────────────────────────────────────┘
   agent wants to      ┌────────────────────────────────────────────┐
   read/run something  │ Layer 1: native V2 permission rules        │  deny / ask / allow
   ───────────────────►│ (ordered rules; last match wins)           │──────────────►
                       └───────────────┬────────────────────────────┘
                                       │ allow/ask decisions
                                       ▼
                       ┌────────────────────────────────────────────┐
                       │ Layer 4: security-guard plugin             │  escalate to deny/ask
                       │ pure decision engine + V2 hooks            │
                       └───────────────┬────────────────────────────┘
                                       │ tool executes
                                       ▼
                       ┌────────────────────────────────────────────┐
                       │ Layer 2: watcher exclusions                │  discovery/indexing only
                       └────────────────────────────────────────────┘
```

## Single source of truth

`policy/policy.jsonc` is the only hand-edited policy. Every rule carries a stable ID (`SG-*` native, `GG-*` guard), an effect, and a rationale. `scripts/generate-config.mjs` derives:

- `config/opencode.jsonc` — the native rule array and watcher list (IDs/reasons become comments because the V2 schema strips unknown fields — verified);
- the compiled rule block inside `plugin/security-guard.js` between generated-policy markers.

Tests enforce this derivation (`tests/unit/drift.test.js`) so the layers cannot silently diverge.

## Layer 1 — native OpenCode V2 permissions

Dialect verified against the V2 documentation and the installed beta:

| Verified semantic | Consequence for this policy |
| --- | --- |
| Rules are an ordered array; **last matching rule wins** | broad allows first → denies → asks → safe exceptions **last** |
| Unmatched resources default to `ask` | explicit broad allows are required or every action prompts |
| `*` spans `/`; there is no `**`; matching covers the whole value | nested coverage needs leading `*` (`*.env`, `*.ssh/*`) |
| Multi-resource ops deny if any resource denies | patching mixed file sets stays safe |
| A shell pattern ending `" *"` also matches the bare command | command prefixes behave intuitively |
| Saved ("allow always") approvals never override a configured `deny` | deny tier is durable even after fat-fingered approvals |
| `external_directory` gates paths outside the workspace *before* read/edit rules | home-directory files face two gates by default |
| grep's resource is the regex, glob's is the pattern — not paths | path-based protection of search tools is a Layer-4 job |
| Unknown config fields are stripped (e.g. a `reason` on rules) | IDs/reasons live in comments |

Rule groups (IDs in `policy/policy.jsonc`): broad allows (`SG-BASE-*`, `SG-NET-*`), environment files (`SG-ENV-*`), key material (`SG-KEY-*`), SSH (`SG-SSH-*`), cloud/kube/gpg/docker/secret-stores (`SG-CLOUD-*`, `SG-WRT-*`), Terraform state (`SG-IAC-*`), package-manager auth (`SG-PKG-*`), shell startup files (`SG-RC-*`), ambiguous asks (`SG-AMB-*`), safe exceptions (`SG-EXC-*`, always last).

## Layer 2 — watcher exclusions

`watcher.ignore` keeps secret-shaped paths out of OpenCode's file watching/indexing. **This is convenience, not authorization**: anything the agent executes can still read those paths.

## Layer 3 — AGENTS.md

Advisory instructions (`policy/AGENTS.md`): never seek/print/transmit secrets, never circumvent denials, treat startup files as sensitive, request sanitized substitutes. Presented to the model as text; **never counted as enforcement**. The installer can append it between markers to your global `AGENTS.md` without touching unrelated content.

## Layer 4 — execution-time guard plugin

Single dependency-free ESM file targeting the verified V2 plugin API:

- default export is an **object** `{ id, setup(ctx) }` (a bare function fails schema validation — probed);
- hooks registered in `setup`: `ctx.tool.hook("execute.before")` and `ctx.permission.hook("evaluate")`;
- `permission.evaluate` sees post-rules decisions and may escalate `allow→ask/deny`; it cannot weaken a configured deny;
- the tool hook closes gaps whose permission resources are not paths (grep/glob) and blocks hard-denied shell operations with a structured message;
- a pure decision engine does all analysis (path classification with case folding for APFS/NTFS and shell-word normalization for quoting/backslash artifacts, command segmentation/tokenization, reader/interpreter/transformer/sender/archive/git verb classes, **re-entry wrapper recursion** (`bash -c`, `eval`, `env`, `sudo`, `watch`, `xargs`), env-dump and secret-variable detection, `$VAR`/`${!VAR}`/`$IFS` indirection, alias-definition bodies, temp-copy provenance via tracked `cp`, `--kubeconfig` flag pointers, guard self-protection on write-class operations, and protected-reference scanning of script content at write time). It is unit-tested without OpenCode;
- diagnostics are value-free: rule ID, category, matched **basename** only — never command text, variable values, or file contents;
- **fail-open reality**: if the plugin throws during load, OpenCode logs a WARN and continues without it (probed on beta-18219). Countermeasure: the plugin writes a heartbeat JSON (`~/.local/share/opencode-security-guard/health.json`) as the very first setup step, and `scripts/doctor.mjs --live` **fails** when it is missing, stale, non-`active`, or records a dead pid, or when logs show load failures.
- **self-protection**: the guard treats its own files as assets. Writes to `security-guard.config.json` and `health.json` are denied, writes to `security-guard.js`/`policy.jsonc` require approval, reads stay free; the same rules exist natively (`SG-WRT-008..011`) so they hold when the plugin is absent.

## Network control (future fifth layer)

Filesystem controls cannot stop exfiltration once a secret is in context. A credible future design places agent execution behind one of:

- an allow-list egress proxy (per-domain policy, TLS inspection off-host);
- Linux network namespaces / macvlan isolation per session;
- containers or micro-VMs with no direct host network;
- OS firewall rules scoped to the agent's uid;

…each with real operational cost. This repository deliberately ships **none** of them rather than a placebo; the docs reserve the architecture space instead.
