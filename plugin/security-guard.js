/**
 * Security Guard for OpenCode — execution-time guard plugin (Layer 4).
 *
 * Platform: OpenCode V2 (opencode2). Verified against 0.0.0-beta-18219:
 *   - plugins are ESM modules whose DEFAULT EXPORT is an OBJECT
 *     ({ id, async setup(ctx) }); a bare function fails schema validation
 *   - hooks are registered inside setup() via ctx.tool.hook(...),
 *     ctx.permission.hook(...), ctx.shell.hook(...)
 *   - a plugin that throws during load is skipped with a WARN log line while
 *     OpenCode keeps running => THIS LAYER CAN FAIL OPEN. scripts/doctor.mjs
 *     verifies liveness via the heartbeat file this plugin writes on startup.
 *
 * Zero dependencies. Single file by design so installations stay auditable.
 *
 * Architecture:
 *   OpenCode adapter (bottom of file)
 *     -> normalized tool/action representation (normalizeToolCall /
 *        evaluatePermissionEvent)
 *       -> pure decision engine (analyzeCommand, classifyPath, ...)
 *
 * The decision engine is deterministic and independently unit-testable with
 * plain Node (`node --test tests/`). It NEVER logs or echoes command text,
 * variable values, or file contents — diagnostics carry rule IDs, categories,
 * and matched basenames only.
 */

// ==== BEGIN GENERATED GUARD POLICY (regenerate via: node scripts/generate-config.mjs) ====
// Compiled from policy/policy.jsonc — EDIT THE POLICY, NOT THIS BLOCK.
export const GENERATED_GUARD_POLICY = Object.freeze({
  "policyVersion": 1,
  "profile": "baseline",
  "denyPaths": [
    {
      "id": "GG-ENV-001",
      "form": "basename",
      "value": ".env",
      "reason": "environment secret file"
    },
    {
      "id": "GG-ENV-002",
      "form": "prefixName",
      "value": ".env.",
      "exceptSuffixes": [
        ".example",
        ".sample",
        ".template"
      ],
      "reason": "environment variant (.env.production etc.; sanitized templates excluded here so they fall through to the allow list)"
    },
    {
      "id": "GG-ENV-003",
      "form": "suffix",
      "value": ".env",
      "reason": "dotenv-convention file at any name (mirrors native *.env; .pub/.example stay allowed)"
    },
    {
      "id": "GG-KEY-001",
      "form": "suffix",
      "value": ".pem",
      "reason": "private key/cert material"
    },
    {
      "id": "GG-KEY-002",
      "form": "suffix",
      "value": ".key",
      "reason": "private key material"
    },
    {
      "id": "GG-KEY-003",
      "form": "suffix",
      "value": ".p12",
      "reason": "keystore"
    },
    {
      "id": "GG-KEY-004",
      "form": "suffix",
      "value": ".pfx",
      "reason": "keystore"
    },
    {
      "id": "GG-KEY-005",
      "form": "suffix",
      "value": ".jks",
      "reason": "keystore"
    },
    {
      "id": "GG-KEY-006",
      "form": "suffix",
      "value": ".keystore",
      "reason": "keystore"
    },
    {
      "id": "GG-SSH-001",
      "form": "basename",
      "value": "id_rsa",
      "reason": "SSH private key"
    },
    {
      "id": "GG-SSH-002",
      "form": "basename",
      "value": "id_ed25519",
      "reason": "SSH private key"
    },
    {
      "id": "GG-SSH-003",
      "form": "basename",
      "value": "id_ecdsa",
      "reason": "SSH private key"
    },
    {
      "id": "GG-SSH-004",
      "form": "basename",
      "value": "id_dsa",
      "reason": "SSH private key"
    },
    {
      "id": "GG-SSH-005",
      "form": "dir",
      "value": ".ssh",
      "reason": "SSH material directory"
    },
    {
      "id": "GG-SSH-006",
      "form": "basename",
      "value": "authorized_keys",
      "reason": "SSH trust store — modification/read signals tampering or recon"
    },
    {
      "id": "GG-CLOUD-001",
      "form": "dir",
      "value": ".aws",
      "reason": "AWS credentials directory"
    },
    {
      "id": "GG-CLOUD-002",
      "form": "dir",
      "value": ".azure",
      "reason": "Azure credentials directory"
    },
    {
      "id": "GG-CLOUD-003",
      "form": "dirSegment2",
      "value": ".config/gcloud",
      "reason": "gcloud credentials directory"
    },
    {
      "id": "GG-CLOUD-004",
      "form": "dir",
      "value": ".kube",
      "reason": "kubernetes credentials directory"
    },
    {
      "id": "GG-CLOUD-005",
      "form": "dir",
      "value": ".gnupg",
      "reason": "GPG private keyring"
    },
    {
      "id": "GG-CLOUD-006",
      "form": "dirSegment2",
      "value": ".config/secrets",
      "reason": "dedicated secret store (incident remediation)"
    },
    {
      "id": "GG-CLOUD-007",
      "form": "basename",
      "value": "credentials",
      "withinDir": ".aws",
      "reason": "AWS shared credentials file"
    },
    {
      "id": "GG-IAC-001",
      "form": "suffix",
      "value": ".tfstate",
      "reason": "terraform state embeds secrets"
    },
    {
      "id": "GG-PKG-001",
      "form": "basename",
      "value": ".netrc",
      "reason": "plaintext machine credentials"
    },
    {
      "id": "GG-PKG-002",
      "form": "basename",
      "value": ".npmrc",
      "reason": "may carry _authToken"
    },
    {
      "id": "GG-PKG-003",
      "form": "basename",
      "value": ".pypirc",
      "reason": "PyPI credentials"
    },
    {
      "id": "GG-PKG-004",
      "form": "basename",
      "value": ".git-credentials",
      "reason": "git credential store"
    },
    {
      "id": "GG-MISC-001",
      "form": "basename",
      "value": "auth.json",
      "reason": "generic auth store"
    },
    {
      "id": "GG-PROC-001",
      "form": "withinDir",
      "value": "environ",
      "withinDir": "proc",
      "reason": "procfs process environment exposes secrets regardless of filename (scoped to /proc/ so docs/environ.md stays allowed)"
    }
  ],
  "askPaths": [
    {
      "id": "GG-RC-001",
      "form": "basename",
      "value": ".zshenv",
      "reason": "shell startup file — incident vector"
    },
    {
      "id": "GG-RC-002",
      "form": "basename",
      "value": ".zshrc",
      "reason": "shell startup file"
    },
    {
      "id": "GG-RC-003",
      "form": "basename",
      "value": ".zprofile",
      "reason": "shell startup file"
    },
    {
      "id": "GG-RC-004",
      "form": "basename",
      "value": ".zlogin",
      "reason": "shell startup file"
    },
    {
      "id": "GG-RC-005",
      "form": "basename",
      "value": ".bashrc",
      "reason": "shell startup file"
    },
    {
      "id": "GG-RC-006",
      "form": "basename",
      "value": ".bash_profile",
      "reason": "shell startup file"
    },
    {
      "id": "GG-RC-007",
      "form": "basename",
      "value": ".profile",
      "reason": "shell startup file"
    },
    {
      "id": "GG-AMB-011",
      "form": "contains",
      "value": "kubeconfig",
      "reason": "cluster credential file outside the standard ~/.kube directory"
    },
    {
      "id": "GG-PROC-002",
      "form": "withinDir",
      "value": "cmdline",
      "withinDir": "proc",
      "reason": "procfs command lines may embed secrets (scoped to /proc/)"
    }
  ],
  "exceptionPaths": [
    {
      "id": "GG-EXC-001",
      "form": "prefixName",
      "value": ".env.",
      "suffixes": [
        ".example",
        ".sample",
        ".template"
      ],
      "reason": "sanitized templates"
    },
    {
      "id": "GG-EXC-002",
      "form": "suffix",
      "value": ".pub",
      "reason": "public key material"
    },
    {
      "id": "GG-EXC-003",
      "form": "contains",
      "value": "tokenizer",
      "reason": "ML tokenizer configuration, not tokens"
    }
  ],
  "selfProtectPaths": [
    {
      "id": "GG-SLF-001",
      "form": "basename",
      "value": "security-guard.config.json",
      "effect": "deny",
      "reason": "guard runtime override file — writing it is how a guard gets silently weakened"
    },
    {
      "id": "GG-SLF-002",
      "form": "basename",
      "value": "health.json",
      "withinDir": "security-guard-for-opencode",
      "effect": "deny",
      "reason": "guard heartbeat file — a forged heartbeat disables fail-open detection"
    },
    {
      "id": "GG-SLF-003",
      "form": "basename",
      "value": "security-guard.js",
      "effect": "ask",
      "reason": "guard plugin source — legitimate during development, a tamper vector everywhere else"
    },
    {
      "id": "GG-SLF-004",
      "form": "basename",
      "value": "policy.jsonc",
      "effect": "ask",
      "reason": "policy source of truth"
    }
  ],
  "promoteAskToDenyIds": [],
  "envVarNamePattern": "(TOKEN|SECRET|PASSWORD|PASSWD|API_?KEY|PRIVATE_KEY|ACCESS_KEY|CLIENT_SECRET|CREDENTIAL|AUTH_|_AUTH|AUTH$)",
  "mcp": {
    "policyVersion": 1,
    "servers": {},
    "tools": [],
    "verbClasses": {
      "external-write": [
        "send",
        "post",
        "create",
        "write",
        "upload",
        "publish",
        "delete",
        "destroy",
        "remove",
        "update",
        "deploy",
        "invite",
        "email",
        "submit",
        "push",
        "modify"
      ],
      "read-only": [
        "get",
        "list",
        "read",
        "search",
        "describe",
        "view",
        "find"
      ],
      "credential-related": [
        "auth",
        "login",
        "token",
        "credential",
        "secret",
        "password",
        "apikey"
      ],
      "destructive": [
        "delete",
        "destroy",
        "drop",
        "wipe",
        "purge"
      ],
      "ambiguous": [
        "fetch",
        "query",
        "run",
        "exec",
        "invoke",
        "call",
        "apply",
        "sync"
      ]
    },
    "defaults": {
      "trusted": {
        "read-only": "allow",
        "local-data": "ask",
        "external-write": "ask",
        "network": "allow",
        "credential-related": "ask",
        "destructive": "deny",
        "unknown": "ask"
      },
      "restricted": {
        "read-only": "allow",
        "local-data": "ask",
        "external-write": "ask",
        "network": "ask",
        "credential-related": "ask",
        "destructive": "deny",
        "unknown": "ask"
      },
      "untrusted": {
        "read-only": "ask",
        "local-data": "deny",
        "external-write": "deny",
        "network": "deny",
        "credential-related": "deny",
        "destructive": "deny",
        "unknown": "ask"
      },
      "blocked": {
        "read-only": "deny",
        "local-data": "deny",
        "external-write": "deny",
        "network": "deny",
        "credential-related": "deny",
        "destructive": "deny",
        "unknown": "deny"
      },
      "unlisted-server": {
        "read-only": "ask",
        "local-data": "ask",
        "external-write": "ask",
        "network": "ask",
        "credential-related": "ask",
        "destructive": "deny",
        "unknown": "ask"
      }
    },
    "argRules": [
      {
        "id": "MCP-ARG-PATH-001",
        "match": "protected-path",
        "onTier": "deny",
        "effect": "block",
        "reason": "argument references high-confidence secret material"
      },
      {
        "id": "MCP-ARG-PATH-002",
        "match": "protected-path",
        "onTier": "ask",
        "effect": "block",
        "reason": "argument references approval-gated material; allowlist deliberately if legitimate"
      },
      {
        "id": "MCP-ARG-SEC-003",
        "match": "secret-var-name",
        "effect": "block",
        "reason": "argument appears to carry a secret-named value; route sanitized substitutes instead"
      }
    ],
    "provenance": {
      "enabled": false
    }
  }
})
// ==== END GENERATED GUARD POLICY ====

export const PLUGIN_VERSION = "0.4.1"
export const PLUGIN_ID = "security-guard"

// ============================================================================
// Pure engine — wildcard matching (OpenCode V2 permission dialect)
// ============================================================================

/**
 * Compile a V2 permission resource pattern.
 * Verified semantics: "*" matches zero or more chars including "/",
 * "?" matches exactly one char, everything else is literal, and the
 * pattern must cover the ENTIRE value. There is no "**".
 */
export function patternToRegExp(pattern) {
  const p = String(pattern)
  let rx = "^"
  // V2 convenience: a pattern ending in " *" also matches the value without
  // arguments (verified: docs/permissions, "git status *" matches bare
  // "git status").
  if (p.endsWith(" *")) {
    for (const ch of p.slice(0, -2)) {
      if (ch === "*") rx += "[\\s\\S]*"
      else if (ch === "?") rx += "[\\s\\S]"
      else rx += ch.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")
    }
    return new RegExp(rx + "(?:[\\s\\S]*)?$")
  }
  for (const ch of p) {
    if (ch === "*") rx += "[\\s\\S]*"
    else if (ch === "?") rx += "[\\s\\S]"
    else rx += ch.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")
  }
  return new RegExp(rx + "$")
}

/** True if the whole value matches the whole pattern. */
export function matchPattern(pattern, value) {
  return patternToRegExp(pattern).test(String(value))
}

/**
 * Evaluate an ordered rule list; LAST matching rule wins (verified V2
 * behavior). Returns the winning rule or null.
 */
export function lastMatchingRule(rules, pickAction, pickResource) {
  let winner = null
  for (const rule of rules) {
    if (rule.action !== "*" && rule.action !== pickAction) continue
    if (!matchPattern(rule.resource, pickResource)) continue
    winner = rule
  }
  return winner
}

// ============================================================================
// Pure engine — path classification
// ============================================================================

function basenameOf(p) {
  const parts = String(p).split("/")
  return parts[parts.length - 1] || p
}

function componentsOf(p) {
  return String(p).split("/").filter(Boolean)
}

function formMatches(form, path) {
  const base = basenameOf(path)
  switch (form.form ?? form.type) {
    case "basename":
      return base === form.value
    case "prefixName":
      return (
        base.startsWith(form.value) &&
        !(form.exceptSuffixes ?? []).some((s) => base.endsWith(s))
      )
    case "suffix":
      if (base.endsWith(form.value)) {
        // Multi-dot bare identifiers (>=3 dots, e.g. discvault.backup.b2.key)
        // are naming conventions, not file paths. Skip suffix matching so
        // rules like GG-KEY-002 (.key) don't flag BWS secret names, reverse-
        // domain identifiers, etc. Single- and double-dot names remain
        // protected (server.key, backup.key, my.bootstrap.pem).
        if (!path.includes("/") && !/^[.\/~]/.test(path)) {
          const dotCount = (base.match(/\./g) || []).length
          if (dotCount >= 3) return false
        }
        return true
      }
      return false
    case "contains":
      return String(path).toLowerCase().includes(String(form.value).toLowerCase())
    case "dir":
      return componentsOf(path).includes(form.value)
    case "dirSegment2":
      return String(path).includes("/" + form.value + "/") || String(path).startsWith(form.value + "/")
    case "withinDir": {
      const comps = componentsOf(path)
      return comps.includes(form.withinDir) && comps[comps.length - 1] === form.value
    }
    default:
      return false
  }
}

function exceptionApplies(exc, path) {
  const base = basenameOf(path)
  if (exc.suffixes) {
    return (
      base.startsWith(exc.value) &&
      exc.suffixes.some((s) => base.endsWith(s))
    )
  }
  return formMatches(exc, path)
}

/**
 * Classify a path candidate across multiple representations (e.g. the
 * original string plus its filesystem-resolved target) and return the WORST
 * tier. Pure: resolution itself is injected by the caller.
 */
export function classifyPathVariants(policy, candidates, opts = {}) {
  let worst = null
  const rank = { deny: 3, ask: 2, pass: 1 }
  for (const cand of candidates) {
    if (!cand) continue
    const cls = classifyPath(policy, cand, opts)
    if (!worst || rank[cls.tier] > rank[worst.tier]) {
      worst = { ...cls, resolvedFrom: candidates[0] !== cand ? cand : undefined }
    }
  }
  return worst ?? { tier: "pass" }
}

/**
 * Self-protection: the guard's own attack surface. Evaluated ONLY for
 * write-intent callers (edit/write tools, `>` redirections, file-management
 * shell verbs, MCP arguments) — reading `security-guard.js` is legitimate
 * review work, rewriting it (or its override file, or its heartbeat) is how an
 * agent disarms Layer 4.
 */
export function classifySelfProtect(policy, rawPath) {
  const p = normalizePathToken(rawPath).toLowerCase()
  if (!p) return null
  for (const rule of policy.selfProtectPaths ?? []) {
    if (formMatches({ form: rule.form, value: rule.value, withinDir: rule.withinDir }, p)) {
      return {
        tier: rule.effect === "ask" ? "ask" : "deny",
        ruleId: rule.id,
        category: "guard-self-protection",
        reason: rule.reason,
      }
    }
  }
  return null
}

/**
 * Basenames of protected-material references embedded in arbitrary text
 * (interpreter code, script bodies, quoted paths). Deny-tier hits only — the
 * caller decides whether that means ask or block.
 */
function embeddedProtectedHits(policy, text) {
  const out = []
  if (!text) return out
  EMBEDDED_PATH_RE.lastIndex = 0
  for (const m of String(text).matchAll(EMBEDDED_PATH_RE)) {
    const cls = classifyPath(policy, m[0])
    if (cls.tier === "deny") out.push(basenameOf(m[0]))
  }
  return out
}

/**
 * Classify a filesystem path against the compiled guard policy.
 * Order: hard denies win over exceptions (so a "tokenizer" file inside
 * ~/.aws stays denied); then profile-promoted asks; then asks; then allows;
 * then "pass" (= no guard opinion). Self-protection runs first but only when
 * the caller declares write intent (opts.mode === "write").
 *
 * Comparison is case-insensitive: macOS APFS and Windows NTFS are
 * case-insensitive by default, so `cat .ENV` opens `.env` there. Treating
 * case as a security signal on Linux costs a rare false positive
 * (`FOO.PEM` is a misnamed public cert) against a universal bypass class.
 */
export function classifyPath(policy, rawPath, opts = {}) {
  const p = normalizePathToken(rawPath).toLowerCase()
  if (!p) return { tier: "pass" }

  if (opts.mode === "write") {
    const self = classifySelfProtect(policy, p)
    if (self) return self
  }

  for (const rule of policy.denyPaths ?? []) {
    if (formMatches(rule, p)) {
      return { tier: "deny", ruleId: rule.id, category: "protected-path", reason: rule.reason }
    }
  }
  for (const exc of policy.exceptionPaths ?? []) {
    if (exceptionApplies(exc, p)) {
      return { tier: "pass", ruleId: exc.id, category: "safe-exception", reason: exc.reason }
    }
  }
  for (const rule of policy.askPaths ?? []) {
    if (formMatches(rule, p)) {
      const promote = (opts.promoteAskToDenyIds ?? policy.promoteAskToDenyIds ?? []).includes(rule.id)
      return promote
        ? { tier: "deny", ruleId: rule.id, category: "protected-path", reason: rule.reason + " (promoted by strict profile)" }
        : { tier: "ask", ruleId: rule.id, category: "approval-required", reason: rule.reason }
    }
  }
  return { tier: "pass" }
}

// ============================================================================
// Pure engine — shell command analysis
// ============================================================================

const READER_VERBS = new Set([
  "cat", "head", "tail", "less", "more", "nl", "strings", "od",
  "hexdump", "xxd", "base64", "basenc", "gpg", "openssl",
  "grep", "egrep", "fgrep", "rg", "ack", "ag",
  "awk", "gawk", "sed", "jq", "yq", "cut", "sort", "uniq", "wc", "diff", "vim", "vi", "nano", "code",
  // E9 curated content viewers (ask-tier now asks instead of staying silent;
  // metadata-only verbs like ls/stat/file/realpath deliberately stay out so
  // `ls ~/.zshenv` remains silent — see NEG-FP-028).
  "bat", "batcat", "delta", "tac", "rev",
])
const TRANSFORMER_VERBS = new Set(["base64", "base32", "xxd", "od", "hexdump", "openssl", "gpg", "iconv", "uudecode", "uuencode", "bzip2", "gzip", "zstd", "xz"])
const INTERPRETERS = new Set([
  "python", "python3", "python3.11", "python3.12", "node", "deno", "bun",
  "ruby", "perl", "php", "php8", "lua", "lua5.1", "osascript", "osacompile", "rscript", "jshell",
  // shell-code execution counts as interpretation (sourcing an RC file runs
  // whatever it exports — the incident vector).
  "source", ".",
])
const SENDER_VERBS = new Set([
  "curl", "wget", "wget2", "nc", "ncat", "netcat", "scp", "sftp", "ftp",
  "rsync", "telnet", "socat", "gh", "gsutil", "aws", "az", "gcloud", "huggingface-cli",
])
const ARCHIVE_CREATORS = new Set(["tar", "zip", "jar", "7z", "7za", "ditto"])
const GIT_CONTENT_SUBCOMMANDS = new Set(["show", "cat-file", "archive", "log", "diff", "whatchanged"])
// Re-entry wrappers: programs whose ARGUMENTS are themselves a command. Without
// recursive analysis these defeat every verb-class rule, because the outer verb
// (`bash`, `eval`, `env`, `sudo`, …) belongs to no class:
//   bash -c 'echo $AWS_SECRET_ACCESS_KEY'   -> printer check never sees `echo`
//   env printenv                            -> env-dump check never fires
const SHELL_REEXEC_VERBS = new Set(["sh", "bash", "zsh", "dash", "ksh", "fish", "csh", "tcsh", "ash"])
const COMMAND_PREFIX_VERBS = new Set([
  "eval", "exec", "env", "command", "builtin", "sudo", "doas", "nohup", "setsid",
  "time", "nice", "stdbuf", "choom", "ionice", "chronic", "runuser", "su",
  "chpst", "supervise", "watch", "entr", "chroot", "unshare", "nsenter",
])
// Flags of prefix wrappers that consume the FOLLOWING token as their own value,
// so it is not mistaken for the wrapped command name.
const PREFIX_FLAG_WITH_VALUE = new Set(["-u", "-g", "-U", "-n", "-t", "-i", "-o", "-e", "-p", "-s", "-l", "-r", "-C", "-c", "-a", "-b", "-d", "-f", "-k", "-w"])
const ENV_DUMP_VERBS = new Set(["env", "printenv", "alias"])
const PRINTERS = new Set(["echo", "printf", "puts", "print", "logger", "tee"])
// Verbs whose purpose is creating/moving/managing files, not reading them.
// The conservative generic catch (GGR-OTHER-001) deliberately skips these so
// ordinary workflows (cp .env.example .env, ssh-keygen -f id_ed25519,
// chmod 600 .env) stay usable. Residual risk documented in docs/limitations.md.
const FILE_MANAGEMENT_VERBS = new Set([
  "cp", "mv", "ln", "touch", "mkdir", "rmdir", "rm", "chmod", "chown", "chgrp",
  "install", "rsync_local_placeholder", "ssh-keygen", "gpgsplit", "shred",
])
// Verbs that can OVERWRITE a file. Used only by the self-protection check
// (writes to the guard's own files), never by the secret-path rules — so
// `cp .env.example .env` keeps working. Split by whether their non-flag
// arguments are all destinations (rm/touch/tee) or source…destination
// (cp/mv/install, where only the LAST path is being written).
const WRITE_CAPABLE_VERBS = new Set(["rm", "tee", "touch", "dd", "truncate", "shred", "ln"])
// mv additionally UNLINKS its sources (a removal-shaped tamper vector).
const MOVE_LIKE_VERBS = new Set(["mv"])
const COPY_LIKE_VERBS = new Set(["cp", "install", "rsync"])
// For openssl, only classify tokens that follow explicit INPUT flags —
// bare positionals are usually outputs (-keyout/-out), which keeps
// certificate/key GENERATION workflows working.
const OPENSSL_INPUT_FLAGS = new Set(["-in", "-inkey", "-CAkey", "-certfile", "-prverify", "-sign", "-decrypt", "-verify"])
// E1 glob/pattern expansion (ask, exemplar-matched — never block).
// The shell expands `*?[{` before the kernel opens files, so `cat .e*`
// opens `.env` while the literal classifier sees no signal. Test glob-bearing
// tokens as patterns against canonical protected exemplars; ask on match.
// `*.log`/`*.js` match no exemplar and stay silent (NEG-FP-023).
const GLOB_EXEMPLARS = [
  ".env", ".env.production", "server.key", "server.pem",
  "id_rsa", "id_ed25519", "id_ecdsa",
  ".ssh/config", ".aws/credentials", "terraform.tfstate",
  ".npmrc", ".netrc", ".pypirc",
  ".zshenv", ".zshrc", ".bashrc", "prod.kubeconfig",
]
function globToRegExpSrc(glob) {
  let out = ""
  for (let i = 0; i < glob.length; i++) {
    const ch = glob[i]
    if (ch === "*") out += ".*"
    else if (ch === "?") out += "."
    else if (ch === "{") out += "(?:"
    else if (ch === "}") out += ")"
    else if (ch === ",") out += "|"
    else if (ch === "[") {
      // Passthrough bracket class verbatim to the closing bracket when valid;
      // otherwise treat the bracket literally.
      const end = glob.indexOf("]", i + 1)
      if (end !== -1) {
        out += glob.slice(i, end + 1)
        i = end
      } else {
        out += "\\["
      }
    } else if (/[.+^${}()|\\]/.test(ch)) out += "\\" + ch
    else out += ch
  }
  return "^" + out + "$"
}
function globMayMatchProtected(rawPattern) {
  const pat = shellDequote(String(rawPattern ?? "").trim()).toLowerCase()
  if (!pat || !/[*?{\[]/.test(pat)) return null
  // Skip flag-looking tokens (`--include=*.log` is handled via its value
  // below; bare `--flag` never matches an exemplar anyway).
  let full = null
  try {
    full = new RegExp(globToRegExpSrc(pat), "i")
  } catch {
    return null
  }
  const basePat = basenameOf(pat)
  let baseRe = null
  try {
    baseRe = new RegExp(globToRegExpSrc(basePat), "i")
  } catch {
    baseRe = null
  }
  for (const ex of GLOB_EXEMPLARS) {
    if (full.test(ex)) return ex
    if (baseRe && baseRe.test(basenameOf(ex))) return ex
  }
  return null
}
// Verbs whose glob operands may expand to protected material. File-management
// verbs (cp/chmod/…) are deliberately excluded so `chmod 600 .e*`-style
// hardening and `cp .env.example .env` workflows stay silent; staging via
// `cp` glob remains a documented cross-call residual (E2).
function globAskAppliesForVerb(verb) {
  if (FILE_MANAGEMENT_VERBS.has(verb)) return false
  return true
}
// Scan segments for embedded path-like substrings (catches paths inside
// quoted interpreter code such as python3 -c 'open(".env").read()').
// The trailing lookahead prevents partial extraction like ".env" out of
// ".env.example" (dot counts as a continuation character here).
const EMBEDDED_PATH_RE =
  /[\w.\/~@-]*\.(?:env|pem|key|p12|pfx|jks|keystore|tfstate|netrc|npmrc|pypirc|pub)(?![\w.-])|[\w.\/~@-]*(?:id_rsa|id_ed25519|id_ecdsa|id_dsa|authorized_keys|git-credentials|auth\.json|kubeconfig)(?![\w.-])|[\w.\/~@-]*\.(?:zshenv|zshrc|zprofile|zlogin|bashrc|bash_profile|bash_login|kshrc)(?![\w.-])|\.[A-Za-z0-9@_-]*(?:ssh|aws|azure|kube|gnupg|config[/\\]secrets)[\w.\/@-]*/gi

/** Split a command into top-level segments on ; && || | and newlines,
 *  respecting single/double quotes and $()/backticks shallowly. */
export function splitSegments(command) {
  const segs = []
  let cur = ""
  let quote = null
  let depth = 0 // $( ) nesting
  for (let i = 0; i < command.length; i++) {
    const ch = command[i]
    if (quote) {
      cur += ch
      if (ch === quote) quote = null
      continue
    }
    if (ch === "'" || ch === '"') {
      quote = ch
      cur += ch
      continue
    }
    if (ch === "\\" && i + 1 < command.length) {
      cur += ch + command[i + 1]
      i++
      continue
    }
    if (ch === "$" && command[i + 1] === "(") {
      depth++
      cur += ch
      continue
    }
    if (ch === ")" && depth > 0) {
      depth--
      cur += ch
      continue
    }
    if (depth === 0 && (ch === ";" || ch === "|" || ch === "\n" || ch === "&")) {
      if ((ch === "|" || ch === "&") && command[i + 1] === ch) i++
      segs.push(cur)
      cur = ""
      continue
    }
    cur += ch
  }
  segs.push(cur)
  return segs.map((s) => s.trim()).filter(Boolean)
}

const OPERATOR_RE = /[;|\n]/

/** Tokenize one segment, respecting quotes. Returns array of raw tokens. */
export function tokenize(segment) {
  const toks = []
  let cur = ""
  let quote = null
  for (let i = 0; i < segment.length; i++) {
    const ch = segment[i]
    if (quote) {
      cur += ch
      if (ch === quote) quote = null
      continue
    }
    if (ch === "'" || ch === '"') {
      quote = ch
      cur += ch
      continue
    }
    if (/\s/.test(ch)) {
      if (cur) toks.push(cur)
      cur = ""
      continue
    }
    if (OPERATOR_RE.test(ch)) {
      if (cur) toks.push(cur)
      cur = ""
      continue
    }
    cur += ch
  }
  if (cur) toks.push(cur)
  return toks
}

/**
 * Remove every shell quoting artifact from a word, the way the kernel sees it:
 * quote characters are metacharacters (not content) and backslash escapes one
 * character. Without this, `cat .e''nv`, `cat .e"nv"` and `cat .e\nv` all open
 * `.env` while the guard previously classified a different string.
 *
 * Windows-style paths (drive letters, UNC) keep their backslashes: there
 * shell-escape semantics do not apply on this platform's threat surface.
 */
export function shellDequote(tok) {
  const s = String(tok)
  if (/^[A-Za-z]:[\\/]|^\\\\/.test(s)) return s.replace(/['"]/g, "")
  return s.replace(/\\(.)/gs, "$1").replace(/['"]/g, "")
}

/** Strip surrounding quotes and a trailing/leading redirection char. */
export function normalizePathToken(tok) {
  if (!tok) return ""
  let t = shellDequote(String(tok).trim())
  t = t.replace(/^[<>]+/, "").trim()
  // curl-style inline-file syntax (--data @file, -F name=@file)
  t = t.replace(/^.*?=@/, "@")
  t = t.replace(/^@/, "")
  if (!t) return ""
  return t
}

function unquote(s) {
  return String(s).replace(/^['"]|['"]$/g, "")
}

function isAssignment(tok) {
  return /^[A-Za-z_][A-Za-z0-9_]*=/.test(tok) && !tok.includes("==")
}

function assignmentName(tok) {
  return tok.slice(0, tok.indexOf("="))
}

function assignmentValue(tok) {
  return unquote(tok.slice(tok.indexOf("=") + 1))
}

function looksLikePath(tok) {
  if (/^(\.|\/|~)/.test(tok)) return true
  if (tok.includes("/")) return true
  if (
    /^[A-Za-z0-9_.@-]+$/.test(tok) &&
    /\.(env|pem|key|p12|pfx|jks|keystore|tfstate|pub)$/i.test(tok) &&
    // Multi-dot bare identifiers (≥3 dots, e.g. discvault.backup.b2.key) are
    // naming conventions (BWS, reverse-domain, Java), not file paths. Single-
    // and double-dot names (server.key, backup.key) remain valid path shapes.
    ((tok.match(/\./g) || []).length <= 2)
  ) return true
  if (/^\.(env|netrc|npmrc|pypirc|git-credentials|zsh|bash)/i.test(tok)) return true
  return false
}

function varRefs(tok) {
  // $NAME, $!NAME, ${NAME}, ${!NAME} and bash parameter-expansion operators:
  // ${N:-d}, ${N:=d}, ${N:?e}, ${N:+a}, ${N#p}, ${N%p}, ${N/p/r}, ${N^}, ${N,},
  // ${N:o:l}, ${#N} (length), ${N[@]} — all still expand (or derive) from N,
  // so extract N and let the secret-name test decide. Non-secret names
  // (${PATH:-/usr/bin}) stay silent via isSecretEnvName.
  const out = []
  for (const m of String(tok).matchAll(/\$\{\s*[#!]?\s*([A-Za-z_][A-Za-z0-9_]*)(?![A-Za-z0-9_])|\$!([A-Za-z_][A-Za-z0-9_]*)|\$([A-Za-z_][A-Za-z0-9_]*)/g)) {
    out.push(m[1] ?? m[2] ?? m[3])
  }
  return out
}

/** Extract inner text of $( ... ) and all ` ... ` substitutions. */
function substitutions(segment) {
  const out = []
  let i = 0
  const s = segment
  while ((i = s.indexOf("$(", i)) !== -1) {
    let depth = 0
    let j = i + 1
    for (; j < s.length; j++) {
      if (s[j] === "(") depth++
      else if (s[j] === ")") {
        depth--
        if (depth === 0) break
      }
    }
    out.push(s.slice(i + 2, j))
    i = j
  }
  // Every backtick pair, not just the first.
  for (let bt = s.indexOf("`"); bt !== -1; ) {
    const end = s.indexOf("`", bt + 1)
    if (end === -1) break
    out.push(s.slice(bt + 1, end))
    bt = s.indexOf("`", end + 1)
  }
  return out
}

const _rxCache = new WeakMap()

function envVarNamesFromPolicy(policy) {
  if (!_rxCache.has(policy)) {
    _rxCache.set(policy, new RegExp(policy.envVarNamePattern ?? "(?!x)x", "i"))
  }
  return _rxCache.get(policy)
}

function isSecretEnvName(policy, name) {
  return envVarNamesFromPolicy(policy).test(name)
}

// ============================================================================
// E2 session file-copy provenance (pure helpers; adapter owns the session).
// Same-command `cp` tracking already lives inside analyzeCommand; these let
// the adapter persist it across tool calls without reimplementing parsing.
// ============================================================================

const COPY_TRACK_VERBS = new Set(["cp", "install", "mv", "ln"])

/** Bounded FIFO store: normalized dest -> {tier, ruleId, token}. */
export function createCopyProvenanceStore(opts = {}) {
  const maxEntries = opts.maxEntries ?? 32
  const map = new Map() // normLower -> {tier, ruleId, token}
  const norm = (t) => {
    let n = normalizePathToken(String(t ?? "")).toLowerCase()
    n = n.replace(/^\.\/+/, "")
    return n
  }
  return {
    note(destToken, tier, ruleId) {
      const key = norm(destToken)
      if (!key || tier === "pass") return null
      if (map.has(key)) map.delete(key) // refresh recency
      map.set(key, { tier, ruleId, token: normalizePathToken(String(destToken)) })
      while (map.size > maxEntries) {
        const oldest = map.keys().next().value
        map.delete(oldest)
      }
      return key
    },
    lookup(token) {
      const hit = map.get(norm(token))
      return hit ? { ...hit } : null
    },
    remove(token) {
      return map.delete(norm(token))
    },
    entries() {
      return [...map.values()].map((v) => ({ ...v }))
    },
    size() {
      return map.size
    },
  }
}

/**
 * Detect new copy-tracking entries a *successful* shell command would create.
 * Mirrors analyzeCommand's same-command logic (first deny/ask source via
 * classifyToken, last clean dest via classifyPath) but returns data instead
 * of a verdict. Call from execute.after only — never pre-execution — so
 * denied/unapproved copies are never recorded.
 */
export function detectCopyTracks(policy, command, opts = {}) {
  const out = []
  const promote = opts.promoteAskToDenyIds ?? policy.promoteAskToDenyIds ?? []
  for (const rawSeg of splitSegments(String(command ?? ""))) {
    const toks = tokenize(rawSeg).map((t) => (isAssignment(t) ? t : unquote(t)))
    if (!toks.length) continue
    let idx = 0
    while (idx < toks.length && isAssignment(toks[idx]) && !toks[idx].includes("(")) idx++
    const words = toks.slice(idx)
    if (!words.length) continue
    const verb = basenameOf(words[0]).toLowerCase()
    if (!COPY_TRACK_VERBS.has(verb)) continue
    // Find first deny/ask source (same shape gates as analyzeCommand).
    let srcHit = null
    let srcIdx = -1
    for (let wi = 1; wi < words.length; wi++) {
      const n = normalizePathToken(words[wi])
      if (!n || !looksLikePath(n)) continue
      const cls = classifyPath(policy, n, { promoteAskToDenyIds: promote })
      if (cls.tier !== "pass") {
        // Resolve symlinks when available so `cp link /tmp/x` tracks the
        // real source tier.
        let best = cls
        if (typeof opts.resolvePath === "function") {
          try {
            const real = opts.resolvePath(n)
            if (real && real !== n) {
              const rcls = classifyPath(policy, real, { promoteAskToDenyIds: promote })
              if (rcls.tier !== "pass" && rcls.tier === "deny") best = rcls
            }
          } catch {}
        }
        srcHit = best
        srcIdx = wi
        break
      }
    }
    if (!srcHit) continue
    for (let wi = words.length - 1; wi > srcIdx; wi--) {
      const n = normalizePathToken(words[wi])
      if (!n || !looksLikePath(n)) continue
      if (classifyPath(policy, n).tier === "pass") {
        out.push({ dest: n, tier: srcHit.tier, ruleId: srcHit.ruleId })
        break
      }
    }
  }
  return out
}

/**
 * Detect tracking invalidation a *successful* command causes: `rm` of a
 * tracked dest, or overwrite of a tracked dest from a clean source
 * (`cp notes.txt /tmp/x`). Returns normalized dest tokens to drop.
 */
export function detectCopyClears(command, trackedNorms) {
  const drop = []
  if (!trackedNorms?.length) return drop
  const set = new Set(trackedNorms.map((t) => normalizePathToken(String(t)).toLowerCase().replace(/^\.\/+/, "")))
  for (const rawSeg of splitSegments(String(command ?? ""))) {
    const toks = tokenize(rawSeg).map((t) => (isAssignment(t) ? t : unquote(t)))
    if (!toks.length) continue
    let idx = 0
    while (idx < toks.length && isAssignment(toks[idx]) && !toks[idx].includes("(")) idx++
    const words = toks.slice(idx)
    if (!words.length) continue
    const verb = basenameOf(words[0]).toLowerCase()
    for (const w of words.slice(1)) {
      const n = normalizePathToken(String(w)).toLowerCase().replace(/^\.\/+/, "")
      if (n && set.has(n) && (verb === "rm" || verb === "shred")) drop.push(n)
    }
  }
  return [...new Set(drop)]
}

/**
 * Extract the inner command string carried by a re-entry wrapper invocation.
 * Returns "" when the wrapper has no analyzable payload (e.g. plain `make`).
 */
export function wrapperInnerCommand(verb, args) {
  const clean = (s) => shellDequote(s)
  if (SHELL_REEXEC_VERBS.has(verb)) {
    // `-c` may be bundled with other single-letter options (-fc, -lc, -ic, -xc).
    for (let i = 0; i < args.length; i++) {
      const a = clean(args[i])
      if (/^-[A-Za-z]*c$/.test(a)) return i + 1 < args.length ? clean(args[i + 1]) : ""
    }
    return ""
  }
  if (verb === "eval" || verb === "exec") {
    // eval concatenates ALL its arguments into one command line.
    return args.map(clean).join(" ")
  }
  if (verb === "xargs") {
    // xargs builds a command from its arguments plus stdin; only the visible
    // part can be analyzed (`xargs -a list cat` stays a documented blind spot).
    const rest = []
    for (let i = 0; i < args.length; i++) {
      const a = clean(args[i])
      if (a.startsWith("-")) {
        if (/^-[A-Za-z]$/.test(a) && PREFIX_FLAG_WITH_VALUE.has(a)) i++
        continue
      }
      rest.push(a)
    }
    return rest.join(" ")
  }
  if (COMMAND_PREFIX_VERBS.has(verb)) {
    const rest = []
    let i = 0
    // Leading VAR=value assignments belong to env(1)'s environment, not its command.
    for (; i < args.length; i++) {
      const a = clean(args[i])
      if (isAssignment(a)) continue
      if (a === "--") {
        i++
        break
      }
      if (a.startsWith("-")) {
        if (/^-[A-Za-z]$/.test(a) && PREFIX_FLAG_WITH_VALUE.has(a)) i++
        continue
      }
      break
    }
    for (; i < args.length; i++) rest.push(clean(args[i]))
    return rest.join(" ")
  }
  return ""
}

/** Split a `git` argument list, skipping global flags, into its subcommand. */
function gitSubcommand(args) {
  const valueFlags = new Set(["-C", "-c", "--git-dir", "--work-tree", "--namespace", "--exec-path", "--super-prefix"])
  for (let i = 0; i < args.length; i++) {
    const a = String(args[i])
    if (a === "--") return String(args[i + 1] ?? "")
    if (valueFlags.has(a)) {
      i++
      continue
    }
    if (a.startsWith("-")) continue
    return a
  }
  return ""
}

/**
 * Analyze one command string against the policy.
 * Returns null (no opinion) or {decision:"block"|"ask", ruleId, category, reason, matched}.
 * `matched` contains a SAFE excerpt: a basename or variable NAME — never
 * values, never full paths into the user's home, never raw command text.
 * opts._depth bounds re-entry wrapper recursion (wrapper payloads are analyzed
 * as commands, which can themselves contain wrappers).
 */
export function analyzeCommand(policy, command, opts = {}) {
  const depth = opts._depth ?? 0
  const promote = opts.promoteAskToDenyIds ?? policy.promoteAskToDenyIds ?? []
  const assignments = {} // simple single-level indirection support
  // E2 session provenance: seed per-command tracking with cross-call entries
  // supplied by the adapter (`opts.knownCopies`). Same-command `cp` legs
  // append below without mutating the caller's array.
  const copies = [...(opts.knownCopies ?? [])] // temp-copy provenance: cp .env /tmp/x => /tmp/x inherits .env's tier

  // Classify a token, falling back to inherited tiers from tracked copies.
  // `mode` ("write" for segments that create/replace files) enables the
  // guard's self-protection rules.
  const classifyToken = (tok, mode = opts.mode) => {
    const cls = classifyPath(policy, tok, { promoteAskToDenyIds: promote, mode })
    if (cls.tier !== "pass") return cls
    // Symlink/alias defense: a benign-named path may resolve onto protected
    // material. Reclassify the resolved target when a resolver is provided.
    if (typeof opts.resolvePath === "function") {
      try {
        const real = opts.resolvePath(tok)
        if (real && real !== tok) {
          const rcls = classifyPath(policy, real, { promoteAskToDenyIds: promote, mode })
          if (rcls.tier !== "pass") return { ...rcls, viaResolution: true }
        }
      } catch {}
    }
    const base = basenameOf(tok)
    const c = copies.find((c) => c.token === tok || basenameOf(c.token) === base)
    if (c) return { tier: c.tier, ruleId: c.ruleId, category: "protected-path", reason: "temporary copy of protected material" }
    // E2 cross-call fallback: exact normalized match against session-tracked
    // dests (stricter than the basename fallback above to avoid flagging
    // unrelated same-named files in other directories).
    if (Array.isArray(opts.knownCopies)) {
      const norm = normalizePathToken(String(tok)).toLowerCase()
      const hit = opts.knownCopies.find((k) => normalizePathToken(String(k.token ?? "")).toLowerCase() === norm)
      if (hit) return { tier: hit.tier, ruleId: hit.ruleId, category: "protected-path", reason: "temporary copy of protected material" }
    }
    return cls
  }

  const segments = splitSegments(command)
  for (let sIdx = 0; sIdx < segments.length; sIdx++) {
    const rawSeg = segments[sIdx]

    // Recurse into command/process substitutions first.
    for (const sub of substitutions(rawSeg)) {
      const r = analyzeCommand(policy, sub, { ...opts, _depth: depth + 1 })
      if (r) {
        return { ...r, category: r.category + "+substitution" }
      }
    }

    const toks = tokenize(rawSeg).map((t) => (isAssignment(t) ? t : unquote(t)))
    if (!toks.length) continue

    // Track assignments for indirection (VAR=.env or VAR=$(cat .env)).
    for (const t of toks) {
      if (isAssignment(t)) assignments[assignmentName(t)] = assignmentValue(t)
    }

    // Leading assignments do not change the verb.
    let idx = 0
    while (idx < toks.length && isAssignment(toks[idx]) && !toks[idx].includes("(")) idx++
    const words = toks.slice(idx)
    if (!words.length) continue

    const verb = basenameOf(words[0]).toLowerCase()
    const args = words.slice(1)

    // ---- re-entry wrappers: analyze the payload as a command ----------------
    if (depth < 4) {
      const inner = wrapperInnerCommand(verb, args)
      if (inner && inner.trim() !== String(rawSeg).trim()) {
        const r = analyzeCommand(policy, inner, { ...opts, _depth: depth + 1 })
        if (r) return { ...r, category: r.category + "+wrapper" }
      }
    }

    // ---- alias definitions: the VALUE becomes a command on every later use ---
    // Closes the single-pass blind spot for `alias rc='cat .zshenv'` by
    // analyzing the alias body at definition time. (`unalias` and multi-line
    // function bodies remain invisible — documented residual.)
    if (verb === "alias") {
      for (const a of args) {
        const body = shellDequote(String(a))
        if (!isAssignment(body) || body.startsWith("-")) continue
        const payload = body.slice(body.indexOf("=") + 1)
        if (!payload.trim()) continue
        const r = analyzeCommand(policy, payload, { ...opts, _depth: depth + 1 })
        if (r) return { ...r, category: r.category + "+alias-definition" }
      }
    }

    // ---- environment dumps -------------------------------------------------
    if (ENV_DUMP_VERBS.has(verb) && args.length === 0) {
      return {
        decision: "block", ruleId: "GGE-DUMP-001", category: "environment-dump",
        reason: "environment dumping exposes every secret in the process environment",
        matched: verb,
      }
    }
    if ((verb === "set" || verb === "declare" || verb === "typeset" || verb === "local" || verb === "readonly" || verb === "export")) {
      const dashP = args.some((a) => a === "-p")
      const secretArgs = args.filter((a) => !a.startsWith("-")).filter((a) => isSecretEnvName(policy, assignmentName(a + "=")))
      if (verb === "set" && args.length === 0) {
        return blockDump("GGE-DUMP-002", "set")
      }
      if (dashP && args.every((a) => a === "-p" || /^-\w+$/.test(a))) {
        return blockDump("GGE-DUMP-003", verb)
      }
      // Bare `export` / `declare` / `typeset` / `readonly` / `local` with no
      // args dump the environment (like `set`); flag-only forms (`declare -r`)
      // do too. Assignment (`FOO=bar`) and name-only (`export FOO`) forms
      // define rather than dump and must stay silent (E7 FP boundary).
      if (
        (verb === "export" || verb === "declare" || verb === "typeset" || verb === "readonly" || verb === "local") &&
        args.length === 0
      ) {
        return blockDump("GGE-DUMP-004", verb)
      }
      {
        const nonFlag = args.filter((a) => !String(a).startsWith("-"))
        const hasValueCarrying = nonFlag.some((a) => String(a).includes("=") || isAssignment(String(a)))
        if (
          (verb === "declare" || verb === "typeset" || verb === "readonly" || verb === "local" || verb === "export") &&
          args.length > 0 &&
          nonFlag.length === 0 &&
          !hasValueCarrying
        ) {
          return blockDump("GGE-DUMP-005", verb)
        }
      }
      if (secretArgs.length && (dashP || verb === "printenv")) {
        return {
          decision: "block", ruleId: "GGE-VAR-001", category: "secret-variable-display",
          reason: "prints the value of a secret-named variable",
          matched: secretArgs[0],
        }
      }
    }
    // `compgen -e` / `-v` / `-A variable` list environment variable NAMES,
    // enabling targeted dumps; `compgen -c` (commands) stays silent.
    if (verb === "compgen") {
      const flat = args.map((a) => shellDequote(String(a)))
      if (flat.some((a) => a === "-e" || a === "-v")) {
        return blockDump("GGE-DUMP-006", "compgen")
      }
      for (let i = 0; i < flat.length; i++) {
        if (flat[i] === "-A" && String(flat[i + 1] ?? "").toLowerCase() === "variable") {
          return blockDump("GGE-DUMP-006", "compgen")
        }
      }
    }
    if (verb === "printenv") {
      const named = args.filter((a) => !a.startsWith("-"))
      const secret = named.find((a) => isSecretEnvName(policy, a))
      if (named.length === 0) return blockDump("GGE-DUMP-001", "printenv")
      if (secret) {
        return {
          decision: "block", ruleId: "GGE-VAR-002", category: "secret-variable-display",
          reason: "prints the value of a secret-named variable",
          matched: secret,
        }
      }
    }

    // ---- interpreters touching the process environment ----------------------
    if (/environ|getenv|process\.env/.test(rawSeg)) {
      const interpish =
        INTERPRETERS.has(verb) ||
        /\b(python3?|node|ruby|perl|php|deno|bun)\b/.test(rawSeg)
      if (interpish) {
        const candidates = rawSeg.match(/\b[A-Z][A-Z0-9_]{2,}\b/g) ?? []
        const secretLiteral = candidates.find((n) => isSecretEnvName(policy, n))
        if (secretLiteral) {
          return {
            decision: "block", ruleId: "GGE-VAR-020", category: "environment-dump",
            reason: "interpreter code reads a secret-named environment variable",
            matched: secretLiteral,
          }
        }
        return {
          decision: "ask", ruleId: "GGE-DUMP-010", category: "environment-dump",
          reason: "interpreter code accesses the process environment; approve only if it cannot print secret values",
          matched: verb,
        }
      }
    }

    // ---- secret-named variables --------------------------------------------
    const referencedVars = []
    for (const t of words) referencedVars.push(...varRefs(t))
    const secretRef = referencedVars.find((v) => isSecretEnvName(policy, v))
    if (secretRef) {
      if (PRINTERS.has(verb)) {
        return {
          decision: "block", ruleId: "GGE-VAR-010", category: "secret-variable-display",
          reason: "displays a secret-named variable's value into the transcript",
          matched: secretRef,
        }
      }
      if (SENDER_VERBS.has(verb)) {
        return {
          decision: "ask", ruleId: "GGE-VAR-011", category: "secret-variable-send",
          reason: "sends a secret-named variable toward a network destination; legitimate authenticated API calls also look like this — approve only if expected",
          matched: secretRef,
        }
      }
      // Non-printing/non-sending use (e.g. passing to build tools): allow.
    }

    // ---- path classification over tokens (incl. chained indirection) --------
    const classified = []
    const seenTokens = new Set()
    // Resolve an assignment value, following name→name chains (bounded):
    // covers plain multi-hop (`A=B; B=.env; cat $A`) and bash indirect
    // expansion (`A=B; B=.env; cat ${!A}`) which both expand to protected names.
    const resolveAssigned = (name) => {
      let val = assignments[name]
      let hops = 0
      while (val && /^[A-Za-z_][A-Za-z0-9_]*$/.test(val) && assignments[val] && hops++ < 4) {
        val = assignments[val]
      }
      return val
    }
    const considerToken = (t, opts2 = {}, cDepth = 0) => {
      if (cDepth > 5) return
      for (const v of varRefs(t)) {
        const val = resolveAssigned(v)
        if (val) considerToken(val, opts2, cDepth + 1)
      }
      // $IFS used AS a word separator: `cat$IFS.env` runs `cat .env`.
      if (/\$IFS\}?$/.test(t) || t.includes("$IFS")) {
        for (const piece of t.split(/\$\{?IFS\}?/)) {
          if (piece) considerToken(piece, opts2, cDepth + 1)
        }
        return
      }
      let cand = normalizePathToken(t)
      if (opts2.opensslInputOnly) {
        // handled by caller via flag pairs; skip generic consideration
        return
      }
      cand = cand.replace(/^\$\{\s*[#!]?\s*[A-Za-z_][A-Za-z0-9_]*[^}]*\}?/, "")
      if (!cand || /\$\{\s*[#!]?\s*[A-Za-z_]/.test(cand)) return
      // Symlink/alias defense: when a resolver is available, benign-named
      // tokens may still resolve onto protected files, so attempt resolution
      // BEFORE the shape gates reject the token.
      let resolvedVariant = null
      if (typeof opts.resolvePath === "function") {
        try {
          const real = opts.resolvePath(cand)
          if (real && real !== cand) resolvedVariant = real
        } catch {}
      }
      if (!looksLikePath(cand) && !EMBEDDED_PATH_CANDIDATE(cand)) {
        if (!resolvedVariant) return
        // Only the resolved target mattered; classify that.
        if (seenTokens.has(cand)) return
        seenTokens.add(cand)
        const cls = classifyToken(cand)
        if (cls.tier !== "pass") classified.push({ token: basenameOf(cand), ...cls })
        return
      }
      if (seenTokens.has(cand)) return
      seenTokens.add(cand)
      const cls = classifyToken(cand)
      if (cls.tier !== "pass") classified.push({ token: basenameOf(cand), ...cls })
    }
    const EMBEDDED_PATH_CANDIDATE = (s) => {
      EMBEDDED_PATH_RE.lastIndex = 0
      return EMBEDDED_PATH_RE.test(s)
    }

    if (verb === "openssl") {
      for (let i = 0; i < args.length; i++) {
        if (OPENSSL_INPUT_FLAGS.has(args[i]) && args[i + 1]) {
          const cls = classifyToken(normalizePathToken(args[i + 1]))
          if (cls.tier !== "pass") classified.push({ token: basenameOf(normalizePathToken(args[i + 1])), ...cls })
        }
      }
    } else {
      for (const t of words) considerToken(t)
    }
    // Embedded scan across the raw segment (interpreter code, quoted paths),
    // skipped for openssl (flag-scoped above prevents -keyout false positives).
    if (verb !== "openssl") {
      EMBEDDED_PATH_RE.lastIndex = 0
      for (const m of rawSeg.matchAll(EMBEDDED_PATH_RE)) {
        const cls = classifyToken(m[0])
        if (cls.tier !== "pass") classified.push({ token: basenameOf(m[0]), ...cls })
      }
    }

    // Explicit credential-store flags (--kubeconfig file ...) point the tool
    // at non-default cluster credentials; classify their values directly.
    for (let i = 0; i < args.length; i++) {
      const a = args[i]
      let flagVal = null
      if (a === "--kubeconfig" && args[i + 1]) flagVal = args[i + 1]
      else if (typeof a === "string" && a.startsWith("--kubeconfig=")) flagVal = a.slice(a.indexOf("=") + 1)
      if (flagVal) {
        const cls = classifyToken(normalizePathToken(flagVal))
        if (cls.tier !== "pass") classified.push({ token: basenameOf(normalizePathToken(flagVal)), ...cls, explicit: true })
      }
    }

    // ---- guard self-protection: writes onto the guard's own files ----------
    // Triggered by output redirection (`>`, `>>`, `2>`) targets and by
    // write-capable verbs taking the path as an argument. Reads are never
    // flagged: auditing the guard must stay possible.
    {
      const outTargets = []
      for (let i = 0; i < toks.length; i++) {
        const d = unquote(toks[i])
        const m = d.match(/^[0-9]*>>?(.*)$/)
        if (!m) continue
        const inline = normalizePathToken(m[1])
        outTargets.push(inline || (toks[i + 1] ? normalizePathToken(unquote(toks[i + 1])) : ""))
      }
      // Verbs that take the path as an argument. For copy/move shapes the
      // SOURCE is a read (backing up the policy file is routine), so only
      // verbs whose non-flag arguments are all destinations count as writes;
      // cp/mv/install/rsync are handled by their destination pass below.
      if (WRITE_CAPABLE_VERBS.has(verb)) {
        for (const w of args) {
          const t = normalizePathToken(String(w).replace(/^(?:of|out)=/i, ""))
          if (t && !t.startsWith("-")) outTargets.push(t)
        }
      }
      if (MOVE_LIKE_VERBS.has(verb)) {
        // mv UNLINKS its sources: `mv plugin/security-guard.js /tmp/x` disarms
        // the guard by removal, so every non-flag argument counts as a target.
        for (const w of args) {
          const t = normalizePathToken(w)
          if (t && !t.startsWith("-")) outTargets.push(t)
        }
      } else if (COPY_LIKE_VERBS.has(verb)) {
        // last non-flag argument is the destination
        for (let i = args.length - 1; i >= 0; i--) {
          const t = normalizePathToken(args[i])
          if (t && !t.startsWith("-")) {
            outTargets.push(t)
            break
          }
        }
      }
      // `sed -i` edits in place: treat file operands as write targets.
      if (verb === "sed" && args.some((a) => /^-[A-Za-z]*i/.test(String(a)))) {
        for (const w of args) {
          const t = normalizePathToken(w)
          if (t && !t.startsWith("-")) outTargets.push(t)
        }
      }
      for (const cand of outTargets) {
        if (!cand) continue
        const self = classifySelfProtect(policy, cand)
        if (self) {
          return {
            decision: self.tier === "deny" ? "block" : "ask",
            ruleId: self.ruleId,
            category: self.category,
            reason: self.reason,
            matched: basenameOf(cand),
          }
        }
        // Redirection INTO a high-confidence secret file (creating your own
        // .env) is normal setup; only guard-owned paths are blocked here.
      }
    }

    const worst = (tier) => classified.find((c) => c.tier === tier)
    const denyHit = worst("deny")
    const askHit = worst("ask")

    // Track temp-copy provenance: "cp .env /tmp/x" makes /tmp/x dangerous.
    // Only a DENIED/ASKED SOURCE followed by a clean destination counts;
    // writing INTO a protected name (cp .env.example .env) is not exfiltration.
    if (classified.length && FILE_MANAGEMENT_VERBS.has(verb)) {
      let srcIdx = -1
      let srcHit = null
      for (let wi = 1; wi < words.length; wi++) {
        const norm = normalizePathToken(words[wi])
        if (!norm || !looksLikePath(norm)) continue
        const cls = classifyToken(norm)
        if (cls.tier !== "pass") {
          srcIdx = wi
          srcHit = cls
          break
        }
      }
      if (srcHit) {
        for (let wi = words.length - 1; wi > srcIdx; wi--) {
          const norm = normalizePathToken(words[wi])
          if (!norm || !looksLikePath(norm)) continue
          if (classifyPath(policy, norm).tier === "pass") {
            copies.push({ token: norm, tier: srcHit.tier, ruleId: srcHit.ruleId })
            break
          }
        }
      }
    }

    // stdin redirection `< protected` applies to whatever this segment runs
    const redirIdx = toks.findIndex((t) => t === "<")
    if (redirIdx !== -1 && redirIdx + 1 < toks.length) {
      const cls = classifyToken(normalizePathToken(toks[redirIdx + 1]))
      if (cls.tier !== "pass") {
        classified.push({ token: basenameOf(normalizePathToken(toks[redirIdx + 1])), ...cls })
      }
    }

    // ---- git commit/tag -m: skip path classification on narrative text -----
    // Commit and tag messages are human-readable prose, not file references.
    // A path-like token in a message (e.g. "discvault.env") is coincidental:
    // it names a runtime config file without referencing secret material.
    if (verb === "git") {
      const sub = gitSubcommand(args)
      if ((sub === "commit" || sub === "tag") && args.some(a => a === "-m" || a === "--message")) {
        classified.length = 0
      }
    }

    if (classified.length) {
      const hit = denyHit ?? askHit
      // readers / transformers / interpreters / senders / archives / git
      if (READER_VERBS.has(verb) || TRANSFORMER_VERBS.has(verb)) {
        return verdict(hit, "GGR-READ-001", "protected file read via shell utility", hit.token)
      }
      if (INTERPRETERS.has(verb)) {
        // Any interpreter invocation that mentions protected material counts,
        // whether inline (-c/-e), a script path, or stdin code.
        return verdict(hit, "GGR-LANG-001", "interpreter invoked with a reference to protected material", hit.token)
      }
      if (SENDER_VERBS.has(verb)) {
        const sendsFile =
          /(^|\s)@[^\s]+/.test(rawSeg) ||
          args.some((a) => /=[^=]*@/.test(a) || a === "--data-binary" || a === "--upload-file" || a === "-T") ||
          toks.includes("<")
        return verdict(
          hit,
          sendsFile ? "GGN-SEND-001" : "GGN-SEND-002",
          sendsFile ? "network sender consumes protected material (@file / stdin)" : "network sender references protected material",
          hit.token
        )
      }
      if (ARCHIVE_CREATORS.has(verb)) {
        return verdict(hit, "GGA-PACK-001", "archive creation includes protected material", hit.token)
      }
      if (verb === "git" && GIT_CONTENT_SUBCOMMANDS.has(gitSubcommand(args))) {
        return verdict(hit, "GGG-GIT-001", "git object/history access may expose protected material committed earlier", hit.token)
      }
      // Generic: a protected path touched by something unrecognized. Deny-tier
      // hits block unless the verb is ordinary file management (creating your
      // own .env from an example, generating keys, permission fixes...);
      // ask-tier hits fire generically only when explicitly flagged
      // (--kubeconfig-style credential pointers), never on name coincidence.
      if (!FILE_MANAGEMENT_VERBS.has(verb)) {
        const hitForGeneric = denyHit ?? null
        if (hitForGeneric) {
          return verdict(hitForGeneric, "GGR-OTHER-001", "unrecognized operation references protected material", hitForGeneric.token)
        }
        const explicitAsk = classified.find((c) => c.tier === "ask" && c.explicit)
        if (explicitAsk) {
          return verdict(explicitAsk, "GGR-CFG-001", "tool pointed at cluster credential material via an explicit config flag", explicitAsk.token)
        }
      }
    }

    // ---- E1 glob/pattern expansion (ask, exemplar-matched) ------------------
    // Runs only when no literal fired, so `cat .env*` keeps its block while
    // `cat .e*` asks. File-management verbs stay silent (chmod/cp workflows);
    // `*.log` stays silent via exemplar mismatch. Commit-message text stays
    // silent (narrative, not a file reference).
    {
      const isGitMessage =
        verb === "git" &&
        (gitSubcommand(args) === "commit" || gitSubcommand(args) === "tag") &&
        args.some((a) => a === "-m" || a === "--message")
      if (!isGitMessage && !classified.length && globAskAppliesForVerb(verb)) {
        for (const t of words) {
          const cands = [String(t)]
          const eq = String(t).lastIndexOf("=")
          if (eq !== -1 && eq + 1 < String(t).length) cands.push(String(t).slice(eq + 1))
          for (const c of cands) {
            const ex = globMayMatchProtected(c)
            if (ex) {
              return {
                decision: "ask",
                ruleId: "GGR-GLOB-001",
                category: "semantic-bypass",
                reason: "glob pattern may expand to protected material; approve only if no secret matches",
                matched: basenameOf(shellDequote(String(c))),
              }
            }
          }
        }
      }
    }

    // ---- E3 directory-operand archives (ask, broad-root creation only) ------
    // `tar czf out.tgz .` archives everything without naming a member.
    // Ask only on creation (`c` flag) with a broad-root operand; extraction
    // (`tar -xf`, BYP-ARC-003) and scoped sources (`dist/`) stay silent.
    if (!classified.length && ARCHIVE_CREATORS.has(verb)) {
      // `tar` creation carries `c` in its flag bundle with or without a dash
      // (`czf`, `-cf`); extraction (`-xf`, BYP-ARC-003) and listing (`-tf`)
      // stay silent.
      const isCreation =
        verb !== "tar" ||
        args.some((a) => {
          const d = shellDequote(String(a))
          if (/^-/.test(d)) return /c/.test(d) && !/x/.test(d)
          return /^[A-Za-z]{1,6}$/.test(d) && /c/.test(d) && !/x/.test(d)
        })
      if (isCreation) {
        const broadRoot = (v) => {
          const d = shellDequote(String(v)).trim()
          return d === "." || d === "./" || d === "/" || d === "~" || d === "$HOME" || d === "${HOME}"
        }
        const nonFlag = args.filter((a) => !shellDequote(String(a)).startsWith("-"))
        if (nonFlag.some(broadRoot)) {
          return {
            decision: "ask",
            ruleId: "GGA-DIR-001",
            category: "semantic-bypass",
            reason: "archive creation over a broad directory may include secret material; scope to needed files or approve",
            matched: verb,
          }
        }
      }
    }

    // ---- E4 bare history / full-tree git (ask, patch-display only) ---------
    // `git log -p`, `git show HEAD`, `git archive main -o …` carry no
    // pathspec. Ask only when they display patches/trees; metadata
    // (`log --oneline`, `show --stat`, `diff --name-only`, `status`) stays
    // silent, as do `--`-scoped invocations.
    if (!classified.length && verb === "git") {
      const sub = gitSubcommand(args)
      if (GIT_CONTENT_SUBCOMMANDS.has(sub)) {
        const deq = (a) => shellDequote(String(a))
        const has = (names) => args.some((a) => names.includes(deq(a)))
        const hasPrefix = (pre) => args.some((a) => deq(a).startsWith(pre))
        const metaOnly =
          has(["--stat", "--name-only", "--name-status", "--oneline"]) || hasPrefix("--format=")
        const hasPathFilter = args.some((a) => deq(a) === "--")
        if (!metaOnly && !hasPathFilter) {
          let fire = false
          if (sub === "log") {
            fire = has(["-p", "--patch"])
          } else if (sub === "show" || sub === "diff" || sub === "whatchanged" || sub === "cat-file") {
            fire = true
          } else if (sub === "archive") {
            // Full-tree when no pathspec remains after removing revisions,
            // outputs, and flags; a scoped archive (`… src/`) stays silent
            // unless a literal already fired above.
            const isPathspec = (d) => {
              if (!d || d.startsWith("-") || d === sub) return false
              if (["main", "HEAD", "master"].includes(d)) return false
              if (d === "-o" || d.endsWith(".tar") || d.endsWith(".tgz") || d.endsWith(".zip")) return false
              if (d.startsWith("--")) return false
              return true
            }
            // `-o <file>` consumes the next token as output, not a pathspec.
            const tokens = args.map(deq)
            let hasSpec = false
            for (let i = 0; i < tokens.length; i++) {
              if (tokens[i] === "-o") {
                i++
                continue
              }
              if (isPathspec(tokens[i])) {
                hasSpec = true
                break
              }
            }
            fire = !hasSpec
          }
          if (fire) {
            return {
              decision: "ask",
              ruleId: "GGG-HIST-001",
              category: "semantic-bypass",
              reason: "bare history/full-tree git access may expose secrets committed earlier; scope with a path or approve",
              matched: sub,
            }
          }
        }
      }
    }

    // ---- E5 broad-root recursive search (ask, narrow) -----------------------
    // `grep -r PASSWORD .` surfaces protected contents via the pattern, not
    // the path. Ask only on recursive search rooted at a broad root;
    // scoped roots (`src/`, `docs/`) stay silent (NEG-FP-002, NEG-EXC-011).
    if (!classified.length && (READER_VERBS.has(verb) || verb === "find")) {
      const searchVerbs = new Set(["grep", "egrep", "fgrep", "rg", "ack", "ag"])
      if (searchVerbs.has(verb)) {
        const deqArgs = args.map((a) => shellDequote(String(a)))
        const recursive =
          verb === "rg" || verb === "ack" || verb === "ag" ||
          deqArgs.some((a) => a === "-r" || a === "-R" || a === "--recursive" || /^-.*[rR]$/.test(a) || /^-.*[rR][A-Za-z]*$/.test(a))
        if (recursive) {
          const broadRoot = (v) => {
            const d = String(v).trim()
            return d === "." || d === "./" || d === "/" || d === "~" || d === "$HOME"
          }
          const nonFlag = deqArgs.filter((a) => !a.startsWith("-"))
          if (nonFlag.some(broadRoot)) {
            return {
              decision: "ask",
              ruleId: "GGR-SEARCH-001",
              category: "semantic-bypass",
              reason: "broad recursive search may surface secret contents; scope to a subdirectory or approve",
              matched: verb,
            }
          }
        }
      }
    }
  }
  return null

  function blockDump(ruleId, matchedVerb) {
    return {
      decision: "block", ruleId, category: "environment-dump",
      reason: "environment dumping exposes every secret in the process environment",
      matched: matchedVerb,
    }
  }
  function verdict(hit, ruleId, reason, matched) {
    const base =
      hit.tier === "deny"
        ? { decision: "block", ruleId, category: "semantic-bypass", reason, matched }
        : { decision: "ask", ruleId, category: "semantic-bypass", reason, matched }
    base.pathRule = hit.ruleId // which protected-path rule fired (diagnostics + tests)
    return base
  }
}

// ============================================================================
// Pure engine — MCP connector analysis (P0-verified runtime facts)
// ============================================================================

const MCP_DEFAULT_TRUST = "unlisted-server"
const MCP_EFFECTS = new Set(["allow", "ask", "deny"])

/**
 * Split an OpenCode MCP tool/action name `${server}_${tool}`.
 * Ambiguity (server names containing "_") is resolved against the configured
 * server inventory (longest prefix wins); unknown prefixes degrade to a
 * conservative unlisted-server classification.
 */
export function parseMcpToolName(toolName, knownServers = []) {
  const t = String(toolName ?? "")
  if (!t.includes("_")) return null
  let best = null
  for (const s of knownServers) {
    if (s && t.startsWith(s + "_") && (!best || s.length > best.length)) best = s
  }
  if (best) return { server: best, tool: t.slice(best.length + 1) }
  const i = t.indexOf("_")
  return { server: t.slice(0, i), tool: t.slice(i + 1), inventoryMatch: false }
}

function mcpTokens(name) {
  return String(name)
    .split(/[_\-\s]|(?<=[a-z0-9])(?=[A-Z])/)
    .filter(Boolean)
    .map((t) => t.toLowerCase())
}

/** Verb-token classification for tools without an explicit entry.
 *  Write-side wins over read-side when both appear (conservative). */
export function classifyMcpTool(policyMcp, server, tool) {
  const explicit = (policyMcp.tools ?? []).find((r) => r.server === server && r.tool === tool)
  if (explicit) {
    return { class: explicit.class ?? "unknown", ruleId: explicit.id, reason: explicit.reason, effectOverride: explicit.effect, explicit: true }
  }
  const vc = policyMcp.verbClasses ?? {}
  const has = (verbs) => verbs.some((v) => mcpTokens(tool).includes(v))
  if (has(vc.destructive ?? [])) return { class: "destructive", ruleId: "MCP-CLS-D-001" }
  if (has(vc["external-write"] ?? [])) return { class: "external-write", ruleId: "MCP-CLS-W-001" }
  if (has(vc["credential-related"] ?? [])) return { class: "credential-related", ruleId: "MCP-CLS-C-001" }
  const writeish = has((vc["external-write"] ?? []).map((v) => v.replace(/e$/, ""))) // stem variants (updates->update handled by tokens anyway)
  if (has(vc["read-only"] ?? []) && !writeish) {
    // A read verb alone classifies as read-only UNLESS a write token also
    // appears anywhere in the name (e.g. get_and_write_report).
    const allTokens = mcpTokens(tool)
    if (!(vc["external-write"] ?? []).some((v) => allTokens.includes(v)) && !(vc.destructive ?? []).some((v) => allTokens.includes(v))) {
      return { class: "read-only", ruleId: "MCP-CLS-R-001" }
    }
  }
  if (has(vc.ambiguous ?? [])) return { class: "unknown", ruleId: "MCP-CLS-U-001", ambiguous: true }
  return { class: "unknown", ruleId: "MCP-CLS-U-002" }
}

function mcpEffectFor(policyMcp, server, cls) {
  const trust = policyMcp.servers?.[server]?.trust ?? MCP_DEFAULT_TRUST
  const table = policyMcp.defaults?.[trust] ?? policyMcp.defaults?.[MCP_DEFAULT_TRUST] ?? {}
  return table[cls] ?? "ask"
}

function mcpTrustReason(policyMcp, server) {
  const entry = policyMcp.servers?.[server]
  return entry?.reason ? `${server} (${entry.trust}): ${entry.reason}` : `${server}: server not present in MCP trust policy`
}

/** Argument-level rules: protected-path tiers reuse the filesystem classifier;
 *  secret-named values are flagged conservatively. Returns escalations only. */
export function mcpArgumentVerdicts(policy, input, promote, opts = {}) {
  const out = []
  const strings = []
  const collect = (v, key) => {
    if (typeof v === "string") strings.push([key, v])
    else if (v && typeof v === "object") for (const [k2, v2] of Object.entries(v)) collect(v2, key ? `${key}.${k2}` : k2)
  }
  for (const [k, v] of Object.entries(input ?? {})) collect(v, k)

  for (const [, value] of strings) {
    let hitPath = false
    const norm = normalizePathToken(value)
    if (norm && looksLikePath(norm)) {
      // Symlink/alias defense: classify the literal path AND its resolved
      // target (when the caller provides a resolver), escalating to the
      // worst tier. Closes the benign-alias -> secret-file bypass.
      const candidates = [norm]
      if (opts.resolvePath) {
        try {
          const real = opts.resolvePath(norm)
          if (real && real !== norm) candidates.push(real)
        } catch {}
      }
      const cls = classifyPathVariants(policy, candidates, { promoteAskToDenyIds: promote })
      if (cls.tier !== "pass") {
        hitPath = true
        out.push({
          decision: "block", // arg-layer has no prompt channel
          ruleId: cls.tier === "deny" ? "MCP-ARG-PATH-001" : "MCP-ARG-PATH-002",
          category: "mcp-protected-path",
          reason: (cls.tier === "deny" ? cls.reason : "approval-gated: " + cls.reason),
          matched: basenameOf(norm),
          pathRule: cls.ruleId,
        })
      }
    }
    // Same embedded scan the shell engine uses: protected references can hide
    // inside a longer string (`cd /srv/app && cat .env`, JSON payloads, URLs
    // ending in credential filenames) instead of being the whole argument.
    if (!hitPath) {
      for (const m of String(value).matchAll(EMBEDDED_PATH_RE)) {
        const cls = classifyPath(policy, m[0], { promoteAskToDenyIds: promote })
        if (cls.tier === "pass") continue
        out.push({
          decision: "block",
          ruleId: cls.tier === "deny" ? "MCP-ARG-PATH-001" : "MCP-ARG-PATH-002",
          category: "mcp-protected-path",
          reason: (cls.tier === "deny" ? cls.reason : "approval-gated: " + cls.reason) + " (embedded in an argument)",
          matched: basenameOf(m[0]),
          pathRule: cls.ruleId,
        })
        break
      }
    }
    // Guard self-protection: an MCP filesystem-style tool pointed at the
    // guard's own files is the same tamper vector as a shell write.
    if (!hitPath && norm) {
      const self = classifySelfProtect(policy, norm)
      if (self) {
        out.push({
          decision: "block",
          ruleId: self.ruleId,
          category: "guard-self-protection",
          reason: self.reason,
          matched: basenameOf(norm),
          pathRule: self.ruleId,
        })
        hitPath = true
      }
    }
    // Secret-named VALUE detection — deliberately narrow to avoid flagging
    // prose that merely contains words like "secret": either a BARE variable
    // name, or an explicit KEY=VALUE assignment whose key names a secret.
    {
      const tv = String(value).trim()
      const bareName = !/\s/.test(tv) && tv.length >= 4 && isSecretEnvName(policy, tv)
      const kv = value.match(/^(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)=(\S.*)$/)
      if (bareName || (kv && isSecretEnvName(policy, kv[1]))) {
        out.push({
          decision: "block",
          ruleId: "MCP-ARG-SEC-003",
          category: "mcp-secret-value",
          reason: "argument appears to carry a secret-named value; route sanitized substitutes instead",
          matched: "<argument>",
        })
      }
    }
  }
  return out
}

/**
 * Full MCP decision. Effects:
 *   deny -> block (hard), ask -> ask, allow -> null (no opinion).
 * When `withArgs` is false (permission-evaluate channel has no inputs),
 * argument rules are skipped.
 */
export function decideMcpCall(policy, toolName, input, knownServers = [], opts = {}) {
  const parsed = parseMcpToolName(toolName, knownServers)
  if (!parsed) return null
  const { server, tool } = parsed
  const clsInfo = classifyMcpTool(policy.mcp ?? {}, server, tool)
  const effect = clsInfo.effectOverride ?? mcpEffectFor(policy.mcp ?? {}, server, clsInfo.class)
  const reason =
    clsInfo.reason ??
    `${clsInfo.class ?? "unknown"} tool on ` + mcpTrustReason(policy.mcp ?? {}, server)

  let verdict = null
  if (effect === "deny" || effect === "ask") {
    verdict = {
      decision: effect === "deny" ? "block" : "ask",
      ruleId: clsInfo.ruleId ?? "MCP-DEF-001",
      category: "mcp-policy",
      reason,
      matched: tool,
      server,
      tool,
      class: clsInfo.class,
      explicit: !!clsInfo.explicit,
    }
  }

  if (opts.withArgs !== false) {
    const argHits = mcpArgumentVerdicts(policy, input, opts.promoteAskToDenyIds ?? policy.promoteAskToDenyIds ?? [], { resolvePath: opts.resolvePath })
    // Highest escalation wins; argument evidence always surfaces.
    if (argHits.length) {
      const worst = argHits.find((h) => h.decision === "block") ?? argHits[0]
      return { ...worst, server, tool }
    }
  }
  return verdict
}

/** True when an action/tool name plausibly belongs to an MCP server.
 *  Primary signal: configured/known server prefix. Fallback (when inventory
 *  discovery fails): any underscored name that is not a known NATIVE tool —
 *  conservative because native tool names are a small fixed set. */
export const NATIVE_TOOL_NAMES = new Set([
  "read", "edit", "write", "patch", "multiedit", "glob", "grep", "grep_fast",
  "webfetch", "websearch", "subagent", "task", "skill", "question",
  "todo_write", "todowrite", "todo_read", "todoread", "notebookedit",
  "bash", "shell", "command", "execute", "terminal", "list", "view",
  "external_directory", "doom_loop", "lsp",
])

export function isMcpAction(policy, action, knownServers = []) {
  const servers = new Set([...(knownServers ?? []), ...Object.keys(policy.mcp?.servers ?? {})])
  const a = String(action ?? "")
  for (const s of servers) if (s && a.startsWith(s + "_")) return true
  // Inventory-independent fallback: underscored, not native, not bare.
  return a.includes("_") && !NATIVE_TOOL_NAMES.has(a)
}

// ============================================================================
// Normalized tool/action representation + top-level decisions
// ============================================================================

const SHELL_TOOL_NAMES = new Set(["bash", "shell", "command", "execute", "terminal"])

/** Normalize a tool call into a comparable representation. */
export function normalizeToolCall(tool, input = {}) {
  const t = String(tool ?? "")
  if (SHELL_TOOL_NAMES.has(t) || typeof input.command === "string") {
    return { kind: "shell", command: input.command ?? "" }
  }
  if (/^grep/.test(t)) {
    return { kind: "grep", pattern: String(input.pattern ?? ""), path: input.path ? String(input.path) : "" }
  }
  if (t === "glob") {
    return { kind: "glob", pattern: String(input.pattern ?? "") }
  }
  if (t === "webfetch") {
    return { kind: "webfetch", url: String(input.url ?? "") }
  }
  if (typeof input.filePath === "string" || typeof input.path === "string" || typeof input.file_path === "string") {
    return {
      kind: "path",
      path: input.filePath ?? input.path ?? input.file_path,
      mode: t === "read" ? "read" : "write",
      // Written body, when the tool delivers one (write/patch-style tools).
      content:
        typeof input.content === "string"
          ? input.content
          : typeof input.newString === "string"
            ? input.newString
            : undefined,
    }
  }
  return { kind: "other" }
}

/** Tools whose payload is a script the agent is about to place on disk. */
const SCRIPT_EXT_RE = /\.(sh|bash|zsh|ksh|fish|py|rb|pl|php|js|mjs|cjs|ts|expect)$/i

/** True when written content looks like something an interpreter will run. */
function looksLikeScript(path, content) {
  return SCRIPT_EXT_RE.test(String(path ?? "")) || /^#!.*\b(sh|bash|zsh|python[0-9.]*|node|ruby|perl|php|env)\b/.test(String(content ?? "").slice(0, 64))
}

/** Decide on a normalized tool call. Returns null (no opinion) or a verdict. */
export function decideToolCall(policy, toolCall, opts = {}) {
  const knownCopies = opts.knownCopies ?? []
  const copyLookup = (p) => {
    if (!knownCopies.length || !p) return null
    const norm = normalizePathToken(String(p)).toLowerCase().replace(/^\.\/+/, "")
    if (!norm) return null
    return knownCopies.find((k) => normalizePathToken(String(k.token ?? "")).toLowerCase().replace(/^\.\/+/, "") === norm) ?? null
  }
  switch (toolCall.kind) {
    case "shell":
      return analyzeCommand(policy, toolCall.command, { resolvePath: opts.resolvePath, promoteAskToDenyIds: policy.promoteAskToDenyIds ?? [], knownCopies })
    case "path": {
      // E2: reads of session-tracked copies escalate like the source tier,
      // mirroring single-command `cp && cat` behavior. Writes are left to
      // the adapter's after-hook (overwrite clears tracking) so legitimate
      // replacement stays possible.
      if (toolCall.mode === "read") {
        const hit = copyLookup(toolCall.path)
        if (hit) {
          return {
            decision: hit.tier === "deny" ? "block" : "ask",
            ruleId: "GGR-COPY-001",
            category: "semantic-bypass",
            reason: "read of a temporary copy of protected material",
            matched: basenameOf(toolCall.path),
            pathRule: hit.ruleId,
          }
        }
      }
      // Symlink/alias defense: classify the literal path and (when a resolver
      // is available) its on-disk target, escalating to the worst tier.
      const candidates = [toolCall.path]
      if (typeof opts.resolvePath === "function") {
        try {
          const real = opts.resolvePath(toolCall.path)
          if (real && real !== toolCall.path) candidates.push(real)
        } catch {}
      }
      const cls = classifyPathVariants(policy, candidates, {
        promoteAskToDenyIds: policy.promoteAskToDenyIds ?? [],
        mode: toolCall.mode,
      })
      if (cls.tier === "pass") {
        // Writing a SCRIPT that references protected material is the
        // write-a-file-then-run-it shape: the guard cannot see script bodies
        // at execution time, so this is the only choke point that can. Ask —
        // never block — because scripts legitimately mention .env paths.
        if (toolCall.mode === "write" && looksLikeScript(toolCall.path, toolCall.content)) {
          const hits = embeddedProtectedHits(policy, toolCall.content)
          if (hits.length) {
            return {
              decision: "ask",
              ruleId: "GGW-CONTENT-001",
              category: "deferred-execution",
              reason: "script content references protected material the guard cannot inspect when the script later runs",
              matched: hits[0],
            }
          }
        }
        return null
      }
      if (toolCall.mode === "write" && cls.tier === "ask") {
        return { decision: "ask", ruleId: cls.ruleId, category: "approval-required", reason: "writing to " + cls.reason, matched: basenameOf(toolCall.path) }
      }
      return {
        decision: cls.tier === "deny" ? "block" : "ask",
        ruleId: cls.ruleId,
        category: cls.category,
        reason: cls.reason,
        matched: basenameOf(toolCall.path),
      }
    }
    case "grep": {
      if (!toolCall.path) return null
      {
        const hit = copyLookup(toolCall.path)
        if (hit) {
          return {
            decision: hit.tier === "deny" ? "block" : "ask",
            ruleId: "GGR-COPY-001+GREP",
            category: "search-bypass",
            reason: "content search over a temporary copy of protected material",
            matched: basenameOf(toolCall.path),
            pathRule: hit.ruleId,
          }
        }
      }
      const cls = classifyPath(policy, toolCall.path)
      if (cls.tier === "pass") return null
      return {
        decision: cls.tier === "deny" ? "block" : "ask",
        ruleId: (cls.ruleId ?? "") + "+GREP",
        category: "search-bypass",
        reason: "content search over " + cls.reason + " would surface contents in the transcript",
        matched: basenameOf(toolCall.path),
      }
    }
    case "glob": {
      // Glob patterns carry their own syntax ("**/.env*"); strip it so the
      // surviving name can be classified like any other path token.
      // E10: deny-tier asks (existing) and ask-tier asks (startup-file
      // discovery is the incident class); pass stays silent so `**/*.log`
      // never prompts.
      const stripped = toolCall.pattern.replaceAll("**/", "").replaceAll("*", "").replaceAll("{", "").replaceAll("}", "")
      const cls = classifyPath(policy, stripped)
      if (cls.tier === "pass") return null
      return {
        decision: "ask",
        ruleId: (cls.ruleId ?? "") + "+GLOB",
        category: "discovery",
        reason: "filename discovery over " + cls.reason,
        matched: basenameOf(stripped),
      }
    }
    default:
      return null
  }
}

/** Decide on a permission-evaluate event (V2 hook). Resources for the shell
 *  action are the raw command text; for read/edit they are paths. */
export function decidePermissionEvent(policy, action, resources, opts = {}) {
  if (!Array.isArray(resources)) return null
  const knownCopies = opts.knownCopies ?? []
  for (const res of resources) {
    if (action === "shell") {
      const r = analyzeCommand(policy, String(res), { resolvePath: opts.resolvePath, promoteAskToDenyIds: policy.promoteAskToDenyIds ?? [], knownCopies })
      if (r) return r
      continue
    }
    if (action === "read" || action === "edit") {
      const mode = action === "edit" ? "write" : "read"
      if (mode === "read" && knownCopies.length) {
        const norm = normalizePathToken(String(res)).toLowerCase().replace(/^\.\/+/, "")
        const hit = knownCopies.find((k) => normalizePathToken(String(k.token ?? "")).toLowerCase().replace(/^\.\/+/, "") === norm)
        if (hit) {
          return {
            decision: hit.tier === "deny" ? "block" : "ask",
            ruleId: "GGR-COPY-001",
            category: "semantic-bypass",
            reason: "read of a temporary copy of protected material",
            matched: basenameOf(res),
            pathRule: hit.ruleId,
          }
        }
      }
      const candidates = [String(res)]
      if (typeof opts.resolvePath === "function") {
        try {
          const real = opts.resolvePath(String(res))
          if (real && real !== res) candidates.push(String(real))
        } catch {}
      }
      const cls = classifyPathVariants(policy, candidates, {
        mode,
        promoteAskToDenyIds: policy.promoteAskToDenyIds ?? [],
      })
      if (cls.tier === "deny") {
        return { decision: "block", ruleId: cls.ruleId, category: cls.category, reason: cls.reason, matched: basenameOf(res) }
      }
      if (cls.tier === "ask") {
        return { decision: "ask", ruleId: cls.ruleId, category: cls.category, reason: cls.reason, matched: basenameOf(res) }
      }
    }
  }
  return null
}

// ============================================================================
// Diagnostics — deliberately terse and value-free
// ============================================================================

export function formatVerdict(v) {
  const scope = v.decision === "block" ? "BLOCKED" : "APPROVAL REQUIRED"
  const via = v.pathRule ? ` [matched rule ${v.pathRule}]` : ""
  const where = v.server || v.tool ? ` (${v.server}/${v.tool})` : ""
  return (
    `[${PLUGIN_ID}] ${scope} (${v.ruleId})${via}${where}: ${v.reason}. ` +
    `Matched: "${v.matched}". ` +
    `This guard reduces risk; it cannot prove absence of exfiltration. ` +
    `If access is genuinely required, ask the user for a sanitized substitute or adjust the MCP trust policy.`
  )
}

// ============================================================================
// Pure engine — experimental cross-tool provenance (opt-in, OFF by default)
// ============================================================================

/**
 * Session-scoped marker store for the CLEAN/SENSITIVE/UNKNOWN model:
 *   - markSensitive(text): called when a tool result originates from an
 *     approval-gated/local-data source (its content is potentially secret).
 *   - findSensitive(value): returns true when a later argument embeds a
 *     previously observed sensitive snippet (exact substring, minimum length).
 *
 * Honest limits (docs/mcp.md): paraphrase, re-encoding, summarization,
 * chunking, and partial overlaps evade this completely. It is a tripwire,
 * NOT data-flow security.
 */
export function createProvenanceStore(opts = {}) {
  const maxEntries = opts.maxEntries ?? 48
  const minSnippet = opts.minSnippet ?? 32
  const snippets = [] // FIFO of {id, text}
  let counter = 0

  const normalize = (s) => String(s ?? "").replace(/\s+/g, " ").trim()

  return {
    markSensitive(text) {
      const t = normalize(text)
      if (t.length < minSnippet) return null
      const id = `PROV-${String(++counter).padStart(3, "0")}`
      // Store the head window; long outputs are still detectable by their
      // distinctive prefix, and storage stays bounded.
      snippets.push({ id, text: t.slice(0, 240) })
      if (snippets.length > maxEntries) snippets.shift()
      return id
    },
    findSensitive(value) {
      if (snippets.length === 0) return null
      const v = normalize(value)
      if (v.length < minSnippet) return null
      for (const s of snippets) {
        if (v.includes(s.text)) return { id: s.id }
      }
      return null
    },
    size() {
      return snippets.length
    },
  }
}

/** Scan all string values inside a tool-input object for marked content. */
export function provenanceScan(store, input) {
  if (!store) return null
  const strings = []
  const collect = (v, key) => {
    if (typeof v === "string") strings.push([key, v])
    else if (v && typeof v === "object") for (const [k2, v2] of Object.entries(v)) collect(v2, key ? `${key}.${k2}` : k2)
  }
  for (const [k, v] of Object.entries(input ?? {})) collect(v, k)
  for (const [, value] of strings) {
    const hit = store.findSensitive(value)
    if (hit) {
      return {
        decision: "block",
        ruleId: "MCP-PROV-001",
        category: "mcp-provenance",
        reason: "argument embeds content previously returned by an approval-gated source (experimental provenance tripwire)",
        matched: hit.id,
      }
    }
  }
  return null
}

/** Apply an optional user override (sibling security-guard.config.json):
 *  { "mcpServers": { "<name>": { "trust": "...", "reason": "..." } },
 *    "mcpToolOverrides": { "<server>_<tool>": { "effect": "allow"|"ask"|"deny" } },
 *    "promoteAskToDeny": true|false,
 *    "provenance": { "enabled": true } }
 * Pure + exported for tests. */
export function applyGuardOverride(basePolicy, override) {
  if (!override || typeof override !== "object") return basePolicy
  const out = { ...basePolicy }
  out.mcp = {
    ...(basePolicy.mcp ?? {}),
    ...(override.mcp ? { ...basePolicy.mcp, ...override.mcp } : {}),
    servers: { ...(basePolicy.mcp?.servers ?? {}), ...(override.mcpServers ?? {}) },
  }
  if (typeof override.promoteAskToDeny === "boolean") {
    out.promoteAskToDenyIds = override.promoteAskToDeny
      ? (basePolicy.askPaths ?? []).map((r) => r.id)
      : []
  } else {
    out.promoteAskToDenyIds = basePolicy.promoteAskToDenyIds ?? []
  }
  // Per-tool effect overrides (e.g. { "outline_update_document": { "effect": "allow" } })
  // Format: { "<action_name>": { "effect": "allow"|"ask"|"deny", ... } }
  // Each entry is merged into policy.mcp.tools so classifyMcpTool picks it up.
  if (override.mcpToolOverrides && typeof override.mcpToolOverrides === "object") {
    const existing = out.mcp.tools ?? []
    const merged = [...existing]
    for (const [action, entry] of Object.entries(override.mcpToolOverrides)) {
      const underscore = action.indexOf("_")
      if (underscore === -1) continue
      const server = action.slice(0, underscore)
      const tool = action.slice(underscore + 1)
      const existingIdx = merged.findIndex((t) => t.server === server && t.tool === tool)
      const toolEntry = { server, tool, id: `OVERRIDE-${action}`, class: "unknown", ...entry }
      if (existingIdx >= 0) merged[existingIdx] = { ...merged[existingIdx], ...toolEntry }
      else merged.push(toolEntry)
    }
    out.mcp.tools = merged
  }
  if (override.provenance && typeof override.provenance === "object") {
    out.mcp.provenance = { ...(basePolicy.mcp?.provenance ?? {}), ...override.provenance }
  }
  return out
}

// ============================================================================
// OpenCode V2 adapter
// ============================================================================

import { mkdirSync, writeFileSync, readFileSync, realpathSync } from "node:fs"
import { homedir } from "node:os"
import path from "node:path"

function heartbeatPath() {
  const dataHome = process.env.XDG_DATA_HOME || path.join(homedir(), ".local", "share")
  return path.join(dataHome, "security-guard-for-opencode", "health.json")
}

function writeHeartbeat(extra = {}) {
  try {
    const file = heartbeatPath()
    mkdirSync(path.dirname(file), { recursive: true })
    writeFileSync(
      file,
      JSON.stringify({ plugin: PLUGIN_ID, version: PLUGIN_VERSION, time: new Date().toISOString(), pid: process.pid, ...extra }, null, 2)
    )
  } catch {
    // Heartbeat failure must never break loading; doctor will report staleness.
  }
}

/**
 * Default export: OpenCode V2 plugin object.
 * `options.profile` (via config plugins entry) selects baseline|strict; the
 * compiled GENERATED_GUARD_POLICY carries the rules for its baked-in profile,
 * and options.promoteAskToDeny can force strict promotion at runtime.
 */
export default {
  id: PLUGIN_ID,

  async setup(ctx) {
    // Per-installation tuning: optional sibling file next to THIS plugin
    // (security-guard.config.json). Verified on beta-18230: ctx.options is
    // NOT delivered to local-file plugins, and ctx.mcp.list() returns empty
    // data — so neither channel can carry configuration or inventory.
    let siblingOverride = null
    try {
      const cfgPath = process.env.SG_CONFIG_FILE || new URL("security-guard.config.json", import.meta.url)
      siblingOverride = JSON.parse(readFileSync(cfgPath, "utf8"))
    } catch {}
    const basePolicy = applyGuardOverride(GENERATED_GUARD_POLICY, siblingOverride)
    const policy = {
      ...basePolicy,
      promoteAskToDenyIds: basePolicy.promoteAskToDenyIds ?? [],
    }
    policy.mcp = { ...(basePolicy.mcp ?? {}) }

    // Heartbeat FIRST so a crash later in setup is still observable.
    writeHeartbeat({ phase: "starting", opencode: ctx?.app?.version, policyVersion: policy.policyVersion })

    // Server inventory: policy-declared servers are authoritative; runtime
    // discovery is merged best-effort (returned empty data on the tested
    // beta). Unlisted servers fall back to conservative heuristics via
    // isMcpAction/parseMcpToolName regardless.
    let knownServers = Object.keys(policy.mcp?.servers ?? {})
    try {
      const listed = await ctx.mcp.list()
      const rows = Array.isArray(listed?.data)
        ? listed.data
        : Array.isArray(listed?.servers)
          ? listed.servers
          : Array.isArray(listed)
            ? listed
            : []
      const names = rows.map((s) => s?.name ?? s?.id ?? s).filter(Boolean)
      knownServers = [...new Set([...knownServers, ...names.map(String)])]
    } catch {}

    // Experimental cross-tool provenance (policy-gated, default OFF).
    const prov = policy.mcp?.provenance?.enabled === true ? createProvenanceStore() : null
    const pendingSensitive = new Map() // callID -> true (result should be marked)
    const callIdOf = (event) => (event && typeof event.callID === "string" ? event.callID : "")

    // E2 session file-copy provenance (always on, bounded): `cp .env /tmp/x`
    // in one tool call, `cat /tmp/x` in the next. Same-command tracking lives
    // in analyzeCommand; this persists it across calls. Populated in
    // execute.after only (never pre-execution) so denied/unapproved copies
    // are never recorded; cleared on `rm` and on clean-source overwrite.
    const copyStore = createCopyProvenanceStore({ maxEntries: 32 })

    // Symlink/alias defense: resolve on-disk targets so benign-named links
    // onto protected material are classified by what they really are.
    // `~` is expanded first — realpathSync does not understand it, so without
    // this the whole defense silently no-opped on the most common path form.
    const resolvePath = (p) => {
      try {
        if (typeof p !== "string" || !p) return null
        const expanded =
          p === "~" ? homedir() : p.startsWith("~/") ? path.join(homedir(), p.slice(2)) : p
        if (!expanded) return null
        return realpathSync(expanded)
      } catch {
        return null
      }
    }

    await ctx.tool.hook("execute.before", (event) => {
      const callID = callIdOf(event)
      // MCP calls first: namespaced `${server}_${tool}` names never collide
      // with native tool names. Deny-class verdicts hard-block here (the
      // Code-Mode wrapper flattens messages, so blocking must not depend on
      // message propagation); approval-tier verdicts are enforced by the
      // permission channel, which fires per nested call and CAN prompt.
      const mcpVerdict = decideMcpCall(policy, event.tool, event.input ?? {}, knownServers, { resolvePath })
      if (prov) {
        const scanHit = provenanceScan(prov, event.input ?? {})
        if (scanHit) {
          writeHeartbeat({ phase: "running", lastDecision: scanHit.ruleId })
          throw new Error(formatVerdict(scanHit))
        }
      }
      if (mcpVerdict) {
        if (prov && mcpVerdict.decision !== "block" && callID) {
          // Approved/allowed local-data reads become provenance sources.
          pendingSensitive.set(callID, true)
        }
        if (mcpVerdict.decision === "block") {
          writeHeartbeat({ phase: "running", lastDecision: mcpVerdict.ruleId })
          throw new Error(formatVerdict(mcpVerdict))
        }
      }

      const norm = normalizeToolCall(event.tool, event.input ?? {})
      const v = decideToolCall(policy, norm, { resolvePath, knownCopies: copyStore.entries() })
      if (v && v.decision === "block") {
        writeHeartbeat({ phase: "running", lastDecision: v.ruleId })
        throw new Error(formatVerdict(v))
      }
      // "ask" verdicts from the TOOL hook cannot raise a permission prompt
      // (that channel belongs to the permission system); they downgrade to
      // block only for tools the permission layer cannot see (grep/glob
      // paths). This is intentional: coverage first, documented in docs/.
      if (v && v.decision === "ask" && (norm.kind === "grep" || norm.kind === "glob")) {
        writeHeartbeat({ phase: "running", lastDecision: v.ruleId })
        throw new Error(formatVerdict({ ...v, decision: "block" }))
      }
      // Provenance sources: any approval-gated call whose result will flow
      // (native read/edit asks; MCP asks already marked above).
      if (prov && v && v.decision === "ask" && callID) {
        pendingSensitive.set(callID, true)
      }
    })

    if (prov) {
      try {
        await ctx.tool.hook("execute.after", (event) => {
          const callID = callIdOf(event)
          if (!callID || !pendingSensitive.has(callID)) return
          pendingSensitive.delete(callID)
          const text =
            event.result?.content?.map?.((c) => c?.text ?? "").join("\n") ??
            (typeof event.output === "string" ? event.output : "")
          if (text) prov.markSensitive(text.slice(0, 2000))
        })
      } catch {}
    }

    // E2: record successful copies after execution (never before, so blocked
    // or denied copies leave no trace). Failures must never break tools.
    try {
      await ctx.tool.hook("execute.after", (event) => {
        try {
          const input = event.input ?? {}
          const norm = normalizeToolCall(event.tool, input)
          if (norm.kind === "shell") {
            const cmd = String(norm.command ?? "")
            // Clear on `rm` first so `rm /tmp/x` then reuse starts clean.
            for (const n of detectCopyClears(cmd, copyStore.entries().map((e) => e.token))) {
              copyStore.remove(n)
            }
            const tracks = detectCopyTracks(policy, cmd, { resolvePath })
            if (tracks.length) {
              for (const t of tracks) copyStore.note(t.dest, t.tier, t.ruleId)
            } else {
              // Clean-source overwrite of a tracked dest clears it
              // (`cp notes.txt /tmp/x` replaces the secrets).
              const tracked = new Set(copyStore.entries().map((e) => normalizePathToken(String(e.token)).toLowerCase()))
              if (tracked.size) {
                for (const rawSeg of splitSegments(cmd)) {
                  const toks = tokenize(rawSeg).map((t) => (isAssignment(t) ? t : unquote(t)))
                  if (!toks.length) continue
                  let idx = 0
                  while (idx < toks.length && isAssignment(toks[idx]) && !toks[idx].includes("(")) idx++
                  const words = toks.slice(idx)
                  if (!words.length) continue
                  const verb = basenameOf(words[0]).toLowerCase()
                  if (verb !== "cp" && verb !== "install" && verb !== "mv" && verb !== "ln") continue
                  const nonFlag = words.slice(1).map((w) => normalizePathToken(String(w))).filter((t) => t && !t.startsWith("-"))
                  if (!nonFlag.length) continue
                  const dest = nonFlag[nonFlag.length - 1].toLowerCase()
                  if (tracked.has(dest)) copyStore.remove(dest)
                }
              }
            }
          } else if (norm.kind === "path" && norm.mode === "write") {
            // Overwriting a tracked copy with new content clears it; the
            // write itself was already gated above when it referenced
            // protected material directly.
            copyStore.remove(String(norm.path ?? ""))
          }
        } catch {}
      })
    } catch {}

    await ctx.permission.hook("evaluate", (event) => {
      // MCP channel: arguments are not present here, so trust/class defaults
      // and explicit per-tool rules apply (arg rules ran in execute.before).
      if (isMcpAction(policy, event.action, knownServers)) {
        const v = decideMcpCall(policy, event.action, undefined, knownServers, { withArgs: false })
        if (!v) return
        if (v.decision === "block") {
          event.effect = "deny"
          event.message = formatVerdict(v)
          writeHeartbeat({ phase: "running", lastDecision: v.ruleId })
        } else if (event.effect === "allow") {
          event.effect = "ask"
          event.message = formatVerdict(v)
        }
        return
      }

      const v = decidePermissionEvent(policy, event.action, event.resources, { resolvePath, knownCopies: copyStore.entries() })
      if (!v) return
      if (v.decision === "block") {
        event.effect = "deny"
        event.message = formatVerdict(v)
      } else if (v.decision === "ask" && event.effect === "allow") {
        // Escalate silent allows to approval prompts; existing asks stay asks.
        event.effect = "ask"
        event.message = formatVerdict(v)
      }
    })

    writeHeartbeat({
      phase: "active",
      opencode: ctx?.app?.version,
      policyVersion: policy.policyVersion,
      profile: policy.profile,
      denyPaths: (policy.denyPaths ?? []).length,
      askPaths: (policy.askPaths ?? []).length,
    })
  },
}
