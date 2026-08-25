/**
 * OpenCode Security Guard — execution-time guard plugin (Layer 4).
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
  "promoteAskToDenyIds": [],
  "envVarNamePattern": "(TOKEN|SECRET|PASSWORD|PASSWD|API_?KEY|PRIVATE_KEY|ACCESS_KEY|CLIENT_SECRET|CREDENTIAL|AUTH_|_AUTH|AUTH$)"
})
// ==== END GENERATED GUARD POLICY ====

export const PLUGIN_VERSION = "0.1.0-rc.1"
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
      return base.endsWith(form.value)
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
 * Classify a filesystem path against the compiled guard policy.
 * Order: hard denies win over exceptions (so a "tokenizer" file inside
 * ~/.aws stays denied); then profile-promoted asks; then asks; then allows;
 * then "pass" (= no guard opinion).
 */
export function classifyPath(policy, rawPath, opts = {}) {
  const p = normalizePathToken(rawPath)
  if (!p) return { tier: "pass" }

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
])
const TRANSFORMER_VERBS = new Set(["base64", "xxd", "od", "hexdump", "openssl", "gpg", "iconv", "uudecode"])
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
// For openssl, only classify tokens that follow explicit INPUT flags —
// bare positionals are usually outputs (-keyout/-out), which keeps
// certificate/key GENERATION workflows working.
const OPENSSL_INPUT_FLAGS = new Set(["-in", "-inkey", "-CAkey", "-certfile", "-prverify", "-sign", "-decrypt", "-verify"])
// Scan segments for embedded path-like substrings (catches paths inside
// quoted interpreter code such as python3 -c 'open(".env").read()').
// The trailing lookahead prevents partial extraction like ".env" out of
// ".env.example" (dot counts as a continuation character here).
const EMBEDDED_PATH_RE =
  /[\w./~@-]*\.(?:env|pem|key|p12|pfx|jks|keystore|tfstate|netrc|npmrc|pypirc|pub)(?![\w.-])|[\w./~@-]*(?:id_rsa|id_ed25519|id_ecdsa|id_dsa|authorized_keys|git-credentials|auth\.json|kubeconfig)(?![\w.-])|\.[A-Za-z0-9@_-]*(?:ssh|aws|azure|kube|gnupg|config[/\\]secrets)[\w./@-]*/gi

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

/** Strip surrounding quotes and a trailing/leading redirection char. */
export function normalizePathToken(tok) {
  if (!tok) return ""
  let t = String(tok).trim()
  t = t.replace(/^['"]|['"]$/g, "")
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
  if (/^[A-Za-z0-9_.@-]+$/.test(tok) && /\.(env|pem|key|p12|pfx|jks|keystore|tfstate|pub)$/.test(tok)) return true
  if (/^\.(env|netrc|npmrc|pypirc|git-credentials|zsh|bash)/.test(tok)) return true
  return false
}

function varRefs(tok) {
  // ${NAME} and $NAME (simple identifiers only)
  const out = []
  for (const m of String(tok).matchAll(/\$\{([A-Za-z_][A-Za-z0-9_]*)\}|\$([A-Za-z_][A-Za-z0-9_]*)/g)) {
    out.push(m[1] ?? m[2])
  }
  return out
}

/** Extract inner text of $( ... ) and ` ... ` substitutions. */
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
  const bt = s.indexOf("`")
  if (bt !== -1) {
    const end = s.indexOf("`", bt + 1)
    if (end !== -1) out.push(s.slice(bt + 1, end))
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

/**
 * Analyze one command string against the policy.
 * Returns null (no opinion) or {decision:"block"|"ask", ruleId, category, reason, matched}.
 * `matched` contains a SAFE excerpt: a basename or variable NAME — never
 * values, never full paths into the user's home, never raw command text.
 */
export function analyzeCommand(policy, command, opts = {}) {
  const promote = opts.promoteAskToDenyIds ?? policy.promoteAskToDenyIds ?? []
  const assignments = {} // simple single-level indirection support
  const copies = [] // temp-copy provenance: cp .env /tmp/x => /tmp/x inherits .env's tier

  // Classify a token, falling back to inherited tiers from tracked copies.
  const classifyToken = (tok) => {
    const cls = classifyPath(policy, tok, { promoteAskToDenyIds: promote })
    if (cls.tier !== "pass") return cls
    const base = basenameOf(tok)
    const c = copies.find((c) => c.token === tok || basenameOf(c.token) === base)
    if (c) return { tier: c.tier, ruleId: c.ruleId, category: "protected-path", reason: "temporary copy of protected material" }
    return cls
  }

  const segments = splitSegments(command)
  for (let sIdx = 0; sIdx < segments.length; sIdx++) {
    const rawSeg = segments[sIdx]

    // Recurse into command/process substitutions first.
    for (const sub of substitutions(rawSeg)) {
      const r = analyzeCommand(policy, sub, { promoteAskToDenyIds: promote })
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
      if (secretArgs.length && (dashP || verb === "printenv")) {
        return {
          decision: "block", ruleId: "GGE-VAR-001", category: "secret-variable-display",
          reason: "prints the value of a secret-named variable",
          matched: secretArgs[0],
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
        const secretLiteral = rawSeg.match(
          /\b[A-Z_]*(?:TOKEN|SECRET|PASSWORD|PASSWD|API_?KEY|PRIVATE_KEY|ACCESS_KEY|CLIENT_SECRET|CREDENTIALS?|AUTH)[A-Z0-9_]*\b/
        )
        if (secretLiteral) {
          return {
            decision: "block", ruleId: "GGE-VAR-020", category: "environment-dump",
            reason: "interpreter code reads a secret-named environment variable",
            matched: secretLiteral[0],
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

    // ---- path classification over tokens (incl. one-level indirection) -----
    const classified = []
    const seenTokens = new Set()
    const considerToken = (t, opts2 = {}) => {
      for (const v of varRefs(t)) {
        if (assignments[v]) considerToken(assignments[v])
      }
      let cand = normalizePathToken(t)
      if (opts2.opensslInputOnly) {
        // handled by caller via flag pairs; skip generic consideration
        return
      }
      cand = cand.replace(/^\$\{?[A-Za-z_][A-Za-z0-9_]*\}?/, "")
      if (!cand || /\$\{?[A-Za-z_]/.test(cand)) return
      if (!looksLikePath(cand) && !EMBEDDED_PATH_CANDIDATE(cand)) return
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
      if (verb === "git" && GIT_CONTENT_SUBCOMMANDS.has(args[0])) {
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
    }
  }
  return { kind: "other" }
}

/** Decide on a normalized tool call. Returns null (no opinion) or a verdict. */
export function decideToolCall(policy, toolCall) {
  switch (toolCall.kind) {
    case "shell":
      return analyzeCommand(policy, toolCall.command)
    case "path": {
      const cls = classifyPath(policy, toolCall.path)
      if (cls.tier === "pass") return null
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
      const stripped = toolCall.pattern.replaceAll("**/", "").replaceAll("*", "").replaceAll("{", "").replaceAll("}", "")
      const cls = classifyPath(policy, stripped)
      if (cls.tier !== "deny") return null
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
export function decidePermissionEvent(policy, action, resources) {
  if (!Array.isArray(resources)) return null
  for (const res of resources) {
    if (action === "shell") {
      const r = analyzeCommand(policy, String(res))
      if (r) return r
      continue
    }
    if (action === "read" || action === "edit") {
      const cls = classifyPath(policy, String(res))
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
  return (
    `[${PLUGIN_ID}] ${scope} (${v.ruleId})${via}: ${v.reason}. ` +
    `Matched: "${v.matched}". ` +
    `This guard reduces risk; it cannot prove absence of exfiltration. ` +
    `If access is genuinely required, ask the user for a sanitized substitute.`
  )
}

// ============================================================================
// OpenCode V2 adapter
// ============================================================================

import { mkdirSync, writeFileSync } from "node:fs"
import { homedir } from "node:os"
import path from "node:path"

function heartbeatPath() {
  const dataHome = process.env.XDG_DATA_HOME || path.join(homedir(), ".local", "share")
  return path.join(dataHome, "opencode-security-guard", "health.json")
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
    const policy = {
      ...GENERATED_GUARD_POLICY,
      promoteAskToDenyIds:
        (ctx?.options?.promoteAskToDeny === true
          ? (GENERATED_GUARD_POLICY.askPaths ?? []).map((r) => r.id)
          : GENERATED_GUARD_POLICY.promoteAskToDenyIds) ?? [],
    }

    // Heartbeat FIRST so a crash later in setup is still observable.
    writeHeartbeat({ phase: "starting", opencode: ctx?.app?.version, policyVersion: policy.policyVersion })

    await ctx.tool.hook("execute.before", (event) => {
      const norm = normalizeToolCall(event.tool, event.input ?? {})
      const v = decideToolCall(policy, norm)
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
    })

    await ctx.permission.hook("evaluate", (event) => {
      const v = decidePermissionEvent(policy, event.action, event.resources)
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
