#!/usr/bin/env node
/**
 * Doctor — verify that OpenCode Security Guard is actually installed, loaded,
 * and consistent. Run after EVERY OpenCode upgrade.
 *
 *   node scripts/doctor.mjs [--live] [--scope project|global|auto]
 *
 * Checks:
 *   - opencode2 presence and version (warns when it differs from the tested build)
 *   - plugin file installed, version matches this repository
 *   - plugin LIVENESS via its heartbeat file (--live additionally restarts nothing;
 *     it greps the OpenCode server log for load/error lines since last boot)
 *   - active configuration contains the generated permission rules with correct
 *     ordering invariants (*.env deny BEFORE *.env.example allow), watcher ignores,
 *     and reports the share setting WITH the honest caveat that V2 currently
 *     does not act on it
 *
 * Exit code 0 only if every critical check passes.
 */
import { readFileSync, existsSync } from "node:fs"
import { execFileSync } from "node:child_process"
import { homedir } from "node:os"
import path from "node:path"
import { parseJsonc } from "./jsonc.mjs"
import { fileURLToPath } from "node:url"

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..")
const args = process.argv.slice(2)
const live = args.includes("--live")
const scopeArg = args.includes("--scope") ? args[args.indexOf("--scope") + 1] : "auto"

let problems = 0
let warnings = 0
const ok = (msg) => console.log(`  ok       ${msg}`)
const warn = (msg) => {
  warnings++
  console.log(`  WARN     ${msg}`)
}
const bad = (msg) => {
  problems++
  console.log(`  FAIL     ${msg}`)
}

function section(name) {
  console.log(`\n== ${name} ==`)
}

// --- binary --------------------------------------------------------------
section("OpenCode V2 binary")
let ocVersion = null
try {
  ocVersion = execFileSync("opencode2", ["--version"], { encoding: "utf8" }).trim()
  ok(`opencode2 found (${ocVersion})`)
} catch {
  bad("opencode2 not found on PATH")
}
{
  const pkg = JSON.parse(readFileSync(path.join(ROOT, "package.json"), "utf8"))
  // testedVersions is an array of full version strings (e.g. "0.0.0-beta-18230");
  // fall back to the older single-string field for local checkouts.
  const testedList = []
    .concat(pkg.opencode?.testedVersions ?? [], pkg.opencode?.testedVersion ?? [])
    .filter(Boolean)
  const matched = testedList.some((t) => ocVersion && ocVersion.includes(t))
  if (ocVersion && testedList.length && !matched) {
    warn(`running ${ocVersion}, tested against: ${testedList.join(", ")} — re-run bypass tests and review docs/limitations.md`)
  } else if (ocVersion) {
    ok(`matches a tested build (${testedList.join(", ")})`)
  }
}

// --- locations -------------------------------------------------------------
section("Locations (scope: " + scopeArg + ")")
const globalCfgDir = path.join(process.env.XDG_CONFIG_HOME || path.join(homedir(), ".config"), "opencode")
const projectCfgDir = path.join(process.cwd(), ".opencode")
const scopes =
  scopeArg === "auto" ? [
    ["project", projectCfgDir],
    ["global", globalCfgDir],
  ] : scopeArg === "global" ? [["global", globalCfgDir]] : [["project", projectCfgDir]]

let foundPlugin = null
let foundConfig = null
for (const [name, dir] of scopes) {
  const p = path.join(dir, "plugins", "security-guard.js")
  const c = path.join(dir, "opencode.jsonc")
  if (existsSync(p)) ok(`plugin present in ${name} scope: ${p}`), (foundPlugin ??= p)
  if (existsSync(c)) {
    try {
      parseJsonc(readFileSync(c, "utf8"))
      ok(`${name} config parses: ${c}`)
      foundConfig ??= c
    } catch (e) {
      bad(`${name} config does not parse: ${c} (${e.message})`)
    }
  }
}
if (!foundPlugin) bad("plugin security-guard.js not found in any checked scope")
if (!foundConfig) bad("generated opencode.jsonc not found in any checked scope")

// --- plugin version ----------------------------------------------------------
section("Plugin integrity")
if (foundPlugin) {
  const repoSrc = readFileSync(path.join(ROOT, "plugin", "security-guard.js"), "utf8")
  const installedSrc = readFileSync(foundPlugin, "utf8")
  const pkg = JSON.parse(readFileSync(path.join(ROOT, "package.json"), "utf8"))
  const vInstalled = installedSrc.match(/export const PLUGIN_VERSION = "([^"]+)"/)?.[1]
  if (vInstalled === pkg.version) ok(`plugin version ${vInstalled}`)
  else bad(`plugin version ${vInstalled ?? "?"} != repository ${pkg.version} — reinstall`)
  if (installedSrc !== repoSrc) warn("installed plugin differs from repository copy (local modifications?)")
  if (!installedSrc.includes("BEGIN GENERATED GUARD POLICY")) bad("installed plugin lacks generated policy block")
}

// --- heartbeat -----------------------------------------------------------------
section("Plugin liveness (heartbeat)")
{
  const dataHome = process.env.XDG_DATA_HOME || path.join(homedir(), ".local", "share")
  const hb = path.join(dataHome, "opencode-security-guard", "health.json")
  if (existsSync(hb)) {
    try {
      const h = JSON.parse(readFileSync(hb, "utf8"))
      const ageH = (Date.now() - Date.parse(h.time)) / 3600e3
      ok(`heartbeat phase=${h.phase} version=${h.version} opencode=${h.opencode ?? "?"} age=${ageH < 1 ? "<1" : Math.round(ageH)}h pid=${h.pid}`)
      if (h.phase !== "active") warn(`heartbeat phase is "${h.phase}" (setup did not complete cleanly?)`)
    } catch (e) {
      bad(`heartbeat unreadable: ${e.message}`)
    }
  } else {
    bad(
      `no heartbeat at ${hb} — the guard has never completed setup here. ` +
        `Install the plugin, restart the service ("opencode2 service restart"), start any session, then re-run.`
    )
  }
}

// --- configuration content ---------------------------------------------------------
section("Configuration rules")
if (foundConfig) {
  const cfg = parseJsonc(readFileSync(foundConfig, "utf8"))
  const perms = cfg.permissions ?? []
  const count = (eff) => perms.filter((r) => r.effect === eff).length
  ok(`permission rules: ${perms.length} (allow=${count("allow")} deny=${count("deny")} ask=${count("ask")})`)
  if (perms.length < 40) warn("rule count lower than the generated baseline; was this config trimmed?")

  const idxEnvDeny = perms.findIndex((r) => r.action === "read" && r.resource === "*.env" && r.effect === "deny")
  const idxExampleAllow = perms.findIndex((r) => r.action === "read" && r.resource === "*.env.example" && r.effect === "allow")
  if (idxEnvDeny === -1) bad('missing read deny for "*.env"')
  if (idxExampleAllow === -1) bad('missing allow exception for "*.env.example"')
  if (idxEnvDeny > -1 && idxExampleAllow > -1 && idxExampleAllow < idxEnvDeny) {
    bad('"*.env.example" allow precedes "*.env" deny — under last-match-wins the exception is dead')
  } else if (idxEnvDeny > -1 && idxExampleAllow > -1) {
    ok("exception ordering valid (*.env.example allowed AFTER *.env deny)")
  }

  const ig = cfg.watcher?.ignore?.length ?? 0
  ig >= 10 ? ok(`watcher ignores: ${ig}`) : warn(`watcher ignores look thin (${ig})`)

  // share: report honestly
  if (cfg.share === "disabled") {
    ok('share="disabled" recorded')
    console.log("           NOTE: current V2 parses but does not ACT on 'share' (no sharing feature exists yet).")
    console.log("           This is an intent marker, not an effective control.")
  } else if (cfg.share === undefined) {
    warn("share not set; add \"share\": \"disabled\" as intent")
  } else {
    warn(`share="${cfg.share}" — review whether you intend that`)
  }
}

// --- MCP configuration ------------------------------------------------------------
section("MCP configuration")
{
  const configured = new Map() // name -> {transport, detail, source}
  let mcpPolicyServers = {}
  try {
    const policySrc = parseJsonc(readFileSync(path.join(ROOT, "policy", "policy.jsonc"), "utf8"))
    for (const [name, s] of Object.entries(policySrc.mcp?.servers ?? {})) mcpPolicyServers[name] = s.trust
  } catch {}

  const configPaths = [
    ...scopes.map(([name, dir]) => [name, path.join(dir, "opencode.jsonc")]),
    ["project-root", path.join(process.cwd(), "opencode.json")],
    ["project-root", path.join(process.cwd(), "opencode.jsonc")],
  ]
  const seenPaths = new Set()
  for (const [, cfgPath] of configPaths) {
    if (!cfgPath || !existsSync(cfgPath) || seenPaths.has(cfgPath)) continue
    seenPaths.add(cfgPath)
    try {
      const cfg = parseJsonc(readFileSync(cfgPath, "utf8"))
      for (const [name, s] of Object.entries(cfg.mcp?.servers ?? {})) {
        if (!configured.has(name)) {
          configured.set(name, {
            transport: s.type ?? "unknown",
            detail: Array.isArray(s.command) ? s.command.join(" ") : typeof s.url === "string" ? s.url : "",
            source: cfgPath,
          })
        }
      }
    } catch {}
  }

  // Orphaned rules: permissions naming <server>_<tool> where the server is
  // configured nowhere. Native actions containing underscores are excluded.
  const NATIVE_ACTIONS = new Set(["external_directory", "doom_loop"])
  const orphans = new Set()
  for (const cfgPath of seenPaths) {
    try {
      const cfg = parseJsonc(readFileSync(cfgPath, "utf8"))
      for (const r of cfg.permissions ?? []) {
        const a = String(r.action ?? "")
        if (NATIVE_ACTIONS.has(a)) continue
        const under = a.indexOf("_")
        if (under > 0 && !NATIVE_ACTIONS.has(a)) {
          const srv = a.slice(0, under)
          if (!configured.has(srv)) orphans.add(`${srv} (rule action "${a}")`)
        }
      }
    } catch {}
  }

  if (configured.size === 0) {
    console.log("           no MCP servers configured in scanned scopes (nothing to report)")
  } else {
    ok(`MCP servers configured: ${configured.size}`)
    for (const [name, info] of configured) {
      const trust = mcpPolicyServers[name] ?? "unlisted-server"
      console.log(`           - ${name} [${info.transport}] trust=${trust}${trust === "unlisted-server" ? "  <-- not in policy; conservative defaults apply" : ""}`)
      if (info.detail) console.log(`             ${info.detail}`)
    }
  }
  if (orphans.size) warn(`orphaned MCP permission rules reference servers that are not configured: ${[...orphans].join("; ")}`)
}

// --- live log check --------------------------------------------------------------------
if (live) {
  section("Live log scan (~/.local/share/opencode/log)")
  const dataHome = process.env.XDG_DATA_HOME || path.join(homedir(), ".local", "share")
  const hbPath = path.join(dataHome, "opencode-security-guard", "health.json")
  let cutoff = Date.now() - 24 * 3600e3
  try {
    const hbTime = JSON.parse(readFileSync(hbPath, "utf8")).time
    if (hbTime) cutoff = Math.min(Date.now(), Date.parse(hbTime) - 5000)
  } catch {}
  const logDir = path.join(dataHome, "opencode", "log")
  try {
    const files = execFileSync("ls", ["-t", logDir], { encoding: "utf8" }).split("\n").filter(Boolean)
    let loadedLine = false
    let failedLine = false
    // Only inspect the tail of the newest logs and only entries at/after the
    // heartbeat time — old failures from previous plugin versions must not
    // fail the current check.
    for (const f of files.slice(0, 2)) {
      const text = readFileSync(path.join(logDir, f), "utf8").slice(-400000)
      for (const line of text.split("\n")) {
        const m = line.match(/^timestamp=([^\s]+)/)
        if (!m || Date.parse(m[1]) < cutoff) continue
        if (/msg="loading plugin".*security-guard\.js/.test(line)) loadedLine = true
        // Only real load-failure records count; INFO lines that merely ECHO a
        // shell command containing these words (e.g. running this very doctor
        // through OpenCode) must not match.
        const level = line.match(/level=(INFO|WARN|ERROR)/)?.[1]
        const isFailureRecord =
          (level === "WARN" || level === "ERROR") &&
          /failed to load plugin/.test(line) &&
          /(target|path)=\S*security-guard\.js/.test(line)
        if (isFailureRecord) failedLine = true
      }
    }
    if (failedLine) bad("server logged a FAILURE while loading a security-guard.js since the last heartbeat")
    else if (loadedLine) ok("server logged successful plugin load line(s) since heartbeat")
    else warn("no security-guard load line since heartbeat — start a session or restart the service first")
  } catch {
    warn("could not read log directory")
  }
}

console.log(`\nresult: ${problems ? `${problems} problem(s)` : "healthy"}${warnings ? `, ${warnings} warning(s)` : ""}`)
process.exit(problems ? 1 : 0)
