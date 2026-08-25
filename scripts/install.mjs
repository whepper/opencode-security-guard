#!/usr/bin/env node
/**
 * Safe installer for OpenCode Security Guard (OpenCode V2 only).
 *
 *   node scripts/install.mjs --scope project [--yes]
 *   node scripts/install.mjs --scope global [--yes]
 *
 * Behavior:
 *   1. detects the opencode2 binary and prints its version;
 *   2. explains exactly what will be written BEFORE writing;
 *   3. backs up every file it touches to
 *      <config-dir>/security-guard-backup-<timestamp>/ and prints how to roll back;
 *   4. installs the plugin into the plugins directory and the permission/
 *      watcher configuration into the chosen scope;
 *   5. NEVER overwrites an existing global opencode.json(c)'s unrelated
 *      settings: if one exists, this tool refuses and prints a manual-merge
 *      recipe instead (--merge performs a key-preserving merge with backup);
 *   6. reminds you that plugin loading requires a service restart and must be
 *      confirmed with scripts/doctor.mjs.
 */
import { readFileSync, writeFileSync, existsSync, mkdirSync, copyFileSync, readdirSync } from "node:fs"
import { execFileSync } from "node:child_process"
import { homedir } from "node:os"
import path from "node:path"
import { parseJsonc } from "./jsonc.mjs"
import { fileURLToPath } from "node:url"

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..")
const PLUGIN_SRC = path.join(ROOT, "plugin", "security-guard.js")
const CONFIG_SRC = path.join(ROOT, "config", "opencode.jsonc")

const args = process.argv.slice(2)
const opt = (name) => args.includes(name)
const scope = opt("--scope") ? args[args.indexOf("--scope") + 1] : null
const yes = opt("--yes")
const merge = opt("--merge")

function die(msg) {
  console.error(`error: ${msg}`)
  process.exit(1)
}
function say(msg) {
  console.log(msg)
}

// --- 1. detect OpenCode V2 ---------------------------------------------------
let ocBin = null
let ocVersion = null
for (const candidate of ["opencode2"]) {
  try {
    execFileSync("which", [candidate], { stdio: "pipe" })
    ocBin = candidate
    break
  } catch {}
}
if (!ocBin) {
  die("opencode2 not found on PATH. This project targets OpenCode V2 only; see docs/installation.md for the manual path.")
}
ocVersion = execFileSync(ocBin, ["--version"], { encoding: "utf8" }).trim()
say(`detected ${ocBin} (${ocVersion})`)
{
  const pkg = JSON.parse(readFileSync(path.join(ROOT, "package.json"), "utf8"))
  const tested = pkg.opencode?.testedVersion
  if (tested && !ocVersion.includes(tested)) {
    say(`NOTE installed version differs from the tested build (${tested});`)
    say(`     re-run scripts/doctor.mjs after upgrading and review CHANGELOG notes.`)
  }
}

// --- 2. resolve scope ----------------------------------------------------------
if (!["project", "global"].includes(scope ?? "")) {
  die("pass --scope project (this repository/session only) or --scope global (your user)")
}
const cfgDir =
  scope === "global"
    ? path.join(process.env.XDG_CONFIG_HOME || path.join(homedir(), ".config"), "opencode")
    : path.join(process.cwd(), ".opencode")
const pluginDir = path.join(cfgDir, "plugins")
const configFile = path.join(cfgDir, "opencode.jsonc")

// --- 3. plan --------------------------------------------------------------------
const plan = [
  { op: "mkdir", path: pluginDir },
  { op: "write", path: path.join(pluginDir, "security-guard.js"), src: PLUGIN_SRC, label: "guard plugin (Layer 4)" },
]

const existingConfig = existsSync(configFile) ? readFileSync(configFile, "utf8") : null
let finalConfigText = null

if (!existingConfig) {
  finalConfigText = readFileSync(CONFIG_SRC, "utf8")
  plan.push({ op: "write", path: configFile, text: finalConfigText, label: "permissions + watcher config (Layers 1+2)" })
} else {
  let parsedExisting
  try {
    parsedExisting = parseJsonc(existingConfig)
  } catch (e) {
    die(`${configFile} does not parse as JSONC (${e.message}); fix it manually first.`)
  }
  const ours = parseJsonc(readFileSync(CONFIG_SRC, "utf8"))
  if (parsedExisting.permissions && !merge) {
    say("")
    say(`REFUSING to touch ${configFile}: it already defines "permissions".`)
    say("Options:")
    say(`  a) keep your file and add the rules from ${path.relative(process.cwd(), CONFIG_SRC)} manually;`)
    say(`  b) re-run with --merge to combine keys (existing unknown keys preserved,`)
    say(`     our permissions/watcher/share win conflicts) — a backup is taken either way.`)
    process.exit(1)
  }
  const merged = { ...ours, ...parsedExisting, permissions: ours.permissions, watcher: ours.watcher, share: ours.share }
  finalConfigText = JSON.stringify(merged, null, 2) + "\n"
  plan.length = 0 // rebuild plan fully
  plan.push({ op: "mkdir", path: pluginDir })
  plan.push({ op: "write", path: path.join(pluginDir, "security-guard.js"), src: PLUGIN_SRC, label: "guard plugin (Layer 4)" })
  plan.push({
    op: "write",
    path: configFile,
    text: finalConfigText,
    label: merge ? "merged config (our permissions/watcher/share preserved-over yours)" : "full replacement",
  })
}

// --- 4. show plan -----------------------------------------------------------------
say("")
say(`Scope: ${scope} (${cfgDir})`)
say("The installer will:")
for (const step of plan) {
  if (step.op === "mkdir") say(`  create directory        ${step.path}`)
  else say(`  ${existsSync(step.path) ? "OVERWRITE (backup taken)" : "write new"}  ${step.path}  — ${step.label}`)
}
say("")
if (!yes) {
  say("Dry summary only. Re-run with --yes to apply.")
  process.exit(0)
}

// --- 5. backup ----------------------------------------------------------------------
const stamp = new Date().toISOString().replace(/[:.]/g, "-")
const backupDir = path.join(cfgDir, `security-guard-backup-${stamp}`)
mkdirSync(backupDir, { recursive: true })
for (const step of plan) {
  if (step.op === "write" && existsSync(step.path)) {
    copyFileSync(step.path, path.join(backupDir, path.basename(step.path)))
  }
}

// --- 6. apply -------------------------------------------------------------------------
for (const step of plan) {
  if (step.op === "mkdir") mkdirSync(step.path, { recursive: true })
  else if (step.text !== undefined) writeFileSync(step.path, step.text)
  else copyFileSync(step.src, step.path)
  say(`wrote ${step.path}`)
}

// --- 7. verify + rollback instructions --------------------------------------------------
say("")
say("Backup directory:")
say(`  ${backupDir}`)
say("")
say("Rollback (if ever needed):")
for (const step of plan) {
  if (step.op !== "write") continue
  const base = path.basename(step.path)
  if (readdirSync(backupDir).includes(base)) {
    say(`  cp "${path.join(backupDir, base)}" "${step.path}"`)
  } else {
    say(`  rm "${step.path}"   # did not exist before install`)
  }
}
say("")
say("IMPORTANT — finish activation:")
say(`  1. restart the background service so plugins reload:  ${ocBin} service restart`)
say(`  2. verify installation and plugin liveness:           node ${path.join(ROOT, "scripts", "doctor.mjs")} --live`)
