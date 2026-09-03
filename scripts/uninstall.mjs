#!/usr/bin/env node
/**
 * Uninstall Security Guard for OpenCode from a scope, safely.
 *
 *   node scripts/uninstall.mjs --scope project|global [--yes]
 *
 * Removes:
 *   - <config-dir>/plugins/security-guard.js
 *   - <config-dir>/plugins/security-guard.config.json (if present)
 *   - the generated config ONLY if it still matches this repository's
 *     generated output byte-for-byte (otherwise it is left in place and the
 *     drift is reported — never destroy a file you cannot reproduce).
 *
 * Backups previously created by install.mjs are preserved and listed.
 */
import { readFileSync, existsSync, unlinkSync, readdirSync, rmdirSync } from "node:fs"
import { createHash } from "node:crypto"
import { homedir } from "node:os"
import path from "node:path"
import { fileURLToPath } from "node:url"

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..")
const args = process.argv.slice(2)
const opt = (n) => args.includes(n)
const scope = opt("--scope") ? args[args.indexOf("--scope") + 1] : null
const yes = opt("--yes")

if (!["project", "global"].includes(scope ?? "")) {
  console.error("usage: node scripts/uninstall.mjs --scope project|global [--yes]")
  process.exit(1)
}
const cfgDir =
  scope === "global"
    ? path.join(process.env.XDG_CONFIG_HOME || path.join(homedir(), ".config"), "opencode")
    : path.join(process.cwd(), ".opencode")
const pluginFile = path.join(cfgDir, "plugins", "security-guard.js")
const cfgOverride = path.join(cfgDir, "plugins", "security-guard.config.json")
const configFile = path.join(cfgDir, "opencode.jsonc")
const repoPlugin = readFileSync(path.join(ROOT, "plugin", "security-guard.js"))
const repoConfig = readFileSync(path.join(ROOT, "config", "opencode.jsonc"))
const sha256 = (buf) => createHash("sha256").update(buf).digest("hex")

const plan = []
if (existsSync(pluginFile)) {
  const installed = readFileSync(pluginFile)
  const drifted = sha256(installed) !== sha256(repoPlugin)
  plan.push({ file: pluginFile, kind: drifted ? "DRIFTED-PLUGIN" : "plugin", remove: true })
} else {
  console.log(`no plugin at ${pluginFile}`)
}
if (existsSync(cfgOverride)) plan.push({ file: cfgOverride, kind: "override-config", remove: true })

if (existsSync(configFile)) {
  const current = readFileSync(configFile)
  const generated = readFileSync(path.join(ROOT, "config", "opencode.jsonc"))
  if (sha256(current) === sha256(generated)) {
    plan.push({ file: configFile, kind: "generated config (exact match)", remove: true })
  } else {
    console.log(
      `KEEP ${configFile}: it differs from the generated output (user customizations or newer policy).\n` +
        `Remove the "permissions"/"watcher"/"share" keys manually if you no longer want them.`
    )
  }
}

if (!plan.length) {
  console.log("nothing to uninstall in this scope.")
  process.exit(0)
}
console.log(`Uninstalling from ${scope} scope (${cfgDir}):`)
for (const p of plan) console.log(`  remove ${p.file}  [${p.kind}]`)
const backups = existsSync(cfgDir)
  ? readdirSync(cfgDir).filter((d) => d.startsWith("security-guard-backup-"))
  : []
if (backups.length) console.log(`\npreserved backups remain available:\n  ${backups.map((b) => path.join(cfgDir, b)).join("\n  ")}`)
if (!yes) {
  console.log("\ndry run only; re-run with --yes to apply.")
  process.exit(0)
}
for (const p of plan) {
  if (p.remove) unlinkSync(p.file)
  console.log(`removed ${p.file}`)
}
// Drop the plugins dir if we emptied it.
try {
  const pd = path.join(cfgDir, "plugins")
  if (readdirSync(pd).length === 0) rmdirSync(pd)
} catch {}
console.log("\nrun `opencode2 service restart` so the running service drops the plugin,\nthen `node scripts/doctor.mjs` to confirm removal.")
