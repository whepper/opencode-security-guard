#!/usr/bin/env node
/**
 * Generate all derived artifacts from policy/policy.jsonc (single source of truth):
 *
 *   1. config/opencode.jsonc      — OpenCode V2 permissions + watcher config (Layer 1+2)
 *   2. plugin/security-guard.js   — injects the compiled guard rule set between
 *                                   GENERATED-POLICY markers (Layer 4 inputs)
 *
 * Usage:
 *   node scripts/generate-config.mjs [--profile baseline|strict] [--check]
 *
 * --check regenerates in memory and fails if any output would differ
 * (used by CI and scripts/validate.mjs to catch drift).
 */
import { readFileSync, writeFileSync } from "node:fs"
import { fileURLToPath } from "node:url"
import path from "node:path"
import { parseJsonc } from "./jsonc.mjs"

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..")
const POLICY_PATH = path.join(ROOT, "policy", "policy.jsonc")
const CONFIG_PATH = path.join(ROOT, "config", "opencode.jsonc")
const PLUGIN_PATH = path.join(ROOT, "plugin", "security-guard.js")
const BEGIN = "// ==== BEGIN GENERATED GUARD POLICY (regenerate via: node scripts/generate-config.mjs) ===="
const END = "// ==== END GENERATED GUARD POLICY ===="

function parseArgs(argv) {
  const args = { profile: "baseline", check: false }
  for (let i = 0; i < argv.length; i++) {
    if (argv[i] === "--profile") args.profile = argv[++i]
    else if (argv[i] === "--check") args.check = true
    else throw new Error(`Unknown argument: ${argv[i]}`)
  }
  if (!["baseline", "strict"].includes(args.profile)) {
    throw new Error(`Unknown profile "${args.profile}" (expected baseline|strict)`)
  }
  return args
}

/** Apply a profile's Layer-1 overrides to the ordered permission rules.
 *  Explicit MCP tool DENIES are mirrored as native rules (belt-and-braces:
 *  native denies survive saved approvals and run even if the plugin is
 *  absent) inserted BEFORE the safe-exceptions section. */
function resolvePermissions(policy, profileName) {
  const profile = policy.profiles[profileName]
  const overrides = profile?.overrides ?? {}
  const fsRules = policy.permissions.map((rule) => {
    const effect = overrides[rule.id] ?? rule.effect
    return { id: rule.id, action: rule.action, resource: rule.resource, effect, reason: rule.reason }
  })
  const firstExcIdx = fsRules.findIndex((r) => r.id.startsWith("SG-EXC"))
  const exc = fsRules.filter((r) => r.id.startsWith("SG-EXC"))
  const head = firstExcIdx === -1 ? fsRules : fsRules.slice(0, firstExcIdx)
  const mcpNative = (policy.mcp?.tools ?? [])
    .filter((t) => t.effect === "deny")
    .map((t) => ({
      id: `${t.id}-NATIVE`,
      action: `${t.server}_${t.tool}`,
      resource: "*",
      effect: "deny",
      reason: `native mirror of ${t.id} (runs even without the guard plugin): ${t.reason}`,
    }))
  return [...head, ...mcpNative, ...exc]
}

/** Emit opencode.jsonc text. Rule IDs/reasons become comments (the V2 schema
 *  strips unknown fields like "reason", verified against beta-18219). */
function renderConfig(policy, profileName, rules) {
  const watcher = policy.watcherIgnore.map((w) => JSON.stringify(w)).join(",\n    ")
  const permLines = rules
    .map((r) => `    // ${r.id}: ${r.reason}\n    { "action": ${JSON.stringify(r.action)}, "resource": ${JSON.stringify(r.resource)}, "effect": ${JSON.stringify(r.effect)} }`)
    .join(",\n")
  return `{
  // ============================================================================
  // GENERATED FILE — do not edit by hand.
  // Source of truth: policy/policy.jsonc (profile: ${profileName}, v${policy.policyVersion})
  // Regenerate:      node scripts/generate-config.mjs${profileName === "baseline" ? "" : ` --profile ${profileName}`}
  //
  // Dialect: OpenCode V2 ("permissions" ordered array). Verified semantics:
  //   - LAST matching rule wins; unmatched resources default to "ask"
  //   - "*" spans "/" (there is no "**"); matching covers the whole value
  //   - multi-resource operations deny if ANY resource resolves to deny
  //   - explicit "deny" can never be overridden by saved approvals
  //
  // Section order is significant: broad allows -> hard denies -> asks -> safe
  // exceptions (which must stay last so they win).
  // ============================================================================
  "$schema": "https://opencode.ai/config.json",

  // Session sharing. NOTE (honesty): current V2 parses but does not act on this
  // field (no sharing feature exists yet). It is kept as intent, not as a control.
  "share": "disabled",

  // Layer 2 — watcher exclusions reduce accidental discovery/indexing.
  // NOT A SECURITY BOUNDARY; agent-run tools can still read these paths.
  "watcher": {
    "ignore": [
    ${watcher}
    ]
  },

  // Layer 1 — native permission rules (ordered).
  "permissions": [
${permLines}
  ],

  // Layer 4 — semantic shell inspection is enforced by plugin/security-guard.js,
  // whose rule set is compiled from the same policy file. Native shell rules see
  // raw command text only; they cannot express "reader verb x secret path".
  //
  // MCP note: MCP tools surface under actions named "<server>_<tool>" (e.g.
  // "filesystem_read_file"). Filesystem-style MCP servers DO NOT pass through
  // native read/edit rules — add explicit rules per server, e.g.:
  //     { "action": "myserver_execute", "resource": "*", "effect": "ask" }
  // See docs/mcp.md before connecting any MCP server that can reach files or
  // the network.
}
`
}

function renderGuardBlob(policy, profileName) {
  const g = policy.guard
  const strict = g.profiles[profileName] ?? {}
  const blob = {
    policyVersion: policy.policyVersion,
    profile: profileName,
    denyPaths: g.denyPaths,
    askPaths: g.askPaths,
    exceptionPaths: g.exceptionPaths,
    promoteAskToDenyIds: strict.promoteAskToDenyIds ?? [],
    envVarNamePattern: g.envVarNamePattern,
    mcp: policy.mcp ?? {},
  }
  return `${BEGIN}
// Compiled from policy/policy.jsonc — EDIT THE POLICY, NOT THIS BLOCK.
export const GENERATED_GUARD_POLICY = Object.freeze(${JSON.stringify(blob, null, 2)})
${END}`
}

function injectGuardBlock(pluginText, block) {
  if (pluginText.includes(BEGIN) && pluginText.includes(END)) {
    const re = new RegExp(`${BEGIN.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")}[\\s\\S]*?${END.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")}`)
    return pluginText.replace(re, block)
  }
  if (pluginText.includes("/* GENERATED-GUARD-MARKERS */")) {
    return pluginText.replace("/* GENERATED-GUARD-MARKERS */", block)
  }
  throw new Error(`plugin/security-guard.js has no guard-policy markers (${BEGIN.slice(0, 40)}...)`)
}

function main() {
  const args = parseArgs(process.argv.slice(2))
  const policy = parseJsonc(readFileSync(POLICY_PATH, "utf8"))
  const rules = resolvePermissions(policy, args.profile)

  const configText = renderConfig(policy, args.profile, rules)
  const guardBlock = renderGuardBlob(policy, args.profile)
  let pluginText = readFileSync(PLUGIN_PATH, "utf8")
  const newPluginText = injectGuardBlock(pluginText, guardBlock)

  if (args.check) {
    const currentConfig = readFileSync(CONFIG_PATH, "utf8")
    if (currentConfig !== configText) {
      console.error("DRIFT: config/opencode.jsonc does not match policy/policy.jsonc")
      process.exit(1)
    }
    if (newPluginText !== pluginText) {
      console.error("DRIFT: plugin/security-guard.js guard-policy block does not match policy/policy.jsonc")
      process.exit(1)
    }
    console.log("check: derived artifacts match policy (no drift)")
    return
  }

  writeFileSync(CONFIG_PATH, configText)
  if (newPluginText !== pluginText) writeFileSync(PLUGIN_PATH, newPluginText)
  const counts = rules.reduce((acc, r) => ((acc[r.effect] = (acc[r.effect] ?? 0) + 1), acc), {})
  console.log(
    `generated config/opencode.jsonc (profile=${args.profile}, rules=${rules.length}: ` +
      `${counts.allow ?? 0} allow / ${counts.deny ?? 0} deny / ${counts.ask ?? 0} ask, ` +
      `watcher ignores=${policy.watcherIgnore.length}) and refreshed plugin guard policy`
  )
}

main()
