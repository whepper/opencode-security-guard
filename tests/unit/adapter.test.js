/**
 * Adapter-level integration tests: run the real plugin `setup()` against a
 * fake ctx and drive recorded hooks. This is the layer that would have
 * caught reference errors inside hook closures (unit tests only cover the
 * pure engine).
 *
 * XDG_DATA_HOME is redirected so tests never touch the real heartbeat.
 */
import { test, beforeEach, afterEach } from "node:test"
import assert from "node:assert/strict"
import { mkdtempSync, rmSync, readFileSync, writeFileSync } from "node:fs"
import { tmpdir } from "node:os"
import path from "node:path"
import securityGuard from "../../plugin/security-guard.js"

let dataHome

beforeEach(() => {
  dataHome = mkdtempSync(path.join(tmpdir(), "sg-heartbeat-"))
  process.env.XDG_DATA_HOME = dataHome
})
afterEach(() => {
  delete process.env.XDG_DATA_HOME
  rmSync(dataHome, { recursive: true, force: true })
})

function makeCtx() {
  const hooks = {}
  const ctx = {
    app: { name: "opencode", version: "0.0.0-test", channel: "beta" },
    options: {},
    mcp: { list: async () => ({ servers: [{ name: "dummy" }] }) },
    tool: {
      hook: async (name, cb) => {
        hooks[name] = hooks[name] || []
        hooks[name].push(cb)
      },
    },
    permission: {
      hook: async (name, cb) => {
        hooks[`perm:${name}`] = cb
      },
    },
  }
  return { ctx, hooks }
}

const P = JSON.parse(JSON.stringify((await import("../../plugin/security-guard.js")).GENERATED_GUARD_POLICY))
P.mcp.servers = { dummy: { trust: "untrusted", reason: "test fixture" } }

test("setup registers hooks and writes an active heartbeat", async () => {
  const { ctx, hooks } = makeCtx()
  await securityGuard.setup(ctx)
  assert.ok(hooks["execute.before"])
  assert.ok(hooks["perm:evaluate"])
  const hbPath = path.join(dataHome, "opencode-security-guard", "health.json")
  const hb = JSON.parse(readFileSync(hbPath, "utf8"))
  assert.equal(hb.phase, "active")
  assert.equal(hb.plugin, "security-guard")
})

test("execute.before blocks denied-class MCP calls mechanically", async () => {
  const { ctx, hooks } = makeCtx()
  // Blocked-trust server delivered through the sibling-config override
  // mechanism (SG_CONFIG_FILE), mirroring real deployments.
  const cfgPath = path.join(tmpdir(), `sg-cfg-${Date.now()}.json`)
  writeFileSync(
    cfgPath,
    JSON.stringify({ mcpServers: { legacy: { trust: "blocked", reason: "test fixture" } } })
  )
  process.env.SG_CONFIG_FILE = cfgPath
  try {
    await securityGuard.setup(ctx)
    assert.throws(
      () =>
        hooks["execute.before"][0]({
          tool: "legacy_run_shell",
          callID: "c1",
          input: { cmd: "ls" },
        }),
      /BLOCKED/
    )
  } finally {
    delete process.env.SG_CONFIG_FILE
    rmSync(cfgPath, { force: true })
  }
})

test("execute.before hard-blocks protected-path arguments on MCP tools", async () => {
  const { ctx, hooks } = makeCtx()
  await securityGuard.setup(ctx)
  assert.throws(
    () =>
      hooks["execute.before"][0]({
        tool: "dummy_read_file",
        callID: "c2",
        input: { file: ".env" },
      }),
    /MCP-ARG-PATH-001/
  )
})

test("permission.evaluate escalates unlisted-server read-only allows to ask", async () => {
  const { ctx, hooks } = makeCtx()
  await securityGuard.setup(ctx)
  const event = { action: "dummy_get_note", resources: ["*"], effect: "allow" }
  await hooks["perm:evaluate"](event)
  assert.equal(event.effect, "ask")
  assert.match(event.message, /dummy\/get_note/)
})

test("permission.evaluate leaves configured denies untouched (deny wins)", async () => {
  // Simulate a configured native deny: evaluate would not even fire; but the
  // guard must never downgrade an existing deny either way.
  const { ctx, hooks } = makeCtx()
  await securityGuard.setup(ctx)
  const event = { action: "read", resources: ["README.md"], effect: "deny" }
  await hooks["perm:evaluate"](event)
  assert.equal(event.effect, "deny") // unchanged, no message injected
})

// ---------------------------------------------------------------------------
// Real-filesystem symlink integration (BYP-FS-LINK regression, end-to-end)
// ---------------------------------------------------------------------------

import { mkdtempSync as mkd2, symlinkSync, writeFileSync as wfs, rmSync as rm2 } from "node:fs"

test("real symlink: benign name resolving onto a secret file is blocked by the adapter", async () => {
  const dir = mkd2(path.join(tmpdir(), "sg-symlink-"))
  try {
    wfs(path.join(dir, ".env"), "# FAKE-NOT-A-REAL-SECRET\nX=1\n")
    symlinkSync(path.join(dir, ".env"), path.join(dir, "mynotes.txt"))
    const { ctx, hooks } = makeCtx()
    process.env.SG_CONFIG_FILE = path.join(dir, "no-config.json")
    try {
      await securityGuard.setup(ctx)
      assert.throws(
        () => hooks["execute.before"][0]({ tool: "read", callID: "c9", input: { filePath: path.join(dir, "mynotes.txt") } }),
        /GG-ENV-001/
      )
    } finally {
      delete process.env.SG_CONFIG_FILE
    }
  } finally {
    rm2(dir, { recursive: true, force: true })
  }
})
