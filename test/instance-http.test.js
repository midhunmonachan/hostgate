import assert from "node:assert/strict";
import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import http from "node:http";
import { spawn, spawnSync } from "node:child_process";
import { once } from "node:events";
import { fileURLToPath } from "node:url";
import test from "node:test";
import { shellEnvironment } from "../src/shell.js";

const root = fileURLToPath(new URL("../", import.meta.url));
const cli = path.join(root, "bin/hostgate.js");
const isWindows = process.platform === "win32";
function fixture(parent, label) {
  const home = path.join(parent, label);
  for (const p of [home, path.join(home, "AppData/Roaming"), path.join(home, "AppData/Local/Temp"), path.join(home, ".config/hostgate")]) fs.mkdirSync(p, { recursive: true });
  const password = crypto.randomUUID() + '#"=literal', username = "isolated-owner";
  const config = path.join(home, ".config/hostgate/.env");
  fs.writeFileSync(config, `HOST=127.0.0.1\nPORT=0\nHOSTGATE_OAUTH_USERNAME=${username}\nHOSTGATE_OAUTH_PASSWORD=${password}\n`, { mode: 0o600 });
  return { home, password, username, config, state: path.join(home, ".local/share/hostgate/oauth-state.json"), logs: path.join(home, ".local/share/hostgate/executions.jsonl"), env: {
    ...shellEnvironment(), HOME: home, USERPROFILE: home,
    APPDATA: path.join(home, "AppData/Roaming"), LOCALAPPDATA: path.join(home, "AppData/Local"),
    TEMP: path.join(home, "AppData/Local/Temp"), TMP: path.join(home, "AppData/Local/Temp"),
    XDG_CONFIG_HOME: path.join(home, ".config"), XDG_DATA_HOME: path.join(home, ".local/share"), XDG_CACHE_HOME: path.join(home, ".cache")
  } };
}
function launch(f, resource, children) {
  const env = { ...f.env, ...(resource ? { HOSTGATE_PUBLIC_URL: resource } : {}) };
  const child = spawn(process.execPath, [cli, "start"], { cwd: root, env, windowsHide: true, stdio: ["ignore", "pipe", "pipe"] });
  children.push(child);
  let output = "", errors = "";
  child.stderr.on("data", b => { errors += b; });
  const ready = new Promise((resolve, reject) => {
    const timer = setTimeout(() => { child.kill(); reject(new Error("Isolated server readiness timed out.")); }, 15000);
    child.once("error", () => { clearTimeout(timer); reject(new Error("Isolated server failed to spawn.")); });
    child.once("exit", () => { clearTimeout(timer); reject(new Error("Isolated server exited before readiness: " + errors)); });
    child.stdout.on("data", b => {
      output += b;
      const match = output.match(/Hostgate listening at http:\/\/127\.0\.0\.1:(\d+)\/mcp/);
      if (match && output.includes(`OAuth state: ${f.state}`)) { clearTimeout(timer); resolve(`http://127.0.0.1:${match[1]}`); }
    });
  });
  return { child, ready };
}
async function stop(child) {
  if (child.exitCode !== null || child.signalCode !== null) return;
  const closed = once(child, "close"); child.kill(); await closed;
}
const request = (url, options = {}) => fetch(url, { ...options, redirect: "manual", signal: AbortSignal.timeout(20000) });
const post = (url, body, headers = {}) => request(url, { method: "POST", headers: { "Content-Type": "application/json", ...headers }, body: JSON.stringify(body) });
let id = 0;
async function rpc(base, token, method, params = {}, prefix = "/hostgate") {
  const requestId = ++id;
  const response = await post(`${base}${prefix}/mcp`, { jsonrpc: "2.0", id: requestId, method, params }, {
    Authorization: `Bearer ${token}`, Accept: "application/json, text/event-stream", "MCP-Protocol-Version": "2025-03-26"
  });
  if (response.status !== 200) return { httpStatus: response.status };
  const text = await response.text();
  const message = response.headers.get("content-type")?.includes("text/event-stream") ? text.split(/\r?\n/).filter(s => s.startsWith("data: ")).map(s => JSON.parse(s.slice(6))).find(x => x.id === requestId) : JSON.parse(text);
  assert(message); assert.equal(message.error, undefined);
  const result = message.result;
  if (result?.structuredContent?.execution) assert.equal(result.structuredContent.execution.requestId, response.headers.get("X-Hostgate-Request-Id"));
  return result;
}
async function grant(base, f, resource, scope = "all") {
  const registration = await post(`${base}/hostgate/oauth/register`, { client_name: "Single-instance test", redirect_uris: ["http://127.0.0.1/callback"] });
  assert.equal(registration.status, 201); const clientId = (await registration.json()).client_id;
  const verifier = crypto.randomBytes(32).toString("base64url");
  const fields = { client_id: clientId, redirect_uri: "http://127.0.0.1/callback", response_type: "code", code_challenge_method: "S256", code_challenge: crypto.createHash("sha256").update(verifier).digest("base64url"), scope, ...(resource ? { resource } : {}) };
  const auth = await request(`${base}/hostgate/oauth/authorize`, { method: "POST", headers: { "Content-Type": "application/x-www-form-urlencoded" }, body: new URLSearchParams({ ...fields, username: f.username, password: f.password }) });
  assert.equal(auth.status, 302);
  return { fields, exchange: { client_id: clientId, redirect_uri: fields.redirect_uri, grant_type: "authorization_code", code: new URL(auth.headers.get("location")).searchParams.get("code"), code_verifier: verifier, ...(resource ? { resource } : {}) } };
}
async function exchange(base, g) { return post(`${base}/hostgate/oauth/token`, g.exchange); }
async function authorize(base, f, resource, scope = "all") {
  const g = await grant(base, f, resource, scope), response = await exchange(base, g); assert.equal(response.status, 200);
  return { ...g, token: (await response.json()).access_token };
}
const quote = s => isWindows ? `'${s.replaceAll("'", "''")}'` : `'${s.replaceAll("'", "'\"'\"'")}'`;
const scriptCommand = (file, args = []) => `${isWindows ? "& " : ""}${quote(process.execPath)} ${quote(file)} ${args.map(quote).join(" ")}`;

test("single endpoint supports independent concurrent requests without a host catalog", { timeout: 90000 }, async t => {
  const parent = fs.mkdtempSync(path.join(os.tmpdir(), "hostgate-instance-http-")), children = [];
  t.after(async () => { for (const child of children) await stop(child); });
  t.diagnostic(`Isolated single-instance fixtures retained: ${parent}`);
  const a = fixture(parent, "instance-a"), b = fixture(parent, "instance-b");
  const endpointA = "https://instance-a.example.test/hostgate/mcp", endpointB = "https://instance-b.example.test/mcp";
  const [baseA, baseB] = await Promise.all([launch(a, endpointA, children).ready, launch(b, endpointB, children).ready]);
  const aa = await authorize(baseA, a, endpointA), otherConnection = await authorize(baseA, a, endpointA), bb = await authorize(baseB, b, endpointB);
  const credentialsBefore = [a, b].map(f => fs.readFileSync(f.config));
  await t.test("four strict tool schemas have no host selectors and retain their safety metadata", async () => {
    const { tools } = await rpc(baseA, aa.token, "tools/list");
    assert.deepEqual(tools.map(x => x.name).sort(), ["read", "shell", "status", "write"]);
    for (const tool of tools) {
      assert.equal(tool.inputSchema.properties.target, undefined); assert.equal(tool.inputSchema.properties.hostId, undefined);
      assert.equal(tool.inputSchema.additionalProperties, false); assert(!(tool.inputSchema.required || []).includes("contextId"));
    }
    assert.deepEqual(tools.find(x => x.name === "shell").annotations, { readOnlyHint: false, destructiveHint: true, openWorldHint: true });
    assert.deepEqual(tools.find(x => x.name === "write").annotations, { readOnlyHint: false, destructiveHint: true, openWorldHint: false });
    assert.match(tools.find(x => x.name === "shell").description, /unrestricted.*intentionally dangerous/);
    const status = await rpc(baseA, aa.token, "tools/call", { name: "status", arguments: {} });
    assert.equal(status.structuredContent.hostname, os.hostname()); assert.equal(status.structuredContent.execution.contextId, null);
  });
  await t.test("canonical discovery and token audiences remain endpoint-bound across root aliases", async () => {
    for (const [base, endpoint] of [[baseA, endpointA], [baseB, endpointB]]) {
      for (const prefix of ["", "/hostgate"]) {
        const response = await request(`${base}${prefix}/.well-known/oauth-authorization-server`, { headers: { Host: "untrusted.invalid" } });
        assert.equal((await response.json()).issuer, endpoint.slice(0, -4));
      }
    }
    assert.equal((await rpc(baseA, bb.token, "tools/list")).httpStatus, 401); assert.equal((await rpc(baseB, aa.token, "tools/list")).httpStatus, 401);
    assert.equal((await rpc(baseA, aa.token, "tools/call", { name: "status", arguments: {} }, "")).isError, undefined);
    const authUrl = `${baseA}/hostgate/oauth/authorize`;
    const missing = { ...aa.fields }; delete missing.resource;
    for (const fields of [missing, { ...aa.fields, resource: endpointB }]) assert.equal((await request(`${authUrl}?${new URLSearchParams(fields)}`)).status, 400);
    const repeated = new URLSearchParams(aa.fields); repeated.append("resource", endpointA); repeated.set("username", a.username); repeated.set("password", a.password);
    assert.equal((await request(authUrl, { method: "POST", headers: { "Content-Type": "application/x-www-form-urlencoded" }, body: repeated })).status, 400);
    const pending = await grant(baseA, a, endpointA);
    assert.equal((await post(`${baseA}/hostgate/oauth/token`, { ...pending.exchange, resource: endpointB })).status, 400);
    assert.equal((await exchange(baseA, pending)).status, 200, "Mismatched resource is rejected before consuming the valid code");
    for (const [f, endpoint] of [[a, endpointA], [b, endpointB]]) { const saved = JSON.parse(fs.readFileSync(f.state)); assert.equal(saved.version, 3); assert.equal(saved.resource, endpoint); assert(saved.accessTokens.every(x => x.resource === endpoint)); }
  });
  const dirs = [0, 1, 2, 3].map(i => { const d = path.join(a.home, `work '${i}`); fs.mkdirSync(d); return d; });
  await t.test("obsolete fields, invalid cwd and insufficient scope fail before requested writes", async () => {
    const file = path.join(a.home, "must-not-write.txt");
    const stale = await rpc(baseA, aa.token, "tools/call", { name: "write", arguments: { target: { hostName: "obsolete" }, path: file, content: "no" } }); assert(stale.isError);
    const bad = await rpc(baseA, aa.token, "tools/call", { name: "write", arguments: { cwd: "relative", path: file, content: "no" } }); assert(bad.isError);
    const limited = await authorize(baseA, a, endpointA, "status");
    const denied = await rpc(baseA, limited.token, "tools/call", { name: "write", arguments: { path: file, content: "no" } }); assert(denied.isError); assert(denied.structuredContent.execution.executionId);
    assert.equal(fs.existsSync(file), false);
  });
  await t.test("four real shell requests on one instance reach a barrier concurrently with separate cwd and process environments", async () => {
    const waiting = [], timers = [];
    const barrier = http.createServer((_req, res) => {
      waiting.push(res); timers.push(setTimeout(() => { if (!res.writableEnded) { res.statusCode = 503; res.end(); } }, 10000));
      if (waiting.length === 4) for (const response of waiting) response.end("ready");
    });
    await new Promise(resolve => barrier.listen(0, "127.0.0.1", resolve));
    const script = path.join(a.home, "barrier-child.cjs");
    fs.writeFileSync(script, `(async()=>{const r=await fetch(process.argv[2]);if(!r.ok)throw Error('barrier');await r.text();console.log(JSON.stringify({cwd:process.cwd(),context:process.env.HOSTGATE_TEST_CONTEXT,pid:process.pid,secretInherited:!!process.env.HOSTGATE_OAUTH_PASSWORD}));process.chdir('..');})().catch(()=>process.exit(7));`);
    try {
      const results = await Promise.all(dirs.map(async (cwd, i) => {
        const setup = isWindows ? `$env:HOSTGATE_TEST_CONTEXT='context-${i}'; ` : `export HOSTGATE_TEST_CONTEXT='context-${i}'; `;
        const result = await rpc(baseA, i < 2 ? aa.token : otherConnection.token, "tools/call", { name: "shell", arguments: {
          cwd, contextId: `project-${i}/chat-${i}`, command: setup + scriptCommand(script, [`http://127.0.0.1:${barrier.address().port}/`])
        }, _meta: { "openai/session": `session-${i}` } });
        assert.equal(result.isError, undefined); const r = result.structuredContent; assert.equal(r.exitCode, 0);
        const output = JSON.parse(r.stdout); assert.equal(output.cwd, cwd); assert.equal(output.context, `context-${i}`); assert.equal(output.secretInherited, false);
        assert.equal(r.cwd, cwd); assert.equal(r.execution.contextId, `project-${i}/chat-${i}`); assert.match(r.execution.conversationId, /^[a-f0-9]{64}$/);
        return r;
      }));
      assert.equal(waiting.length, 4);
      for (const field of ["executionId", "requestId", "contextKey"]) assert.equal(new Set(results.map(x => x.execution[field])).size, 4);
      assert.equal(new Set(results.map(x => x.pid)).size, 4);
      assert.equal(results[0].execution.connectionId, results[1].execution.connectionId); assert.notEqual(results[0].execution.connectionId, results[2].execution.connectionId);
      t.diagnostic("Four independent MCP requests on one server passed a simultaneous barrier; no global queue/cwd/session was shared.");
    } finally { timers.forEach(clearTimeout); barrier.closeAllConnections(); await new Promise(resolve => barrier.close(resolve)); }
  });
  await t.test("later calls have clean process context and explicit file bases remain unrestricted", async () => {
    const script = path.join(a.home, "later-child.cjs"); fs.writeFileSync(script, "console.log(JSON.stringify({cwd:process.cwd(),value:process.env.HOSTGATE_TEST_CONTEXT||null}));");
    const result = await rpc(baseA, aa.token, "tools/call", { name: "shell", arguments: { command: scriptCommand(script) } });
    assert.deepEqual(JSON.parse(result.structuredContent.stdout), { cwd: a.home, value: null });
    for (const [i, cwd] of dirs.slice(0, 2).entries()) {
      const write = await rpc(baseA, aa.token, "tools/call", { name: "write", arguments: { cwd, path: "same.txt", content: `value-${i}` } }); assert(!write.isError);
      const read = await rpc(baseA, aa.token, "tools/call", { name: "read", arguments: { cwd: dirs[3], path: path.join(cwd, "same.txt") } }); assert.equal(read.structuredContent.text, `value-${i}`);
    }
    const logs = fs.readFileSync(a.logs, "utf8");
    for (const value of [a.password, aa.token, "same.txt", "HOSTGATE_TEST_CONTEXT", "session-0", "project-0/chat-0"]) assert(!logs.includes(value));
    const entries = logs.trim().split("\n").map(JSON.parse); assert(entries.every(e => e.requestId && e.executionId && !e.hostId));
    const cliLogs = spawnSync(process.execPath, [cli, "logs", "--executions"], { env: a.env, encoding: "utf8", timeout: 10000 }); assert.equal(cliLogs.status, 0); assert.match(cliLogs.stdout, /tool-completed/);
  });
  await t.test("removed catalog CLI commands cannot create state; instance credentials remain unchanged", () => {
    for (const op of ["add", "list", "rename", "select", "route", "remove"]) {
      const result = spawnSync(process.execPath, [cli, "host", op], { env: a.env, encoding: "utf8", windowsHide: true, timeout: 10000 }); assert.equal(result.status, 2);
    }
    for (const [i, f] of [a, b].entries()) {
      assert.deepEqual(fs.readFileSync(f.config), credentialsBefore[i]); assert.equal(fs.existsSync(path.join(f.home, ".config/hostgate/hosts.json")), false);
    }
  });
});

test("explicit endpoint binding migration retains credentials/state and rejects downgrade without rewriting", { timeout: 60000 }, async t => {
  const parent = fs.mkdtempSync(path.join(os.tmpdir(), "hostgate-endpoint-migration-")), children = [];
  t.after(async () => { for (const child of children) await stop(child); });
  const f = fixture(parent, "home"), resource = "https://migration.example.test/hostgate/mcp";
  let running = launch(f, null, children), base = await running.ready;
  const legacy = await authorize(base, f, null);
  await t.test("optional resource indicators remain bound in compatibility mode", async () => {
    const resourceToken = await authorize(base, f, base + "/hostgate/mcp");
    assert.equal((await rpc(base, resourceToken.token, "tools/list")).httpStatus, undefined);
    assert.equal((await rpc(base, resourceToken.token, "tools/list", {}, "")).httpStatus, 401);
    const mismatch = { ...resourceToken.fields, resource: "https://unrelated.example.test/mcp" };
    assert.equal((await request(base + "/hostgate/oauth/authorize?" + new URLSearchParams(mismatch))).status, 400);
  });
  const credentials = fs.readFileSync(f.config), oldState = fs.readFileSync(f.state);
  assert.equal((await rpc(base, legacy.token, "tools/call", { name: "status", arguments: {} })).isError, undefined);
  await stop(running.child); running = launch(f, resource, children); base = await running.ready;
  assert.deepEqual(fs.readFileSync(f.state), oldState, "Startup alone never rewrites OAuth state");
  assert.equal((await rpc(base, legacy.token, "tools/list")).httpStatus, 401, "Enabling strict binding explicitly requires reconnecting unbound clients");
  const bound = await authorize(base, f, resource); await stop(running.child);
  const boundState = fs.readFileSync(f.state); running = launch(f, resource, children); base = await running.ready;
  assert.equal((await rpc(base, bound.token, "tools/call", { name: "status", arguments: {} })).isError, undefined);
  assert.deepEqual(fs.readFileSync(f.state), boundState); await stop(running.child);
  for (const changed of [null, "https://wrong.example.test/mcp"]) {
    const failed = launch(f, changed, children); await assert.rejects(failed.ready, /incompatible endpoint/);
    assert.deepEqual(fs.readFileSync(f.state), boundState); assert.deepEqual(fs.readFileSync(f.config), credentials);
  }
  const obsolete = spawnSync(process.execPath, [cli, "start"], { env: { ...f.env, HOSTGATE_PROFILE_ID: crypto.randomUUID() }, encoding: "utf8", timeout: 10000 });
  assert.notEqual(obsolete.status, 0); assert.match(obsolete.stderr, /explicit migration/); assert.deepEqual(fs.readFileSync(f.state), boundState);
});
