import assert from "node:assert/strict";
import fs from "node:fs";
import crypto from "node:crypto";
import path from "node:path";
import os from "node:os";
import http from "node:http";
import net from "node:net";
import { spawn, spawnSync } from "node:child_process";
import { once } from "node:events";
import test from "node:test";
import { fileURLToPath } from "node:url";
import { addHost, saveHostConfig, renameHost, removeHost, selectHost, routingCard, readHosts } from "../src/host-profiles.js";
import { hostPaths } from "../src/host-paths.js";
import { startChild, stopChild } from "../src/supervisor.js";
import { shellEnvironment } from "../src/shell.js";
const root = fileURLToPath(new URL("../", import.meta.url));
async function port() {
  const s = net.createServer(); await new Promise(resolve => s.listen(0, "127.0.0.1", resolve)); const p = s.address().port; await new Promise(resolve => s.close(resolve)); return p;
}
async function stop(child) { if (child.exitCode === null && child.signalCode === null) { const closed = once(child, "close"); child.kill(); await closed; } }
function launch(p, home) {
  const env = { ...shellEnvironment(), HOME: home, USERPROFILE: home, HOSTGATE_OAUTH_PASSWORD: "unrelated-inherited-value-must-not-be-used", HOST: "invalid-inherited-host", PORT: "0" };
  const child = spawn(process.execPath, [path.join(root, "bin", "hostgate.js"), "host", "start", p.id], { cwd: root, env, windowsHide: true, stdio: ["ignore", "pipe", "pipe"] });
  let output = "", errors = "";
  child.stderr.on("data", chunk => { errors += chunk; });
  const ready = new Promise((resolve, reject) => {
    const timer = setTimeout(() => { child.kill(); reject(new Error("Isolated profile startup timed out.")); }, 15000);
    child.once("error", () => { clearTimeout(timer); reject(new Error("Could not launch isolated host.")); });
    child.once("exit", () => { clearTimeout(timer); reject(new Error(`Profile startup failed: ${errors}`)); });
    child.stdout.on("data", chunk => { output += chunk; const m = output.match(/Hostgate listening at http:\/\/127\.0\.0\.1:(\d+)\/mcp/); if (m) { clearTimeout(timer); resolve(`http://127.0.0.1:${m[1]}`); } });
  });
  return { child, ready };
}
const request = (url, options = {}) => fetch(url, { ...options, redirect: "manual", signal: AbortSignal.timeout(20000) });
const post = (url, body, headers = {}) => request(url, { method: "POST", headers: { "Content-Type": "application/json", ...headers }, body: JSON.stringify(body) });
let rpcId = 0;
async function rpc(base, token, method, params = {}) {
  const id = ++rpcId;
  const r = await post(`${base}/hostgate/mcp`, { jsonrpc: "2.0", id, method, params }, { Authorization: `Bearer ${token}`, Accept: "application/json, text/event-stream", "MCP-Protocol-Version": "2025-03-26" });
  if (r.status !== 200) return { httpStatus: r.status };
  const text = await r.text();
  const message = r.headers.get("content-type")?.includes("text/event-stream") ? text.split(/\r?\n/).filter(l => l.startsWith("data: ")).map(l => JSON.parse(l.slice(6))).find(v => v.id === id) : JSON.parse(text);
  assert(message); return message.error ? { rpcError: message.error } : message.result;
}
async function authorize(base, p, config) {
  const response = await post(`${base}/hostgate/oauth/register`, { client_name: "Isolated named-host client", redirect_uris: ["http://127.0.0.1/callback"] }); assert.equal(response.status, 201);
  const clientId = (await response.json()).client_id, verifier = crypto.randomBytes(32).toString("base64url");
  const fields = { client_id: clientId, response_type: "code", redirect_uri: "http://127.0.0.1/callback", code_challenge_method: "S256", code_challenge: crypto.createHash("sha256").update(verifier).digest("base64url"), resource: p.endpoint, scope: "all", state: "isolated-state" };
  const auth = await request(`${base}/hostgate/oauth/authorize`, { method: "POST", headers: { "Content-Type": "application/x-www-form-urlencoded" }, body: new URLSearchParams({ ...fields, username: config.HOSTGATE_OAUTH_USERNAME, password: config.HOSTGATE_OAUTH_PASSWORD }) });
  assert.equal(auth.status, 302);
  const exchange = { client_id: clientId, code: new URL(auth.headers.get("location")).searchParams.get("code"), code_verifier: verifier, grant_type: "authorization_code", redirect_uri: fields.redirect_uri, resource: p.endpoint };
  const token = await post(`${base}/hostgate/oauth/token`, exchange); assert.equal(token.status, 200);
  return { token: (await token.json()).access_token, fields, exchange, clientId };
}
function shellScript(source) {
  const encoded = Buffer.from(source).toString("base64");
  const js = `eval(Buffer.from('${encoded}','base64').toString())`;
  return process.platform === "win32" ? `& '${process.execPath.replaceAll("'", "''")}' -e "${js}"` : `'${process.execPath.replaceAll("'", "'\"'\"'")}' -e "${js}"`;
}

test("two named OAuth/MCP runtimes reject cross-host routing and execute concurrent contexts independently", { timeout: 120000 }, async t => {
  const home = fs.mkdtempSync(path.join(os.tmpdir(), "hostgate-multi-host-http-"));
  t.diagnostic(`Retained isolated multi-host fixture: ${home}`);
  const dirs = ["Primary-work", "Second-work", "Chat-A", "Chat-B", "Chat-C", "Chat-D"].map(name => { const d = path.join(home, name); fs.mkdirSync(d); return d; });
  const a = addHost({ name: "Primary laptop", kind: "local", endpoint: "https://primary.example.test/hostgate/mcp", cwd: dirs[0] }, home);
  const b = addHost({ name: "Second laptop", kind: "local", endpoint: "https://second.example.test/hostgate/mcp", cwd: dirs[1] }, home);
  const cfg = async () => ({ HOST: "127.0.0.1", PORT: String(await port()), HOSTGATE_OAUTH_USERNAME: "fixture-owner", HOSTGATE_OAUTH_PASSWORD: crypto.randomUUID() });
  const ca = await cfg(), cb = await cfg(); assert.notEqual(ca.PORT, cb.PORT);
  await saveHostConfig(a, ca, home); await saveHostConfig(b, cb, home);
  const credentials = [a, b].map(p => fs.readFileSync(hostPaths(p.id, home).credentials));
  await t.test("managed staging validates a profiled candidate without confusing its lease or the other host", async () => {
    const environment = { ...shellEnvironment(), HOME: home, USERPROFILE: home, ...ca, HOSTGATE_PROFILE_ID: a.id };
    const config = { repoRoot: root, nodePath: process.execPath, childPath: path.join(root, "src", "managed-child.js"), profileId: a.id, profileEndpoint: a.endpoint, workingDirectory: a.cwd };
    const candidate = await startChild(config, { path: root }, environment, { staged: true });
    await stopChild(candidate);
    assert.equal(fs.existsSync(hostPaths(a.id, home).status), false);
    await assert.rejects(startChild({ ...config, profileId: b.id, profileEndpoint: b.endpoint }, { path: root }, environment, { staged: true }), /health verification/);
  });
  let ra = launch(a, home), rb = launch(b, home); t.after(async () => { await stop(ra.child); await stop(rb.child); });
  let ba = await ra.ready, bb = await rb.ready;
  const authA = await authorize(ba, a, ca), authB = await authorize(bb, b, cb);
  const aa = routingCard(a, "Project-A/chat-A"), ab = routingCard(b, "Project-B/chat-B");
  await t.test("distinct identity, issuer, state and token audiences; root aliases stay on this host", async () => {
    for (const [base, p] of [[ba, a], [bb, b]]) {
      for (const prefix of ["", "/hostgate"]) {
        const metadata = await request(`${base}${prefix}/.well-known/oauth-authorization-server`, { headers: { Host: "spoofed.invalid" } });
        assert.equal((await metadata.json()).issuer, p.endpoint.slice(0, -4));
        const h = await (await request(`${base}${prefix}/health`)).json(); assert.equal(h.host.hostId, p.id); assert.equal(h.host.hostName, p.name);
      }
      const state = JSON.parse(fs.readFileSync(hostPaths(p.id, home).oauth)); assert.equal(state.hostId, p.id); assert.equal(state.resource, p.endpoint); assert.equal(state.version, 2);
    }
    assert.equal((await rpc(ba, authB.token, "tools/list")).httpStatus, 401);
    assert.equal((await rpc(bb, authA.token, "tools/list")).httpStatus, 401);
    assert.notEqual(authA.clientId, authB.clientId);
    assert.equal(fs.existsSync(path.join(home, ".local/share/hostgate/oauth-state.json")), false);
    const wrongResource = await post(`${ba}/hostgate/oauth/token`, { ...authA.exchange, resource: b.endpoint }); assert.equal(wrongResource.status, 400);
    const crossedClient = await request(`${bb}/hostgate/oauth/authorize?${new URLSearchParams({ ...authA.fields, resource: b.endpoint })}`); assert.equal(crossedClient.status, 400);
    const wrongPassword = await request(`${bb}/hostgate/oauth/authorize`, { method: "POST", headers: { "Content-Type": "application/x-www-form-urlencoded" }, body: new URLSearchParams({ ...authB.fields, username: cb.HOSTGATE_OAUTH_USERNAME, password: ca.HOSTGATE_OAUTH_PASSWORD }) }); assert.equal(wrongPassword.status, 401);
  });
  await t.test("all four tools advertise identity requirements and unchanged destructive metadata", async () => {
    const { tools } = await rpc(ba, authA.token, "tools/list"); assert.deepEqual(tools.map(t => t.name).sort(), ["read", "shell", "status", "write"]);
    for (const tool of tools) { assert(tool.inputSchema.required.includes("target")); assert(tool.inputSchema.required.includes("contextId")); assert(tool.description.includes(a.id)); }
    const sh = tools.find(t => t.name === "shell"), wr = tools.find(t => t.name === "write");
    assert.deepEqual(sh.annotations, { readOnlyHint: false, destructiveHint: true, openWorldHint: true });
    assert.deepEqual(wr.annotations, { readOnlyHint: false, destructiveHint: true, openWorldHint: false });
    assert.match(sh.description, /intentionally dangerous/); assert(sh.inputSchema.required.includes("cwd"));
  });
  await t.test("wrong host ID/name/origin, omitted target and missing context execute no side effects", async () => {
    const forbidden = path.join(home, "wrong-host-must-not-write.txt");
    for (const target of [ab.target, { ...aa.target, hostName: b.name }, { ...aa.target, endpoint: b.endpoint }]) {
      const result = await rpc(ba, authA.token, "tools/call", { name: "write", arguments: { target, contextId: "wrong-route", path: forbidden, content: "not written" } }); assert(result.isError || result.rpcError);
    }
    const absent = await rpc(ba, authA.token, "tools/call", { name: "write", arguments: { path: forbidden, content: "not written" } }); assert(absent.isError || absent.rpcError);
    const relative = await rpc(ba, authA.token, "tools/call", { name: "write", arguments: { target: aa.target, contextId: aa.contextId, path: "relative.txt", content: "no cwd" } }); assert(relative.isError);
    assert.equal(fs.existsSync(forbidden), false); assert.equal(fs.existsSync(path.join(dirs[0], "relative.txt")), false);
  });
  await t.test("concurrent calls from four project/chats cross a barrier without serialization or cwd/env sharing", async () => {
    const waiting = [], timerIds = [];
    const barrier = http.createServer((req, res) => {
      waiting.push(res); timerIds.push(setTimeout(() => { if (!res.writableEnded) { res.statusCode = 503; res.end("barrier timeout"); } }, 12000));
      if (waiting.length === 4) for (const r of waiting) r.end("ready");
    });
    await new Promise(resolve => barrier.listen(0, "127.0.0.1", resolve));
    try {
      const results = await Promise.all([0, 1, 2, 3].map(async i => {
        const primary = i < 2, target = primary ? aa.target : ab.target, cwd = dirs[i + 2];
        const source = `(async()=>{const r=await fetch('http://127.0.0.1:${barrier.address().port}/');if(!r.ok)throw Error('concurrency barrier');await r.text();console.log(JSON.stringify({cwd:process.cwd(),context:process.env.HOSTGATE_TEST_CONTEXT,secretInherited:!!process.env.HOSTGATE_OAUTH_PASSWORD,pid:process.pid}));process.chdir('..');})().catch(()=>process.exit(7));`;
        const result = await rpc(primary ? ba : bb, primary ? authA.token : authB.token, "tools/call", { name: "shell", arguments: { target, contextId: `project-${i}/chat-${i}`, cwd, command: (process.platform === "win32" ? `$env:HOSTGATE_TEST_CONTEXT='context-${i}'; ` : `export HOSTGATE_TEST_CONTEXT='context-${i}'; `) + shellScript(source) }, _meta: { "openai/session": `session-${i}` } });
        assert.equal(result.isError, undefined); assert.equal(result.structuredContent.exitCode, 0, "Concurrent child must complete the barrier");
        const output = JSON.parse(result.structuredContent.stdout); assert.equal(output.cwd, cwd); assert.equal(output.context, `context-${i}`); assert.equal(output.secretInherited, false);
        assert.equal(result.structuredContent.host.hostId, target.hostId); assert.equal(result.structuredContent.execution.contextId, `project-${i}/chat-${i}`); assert.match(result.structuredContent.execution.conversationId, /^[a-f0-9]{64}$/);
        return result.structuredContent;
      }));
      assert.equal(waiting.length, 4); assert.equal(new Set(results.map(r => r.execution.executionId)).size, 4); assert.equal(new Set(results.map(r => r.execution.requestId)).size, 4);
      assert.equal(new Set(results.map(r => r.execution.contextKey)).size, 4); assert.equal(new Set(results.map(r => r.pid)).size, 4);
      assert.equal(results[0].execution.connectionId, results[1].execution.connectionId); assert.notEqual(results[0].execution.connectionId, results[2].execution.connectionId);
      t.diagnostic("Four real MCP shell requests reached a shared barrier, including two on each host; separate child PIDs, execution IDs, context keys and working directories verified.");
    } finally { timerIds.forEach(clearTimeout); barrier.closeAllConnections(); await new Promise(resolve => barrier.close(resolve)); }
  });
  await t.test("per-call file context and logs stay separate; absolute paths remain unrestricted", async () => {
    for (const [base, auth, route, cwd, text] of [[ba, authA, aa, dirs[2], "A file"], [bb, authB, ab, dirs[3], "B file"]]) {
      const write = await rpc(base, auth.token, "tools/call", { name: "write", arguments: { target: route.target, contextId: route.contextId, cwd, path: "same-name.txt", content: text } }); assert(!write.isError);
      const read = await rpc(base, auth.token, "tools/call", { name: "read", arguments: { target: route.target, contextId: route.contextId, path: path.join(cwd, "same-name.txt") } }); assert.equal(read.structuredContent.text, text);
      const status = await rpc(base, auth.token, "tools/call", { name: "status", arguments: { target: route.target, contextId: route.contextId } }); assert.equal(status.structuredContent.host.hostId, route.target.hostId);
    }
    for (const [p, other, config] of [[a, b, ca], [b, a, cb]]) {
      const raw = fs.readFileSync(hostPaths(p.id, home).logs, "utf8"), events = raw.trim().split("\n").map(JSON.parse);
      assert(events.every(e => e.hostId === p.id)); assert(!raw.includes(other.id)); assert(!raw.includes(config.HOSTGATE_OAUTH_PASSWORD)); assert(!raw.includes("same-name.txt")); assert(!raw.includes("HOSTGATE_TEST_CONTEXT"));
    }
  });
  await t.test("a later shell call inherits neither another call's cwd nor its temporary variables", async () => {
    const r = await rpc(ba, authA.token, "tools/call", { name: "shell", arguments: { target: aa.target, contextId: "later/chat", cwd: dirs[0], command: shellScript("console.log(JSON.stringify({cwd:process.cwd(),value:process.env.HOSTGATE_TEST_CONTEXT||null}))") } });
    assert.equal(r.structuredContent.exitCode, 0); assert.deepEqual(JSON.parse(r.structuredContent.stdout), { cwd: dirs[0], value: null });
  });
  await t.test("changing another context selection cannot retarget a running server", async () => {
    selectHost(b.id, aa.contextId, home);
    const r = await rpc(ba, authA.token, "tools/call", { name: "status", arguments: { target: aa.target, contextId: aa.contextId } }); assert.equal(r.structuredContent.host.hostId, a.id);
  });
  await t.test("restart of one profile retains its token and does not affect the other", async () => {
    await stop(ra.child); ra = launch(a, home); ba = await ra.ready;
    assert.equal((await rpc(ba, authA.token, "tools/call", { name: "status", arguments: { target: aa.target, contextId: aa.contextId } })).structuredContent.host.hostId, a.id);
    assert.equal((await rpc(bb, authB.token, "tools/call", { name: "status", arguments: { target: ab.target, contextId: ab.contextId } })).structuredContent.host.hostId, b.id);
    for (const [i, p] of [a, b].entries()) assert.deepEqual(fs.readFileSync(hostPaths(p.id, home).credentials), credentials[i]);
  });
  await t.test("duplicate profile server cannot acquire the same host lease", async () => {
    const duplicate = launch(a, home); await assert.rejects(duplicate.ready); await stop(duplicate.child);
    assert.equal((await request(`${ba}/health`)).status, 200);
  });
  await t.test("rename invalidates stale routing and retiring a stopped profile retains its state", async () => {
    assert.throws(() => removeHost(a.id, home), /running/);
    renameHost(a.id, "Renamed primary", home);
    assert.equal((await rpc(ba, authA.token, "tools/call", { name: "status", arguments: { target: aa.target, contextId: aa.contextId } })).httpStatus, 409);
    assert.equal((await request(`${bb}/health`)).status, 200);
    await stop(ra.child); removeHost(a.id, home);
    assert(fs.existsSync(hostPaths(a.id, home).oauth)); assert(fs.existsSync(hostPaths(a.id, home).credentials));
    assert.equal(readHosts(home).profiles.find(p => p.id === b.id).active, true);
  });
  await t.test("copied OAuth state fails closed before binding without replacing it", async () => {
    await stop(rb.child);
    fs.copyFileSync(hostPaths(a.id, home).oauth, hostPaths(b.id, home).oauth);
    const before = fs.readFileSync(hostPaths(b.id, home).oauth);
    const failed = launch(b, home); await assert.rejects(failed.ready, /another host/); await stop(failed.child);
    assert.deepEqual(fs.readFileSync(hostPaths(b.id, home).oauth), before);
  });
});
