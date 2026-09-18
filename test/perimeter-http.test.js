import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import crypto from "node:crypto";
import { once } from "node:events";
import { mkdirSync, mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import http from "node:http";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";
import express from "express";
import { createPerimeter, RATES } from "../src/perimeter.js";
import { shellEnvironment } from "../src/shell.js";

const root = fileURLToPath(new URL("../", import.meta.url));
const hash = (value) => crypto.createHash("sha256").update(value).digest("base64url");

function rawRequest(url, { headers = {}, chunks = [], end = true, method = "POST" } = {}) {
  let req;
  const result = new Promise((resolve, reject) => {
    req = http.request(url, { method, headers, agent: false }, (res) => {
      let body = "";
      res.setEncoding("utf8");
      res.on("data", (chunk) => { body += chunk; });
      res.on("error", reject);
      res.on("end", () => resolve({ status: res.statusCode, headers: res.headers, body }));
    });
    req.on("error", reject);
    req.setTimeout(3000, () => req.destroy(new Error("Test request timed out")));
    for (const chunk of chunks) req.write(chunk);
    if (end) req.end();
    else req.flushHeaders();
  });
  return { req, result };
}
async function harness(t, bodyOptions) {
  const p = createPerimeter({ bodyOptions });
  const app = express();
  app.use(["/oauth", "/hostgate/oauth"], p.middleware);
  let handled = 0;
  app.post(["/oauth/register", "/hostgate/oauth/register"], (req, res) => { handled++; res.json(req.body); });
  const server = app.listen(0, "127.0.0.1");
  await once(server, "listening");
  t.after(async () => { server.closeAllConnections(); await new Promise((resolve) => server.close(resolve)); });
  return { server, base: `http://127.0.0.1:${server.address().port}`, count: () => handled };
}

test("real HTTP rejects declared and chunked OAuth overflows before handler execution", async (t) => {
  const { base, count } = await harness(t, { maxBytes: 32 });
  for (const prefix of ["", "/hostgate"]) {
    const early = rawRequest(base + prefix + "/oauth/register", {
      headers: { "Content-Type": "application/json", "Content-Length": "1000000" }, chunks: ["{"], end: false
    });
    try {
      const r = await early.result;
      assert.equal(r.status, 413);
      assert.equal(r.headers.connection, "close");
      assert.equal(r.headers["cache-control"], "no-store");
    } finally { early.req.destroy(); }
    const chunked = await rawRequest(base + prefix + "/oauth/register", {
      headers: { "Content-Type": "application/json" }, chunks: ["x".repeat(33)]
    }).result;
    assert.equal(chunked.status, 413);
  }
  assert.equal(count(), 0);
  const ok = await rawRequest(base + "/oauth/register", {
    headers: { "Content-Type": "application/json" }, chunks: ['{"ok":true}']
  }).result;
  assert.equal(ok.status, 200);
  assert.equal(count(), 1);
});

test("real slow-body timeout and concurrent-body cap release their slots", async (t) => {
  const { base, server, count } = await harness(t, { timeoutMs: 400, maxPending: 2 });
  const pending = [];
  try {
    for (let i = 0; i < 2; i++) {
      const arrived = once(server, "request");
      pending.push(rawRequest(base + (i ? "/hostgate" : "") + "/oauth/register", {
        headers: { "Content-Type": "application/json", "Content-Length": "100" }, chunks: ["{"], end: false
      }));
      await arrived;
    }
    const busy = await rawRequest(base + "/oauth/register", {
      headers: { "Content-Type": "application/json" }, chunks: ["{}"]
    }).result;
    assert.equal(busy.status, 503);
    assert.equal(busy.headers["retry-after"], "1");
    for (const item of pending) assert.equal((await item.result).status, 408);
  } finally { for (const item of pending) item.req.destroy(); }
  assert.equal(count(), 0);
  const ok = await rawRequest(base + "/oauth/register", {
    headers: { "Content-Type": "application/json" }, chunks: ["{}"]
  }).result;
  assert.equal(ok.status, 200);
  assert.equal(count(), 1);
});

test("real HTTP public content encoding and media type failures are explicit", async (t) => {
  const { base, count } = await harness(t);
  for (const headers of [{ "Content-Type": "text/plain" }, { "Content-Type": "application/json", "Content-Encoding": "gzip" }]) {
    assert.equal((await rawRequest(base + "/oauth/register", { headers, chunks: ["{}"] }).result).status, 415);
  }
  assert.equal(count(), 0);
});

async function stop(child) {
  if (child && child.exitCode === null && child.signalCode === null) {
    const stopped = once(child, "close");
    child.kill();
    await stopped;
  }
}

test("isolated live server protects OAuth admission while preserving full authorized MCP", { timeout: 90000 }, async (t) => {
  const home = mkdtempSync(path.join(os.tmpdir(), "hostgate-perimeter-"));
  t.diagnostic(`Isolated perimeter fixture retained at ${home}`);
  const statePath = path.join(home, ".local/share/hostgate/oauth-state.json");
  mkdirSync(path.dirname(statePath), { recursive: true, mode: 0o700 });
  const username = "perimeter-owner";
  const password = crypto.randomUUID();
  const bearer = crypto.randomBytes(32).toString("base64url");
  const verifier = crypto.randomBytes(32).toString("base64url");
  const client = { clientId: "existing", clientName: "Existing test connection",
    redirectUris: ["https://example.test/callback"], createdAt: Date.now() };
  writeFileSync(statePath, JSON.stringify({ version: 1, clients: [client], accessTokens: [
    { hash: hash(bearer), clientId: client.clientId, scope: "all status read write shell", expiresAt: Date.now() + 86400000 }
  ] }), { mode: 0o600 });
  const snapshot = () => hash(readFileSync(statePath));
  const initial = snapshot();
  const env = { ...shellEnvironment(), HOME: home, USERPROFILE: home, PORT: "0", HOST: "127.0.0.1",
    HOSTGATE_OAUTH_USERNAME: username, HOSTGATE_OAUTH_PASSWORD: password, HOSTGATE_OAUTH_MAX_CLIENTS: "1" };
  const child = spawn(process.execPath, [path.join(root, "src/server.js")], {
    cwd: root, env, windowsHide: true, stdio: ["ignore", "pipe", "pipe"]
  });
  t.after(async () => { await stop(child); });
  let errors = "";
  let output = "";
  const base = await new Promise((resolve, reject) => {
    const timer = setTimeout(() => reject(new Error("Isolated perimeter server did not become ready")), 10000);
    child.once("error", (error) => { clearTimeout(timer); reject(error); });
    child.once("exit", () => { clearTimeout(timer); reject(new Error("Isolated perimeter server exited")); });
    child.stdout.setEncoding("utf8");
    child.stderr.setEncoding("utf8");
    child.stderr.on("data", (chunk) => { errors += chunk; });
    child.stdout.on("data", (chunk) => {
      output += chunk;
      const match = output.match(/Hostgate listening at http:\/\/127\.0\.0\.1:(\d+)\/mcp/);
      if (match && output.includes(`OAuth state: ${statePath}`)) {
        clearTimeout(timer);
        resolve(`http://127.0.0.1:${match[1]}`);
      }
    });
  });
  assert.equal(snapshot(), initial, "Startup must not rewrite existing state");
  const json = async (route, data, headers = {}) => fetch(base + route, {
    method: "POST", headers: { "Content-Type": "application/json", ...headers }, body: JSON.stringify(data),
    redirect: "manual", signal: AbortSignal.timeout(5000)
  });
  const login = { response_type: "code", client_id: client.clientId, redirect_uri: client.redirectUris[0],
    code_challenge: hash(verifier), code_challenge_method: "S256", username, password };
  let id = 0;
  async function rpc(method, params = {}) {
    const current = ++id;
    const r = await json("/hostgate/mcp", { jsonrpc: "2.0", id: current, method, params }, {
      Authorization: `Bearer ${bearer}`, Accept: "application/json, text/event-stream", "MCP-Protocol-Version": "2025-03-26"
    });
    assert.equal(r.status, 200);
    const text = await r.text();
    const message = r.headers.get("content-type")?.includes("text/event-stream")
      ? text.split(/\r?\n/).filter((line) => line.startsWith("data: ")).map((line) => JSON.parse(line.slice(6))).find((item) => item.id === current)
      : JSON.parse(text);
    assert(message?.result);
    assert.equal(message.result.isError, undefined);
    return message.result;
  }

  await t.test("invalid or missing bearer is rejected before unfinished MCP bodies", async () => {
    for (const prefix of ["", "/hostgate"]) {
      for (const headers of [{}, { Authorization: "Bearer invalid" }]) {
        const pending = rawRequest(base + prefix + "/mcp", {
          headers: { ...headers, "Content-Type": "application/json", "Content-Length": "1000000" }, chunks: ["{"], end: false
        });
        try {
          const r = await pending.result;
          assert.equal(r.status, 401);
          assert.match(r.headers["www-authenticate"], /oauth-protected-resource/);
          assert.equal(r.headers.connection, "close");
        } finally { pending.req.destroy(); }
      }
    }
    assert.equal(snapshot(), initial);
  });

  await t.test("unknown routes respond without waiting for or buffering an upload", async () => {
    for (const route of ["/unknown", "/hostgate/oauth/unknown", "/health"]) {
      const pending = rawRequest(base + route, {
        headers: { "Content-Type": "application/json", "Content-Length": "1000000" }, chunks: ["{"], end: false
      });
      try { assert.equal((await pending.result).status, 404); }
      finally { pending.req.destroy(); }
    }
  });

  await t.test("new registrations respect capacity without evicting existing clients or tokens", async () => {
    const before = snapshot();
    for (const prefix of ["", "/hostgate"]) {
      const r = await json(prefix + "/oauth/register", { redirect_uris: client.redirectUris });
      assert.equal(r.status, 503);
      assert.equal((await r.json()).error, "temporarily_unavailable");
    }
    assert.equal(snapshot(), before);
    assert.equal((await rpc("tools/call", { name: "status", arguments: {} })).structuredContent.hostname, os.hostname());
  });

  await t.test("existing registration can complete OAuth and token responses cannot be cached", async () => {
    const r = await json("/hostgate/oauth/authorize", login);
    assert.equal(r.status, 302);
    assert.equal(r.headers.get("cache-control"), "no-store");
    const code = new URL(r.headers.get("location")).searchParams.get("code");
    const exchanged = await json("/oauth/token", { grant_type: "authorization_code", code, client_id: client.clientId,
      redirect_uri: client.redirectUris[0], code_verifier: verifier });
    assert.equal(exchanged.status, 200);
    assert.equal(exchanged.headers.get("cache-control"), "no-store");
    assert.equal(exchanged.headers.get("pragma"), "no-cache");
    const token = await exchanged.json();
    assert.equal(token.expires_in, 86400);
    assert.deepEqual(token.scope.split(" "), ["all", "status", "read", "write", "shell"]);
  });

  await t.test("five bad passwords throttle subsequent attempts across aliases and forged addresses", async () => {
    const before = snapshot();
    for (let i = 0; i < RATES.password.capacity; i++) {
      const r = await json((i % 2 ? "/hostgate" : "") + "/oauth/authorize", { ...login, username: `guess-${i}`, password: "incorrect" },
        { "X-Forwarded-For": `198.51.100.${i}` });
      assert.equal(r.status, 401);
      await r.text();
    }
    const blocked = await json("/oauth/authorize", login, { "X-Forwarded-For": "203.0.113.1" });
    assert.equal(blocked.status, 429);
    assert(Number(blocked.headers.get("retry-after")) > 0);
    assert.equal(blocked.headers.get("cache-control"), "no-store");
    assert.equal(snapshot(), before);
    assert.equal((await rpc("tools/call", { name: "status", arguments: {} })).structuredContent.hostname, os.hostname());
  });

  await t.test("registration and token budgets throttle before invalid-body handling", async () => {
    const before = snapshot();
    for (const endpoint of ["register", "token"]) {
      let blocked = false;
      for (let i = 0; i < 2 * RATES[endpoint].capacity; i++) {
        const route = (i % 2 ? "/hostgate" : "") + "/oauth/" + (i % 3 ? endpoint : endpoint.toUpperCase() + "/");
        const r = await json(route, {}, { "X-Forwarded-For": `192.0.2.${i}`, "X-Forwarded-Host": `fake-${i}.invalid` });
        if (r.status === 429) {
          assert(Number(r.headers.get("retry-after")) >= 1);
          assert.equal((await r.json()).error, "temporarily_unavailable");
          blocked = true;
          break;
        }
        assert.equal(r.status, 400);
        await r.text();
      }
      assert(blocked, `${endpoint} did not enforce admission`);
    }
    assert.equal(snapshot(), before);
  });

  await t.test("OAuth throttling does not restrict the four tools or authenticated large writes", async () => {
    const listed = await rpc("tools/list");
    assert.deepEqual(listed.tools.map((tool) => tool.name).sort(), ["read", "shell", "status", "write"]);
    const text = "UTF-8 café 🚀\n".repeat(12000);
    assert(Buffer.byteLength(text) > 65536);
    const file = path.join(home, "large-authorized-write.txt");
    const written = await rpc("tools/call", { name: "write", arguments: { path: file, content: text } });
    assert.equal(written.structuredContent.bytes, Buffer.byteLength(text));
    const read = await rpc("tools/call", { name: "read", arguments: { path: file } });
    assert.equal(read.structuredContent.text, text);
    const result = await rpc("tools/call", { name: "shell", arguments: { command: process.platform === "win32" ? "Get-Date -Format o" : "date -u +%Y-%m-%dT%H:%M:%SZ" } });
    assert.equal(result.structuredContent.exitCode, 0);
    const state = JSON.parse(readFileSync(statePath, "utf8"));
    assert.deepEqual(state.clients, [client]);
    assert(state.accessTokens.some((token) => token.hash === hash(bearer)));
    assert.equal(state.version, 1);
  });
  assert.equal(errors, "", "Rejected requests must not produce raw server errors");
  assert(!output.includes(password));
  assert(!output.includes(bearer));
});
