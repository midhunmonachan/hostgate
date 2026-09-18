import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import crypto from "node:crypto";
import { once } from "node:events";
import { mkdirSync, mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";
import { shellEnvironment } from "../src/shell.js";

const root = fileURLToPath(new URL("../", import.meta.url));
const hash = (value) => crypto.createHash("sha256").update(value).digest("base64url");
const redirects = ["https://chatgpt.com/connector/oauth/test-callback", "https://chatgpt.com/connector_platform_oauth_redirect"];

async function stop(child) {
  if (child && child.exitCode === null && child.signalCode === null) {
    const closed = once(child, "close");
    child.kill();
    await closed;
  }
}

test("isolated OAuth registration, callback, PKCE, and migration HTTP regressions", { timeout: 90000 }, async (t) => {
  const home = mkdtempSync(path.join(os.tmpdir(), "hostgate-oauth-"));
  const statePath = path.join(home, ".local/share/hostgate/oauth-state.json");
  mkdirSync(path.dirname(statePath), { recursive: true, mode: 0o700 });
  const username = "oauth-test-owner";
  const password = crypto.randomUUID() + '#"=literal';
  const legacyToken = crypto.randomBytes(32).toString("base64url");
  const legacyClients = [
    { clientId: "legacy-valid", clientName: "Existing connection", redirectUris: redirects },
    { clientId: "legacy-empty", clientName: "Old empty list", redirectUris: [] },
    { clientId: "legacy-malformed", clientName: "Old malformed list", redirectUris: "not-an-array" },
    { clientId: "legacy-insecure", clientName: "Old insecure callback", redirectUris: ["http://example.test/callback"] }
  ].map((client) => ({ ...client, createdAt: Date.now() }));
  writeFileSync(statePath, JSON.stringify({ version: 1, clients: legacyClients, accessTokens: [
    { hash: hash(legacyToken), clientId: "legacy-valid", scope: "all status read write shell", expiresAt: Date.now() + 86400000 }
  ] }) + "\n", { mode: 0o600 });
  const stateHash = () => hash(readFileSync(statePath));
  const initialState = stateHash();
  const env = { ...shellEnvironment(), HOME: home, USERPROFILE: home, PORT: "0", HOST: "127.0.0.1",
    HOSTGATE_OAUTH_USERNAME: username, HOSTGATE_OAUTH_PASSWORD: password };
  let child;
  let base;
  let stderr = "";
  const launch = async () => {
    child = spawn(process.execPath, [path.join(root, "src/server.js")], {
      cwd: root, env, windowsHide: true, stdio: ["ignore", "pipe", "pipe"]
    });
    base = await new Promise((resolve, reject) => {
      let output = "";
      const timer = setTimeout(() => reject(new Error("Isolated OAuth server did not become ready.")), 10000);
      child.once("error", (error) => { clearTimeout(timer); reject(error); });
      child.once("exit", () => { clearTimeout(timer); reject(new Error("Isolated OAuth server exited.")); });
      child.stderr.setEncoding("utf8");
      child.stderr.on("data", (chunk) => { stderr += chunk; });
      child.stdout.setEncoding("utf8");
      child.stdout.on("data", (chunk) => {
        output += chunk;
        const match = output.match(/Hostgate listening at http:\/\/127\.0\.0\.1:(\d+)\/mcp/);
        // Do not issue any request until the server confirms its isolated state path.
        if (match && output.includes(`OAuth state: ${statePath}`)) {
          clearTimeout(timer);
          resolve(`http://127.0.0.1:${match[1]}`);
        }
      });
    });
  };
  t.after(async () => { await stop(child); });
  t.diagnostic(`Isolated OAuth fixture retained at ${home}`);
  await launch();
  assert.equal(stateHash(), initialState, "Startup must not migrate or rewrite existing state.");

  const request = (route, options = {}) => fetch(base + route, {
    ...options, signal: AbortSignal.timeout(5000), redirect: "manual"
  });
  const json = (route, body, headers = {}) => request(route, {
    method: "POST", headers: { "Content-Type": "application/json", ...headers }, body: JSON.stringify(body)
  });
  const form = (route, body) => request(route, {
    method: "POST", headers: { "Content-Type": "application/x-www-form-urlencoded" }, body: body.toString()
  });
  const verifier = crypto.randomBytes(32).toString("base64url");
  const params = { response_type: "code", client_id: "legacy-valid", redirect_uri: redirects[0],
    code_challenge: hash(verifier), code_challenge_method: "S256", scope: "all", state: "expected-state" };
  const authorize = (prefix, changes = {}) => json(prefix + "/oauth/authorize", { ...params, username, password, ...changes });
  const grant = async (prefix, changes = {}) => {
    const response = await authorize(prefix, changes);
    assert.equal(response.status, 302);
    const callback = new URL(response.headers.get("location"));
    assert.equal(callback.searchParams.get("state"), "expected-state");
    return { grant_type: "authorization_code", client_id: params.client_id,
      redirect_uri: params.redirect_uri, code: callback.searchParams.get("code"), code_verifier: verifier, ...changes };
  };
  let rpcId = 0;
  async function rpc(prefix, token, method, rpcParams = {}) {
    const id = ++rpcId;
    const response = await json(prefix + "/mcp", { jsonrpc: "2.0", id, method, params: rpcParams }, {
      Authorization: `Bearer ${token}`, Accept: "application/json, text/event-stream", "MCP-Protocol-Version": "2025-03-26"
    });
    assert.equal(response.status, 200);
    const text = await response.text();
    const message = response.headers.get("content-type")?.includes("text/event-stream")
      ? text.split(/\r?\n/).filter((line) => line.startsWith("data: ")).map((line) => JSON.parse(line.slice(6))).find((item) => item.id === id)
      : JSON.parse(text);
    assert.equal(message?.error, undefined);
    assert(message?.result);
    return message.result;
  }

  for (const prefix of ["", "/hostgate"]) {
    await t.test(`${prefix || "root"}: invalid registration never writes OAuth state`, async () => {
      const before = stateHash();
      for (const body of [null, [], "body", {}, { redirect_uris: [] }, { redirect_uris: ["http://example.test/callback"] },
        { redirect_uris: [redirects[0] + "#fragment"] }, { redirect_uris: [null] },
        { redirect_uris: redirects, client_name: {} }, { redirect_uris: redirects, token_endpoint_auth_method: "client_secret_basic" }]) {
        const response = await json(prefix + "/oauth/register", body);
        assert.equal(response.status, 400);
        assert(["invalid_redirect_uri", "invalid_client_metadata"].includes((await response.json()).error));
      }
      assert.equal(stateHash(), before);
    });

    await t.test(`${prefix || "root"}: invalid clients/callbacks never display login or redirect`, async () => {
      const before = stateHash();
      for (const changes of [{ client_id: "unregistered" }, { client_id: "legacy-empty" }, { client_id: "legacy-malformed" },
        { client_id: "legacy-insecure", redirect_uri: "http://example.test/callback" },
        { redirect_uri: redirects[0] + "/extra" }, { redirect_uri: redirects[0] + "?extra=yes" },
        { redirect_uri: "https://chatgpt.com:443/connector/oauth/test-callback" }, { code_challenge_method: "plain" },
        { code_challenge: "A".repeat(43) + "\n" }]) {
        const query = new URLSearchParams({ ...params, ...changes });
        for (const response of [await request(prefix + "/oauth/authorize?" + query), await authorize(prefix, changes)]) {
          assert.equal(response.status, 400);
          assert.equal(response.headers.get("location"), null);
          const html = await response.text();
          assert(!html.includes("<form"));
          assert(!html.includes(password));
        }
      }
      assert.equal(stateHash(), before);
    });

    await t.test(`${prefix || "root"}: malformed inputs and repeated form/query scalars fail safely`, async () => {
      const before = stateHash();
      for (const body of [null, [], "body", { ...params, scope: [] }, { ...params, state: {} }, { ...params, code_challenge: {} }]) {
        assert.equal((await json(prefix + "/oauth/authorize", body)).status, 400);
      }
      const badPassword = await authorize(prefix, { password: {} });
      assert.equal(badPassword.status, 401);
      const query = new URLSearchParams(params);
      query.append("client_id", "other-client");
      assert.equal((await request(prefix + "/oauth/authorize?" + query)).status, 400);
      const repeated = new URLSearchParams({ ...params, username, password });
      repeated.append("redirect_uri", "https://example.invalid/callback");
      const duplicate = await form(prefix + "/oauth/authorize", repeated);
      assert.equal(duplicate.status, 400);
      assert.equal((await duplicate.json()).error, "invalid_request");
      for (const body of [null, [], "body"]) {
        const token = await json(prefix + "/oauth/token", body);
        assert.equal(token.status, 400);
        assert.equal((await token.json()).error, "invalid_request");
      }
      assert.equal(stateHash(), before);
    });

    await t.test(`${prefix || "root"}: DCR and both ChatGPT callback forms complete S256`, async () => {
      const response = await json(prefix + "/oauth/register", {
        client_name: '<img src=x onerror="alert(1)">', redirect_uris: redirects,
        token_endpoint_auth_method: "none", grant_types: ["authorization_code", "refresh_token"],
        response_types: ["code"], ignored_extension: "not persisted"
      });
      assert.equal(response.status, 201);
      const registered = await response.json();
      assert.deepEqual(registered.redirect_uris, redirects);
      assert.deepEqual(registered.grant_types, ["authorization_code"]);
      assert.equal(registered.token_endpoint_auth_method, "none");
      for (const redirect_uri of redirects) {
        const changed = { client_id: registered.client_id, redirect_uri };
        const login = await request(prefix + "/oauth/authorize?" + new URLSearchParams({ ...params, ...changed }));
        assert.equal(login.status, 200);
        const html = await login.text();
        assert(html.includes("<form"));
        assert(html.includes("&lt;img"));
        assert(!html.includes("<img"));
        assert(html.includes("self-reported"));
        const issued = await grant(prefix, changed);
        const exchanged = await json(prefix + "/oauth/token", issued);
        assert.equal(exchanged.status, 200);
        const token = await exchanged.json();
        assert.equal(token.expires_in, 86400);
        assert.equal(token.refresh_token, undefined);
        assert(token.scope.split(" ").includes("all"));
        const listed = await rpc(prefix, token.access_token, "tools/list");
        assert.deepEqual(listed.tools.map((item) => item.name).sort(), ["read", "shell", "status", "write"]);
        assert.equal((await json(prefix + "/oauth/token", issued)).status, 400);
      }
    });

    await t.test(`${prefix || "root"}: default full scope, verifier boundaries, and repeated token fields`, async () => {
      for (const validVerifier of ["A".repeat(43), "Ab09-._~".repeat(16)]) {
        const issued = await grant(prefix, { scope: undefined, code_challenge: hash(validVerifier) });
        issued.code_verifier = validVerifier;
        const duplicated = new URLSearchParams({ ...issued, scope: "all" });
        duplicated.append("code_verifier", "other-verifier");
        const bad = await form(prefix + "/oauth/token", duplicated);
        assert.equal(bad.status, 400);
        assert.equal((await bad.json()).error, "invalid_request");
        // Ambiguous forms fail before code lookup; parsed exchange attempts remain single-use.
        const accepted = await json(prefix + "/oauth/token", issued);
        assert.equal(accepted.status, 200);
        const token = await accepted.json();
        assert.deepEqual(token.scope.split(" "), ["all", "status", "read", "write", "shell"]);
      }
    });

    await t.test(`${prefix || "root"}: exchange binds client/callback/verifier and keeps one-use semantics`, async () => {
      for (const changes of [{ client_id: "unregistered" }, { redirect_uri: redirects[1] }, { code_verifier: {} },
        { code_verifier: "A".repeat(42) }, { code_verifier: "A".repeat(129) }, { code_verifier: verifier + "\n" },
        { code_verifier: "Z".repeat(43) }]) {
        const issued = await grant(prefix);
        const before = stateHash();
        const rejected = await json(prefix + "/oauth/token", { ...issued, ...changes });
        assert.equal(rejected.status, 400);
        assert.equal((await rejected.json()).error, "invalid_grant");
        assert.equal((await json(prefix + "/oauth/token", issued)).status, 400);
        assert.equal(stateHash(), before);
      }
    });
  }

  await t.test("persisted legacy token, registration IDs, state format, and scopes survive restart", async () => {
    const before = stateHash();
    await stop(child);
    await launch();
    assert.equal(stateHash(), before, "Restart must not rewrite or invalidate state.");
    const state = JSON.parse(readFileSync(statePath, "utf8"));
    assert.equal(state.version, 1);
    assert(state.accessTokens.some((token) => token.hash === hash(legacyToken)));
    assert(!readFileSync(statePath, "utf8").includes(legacyToken));
    for (const oldClient of legacyClients) assert.deepEqual(state.clients.find((c) => c.clientId === oldClient.clientId), oldClient);
    const result = await rpc("/hostgate", legacyToken, "tools/call", { name: "status", arguments: {} });
    assert.equal(result.structuredContent.hostname, os.hostname());
    const issued = await grant("/hostgate");
    assert.equal((await json("/hostgate/oauth/token", issued)).status, 200);
    assert(!stderr.includes(password));
    assert(!stderr.includes(legacyToken));
    assert.equal(stderr, "", "Invalid OAuth requests must not throw server errors.");
  });
});
