import assert from "node:assert/strict";
import { spawn, spawnSync } from "node:child_process";
import crypto from "node:crypto";
import { once } from "node:events";
import { existsSync, mkdirSync, mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";
import { shellEnvironment } from "../src/shell.js";

const root = fileURLToPath(new URL("../", import.meta.url));
const cli = path.join(root, "bin", "hostgate.js");
const isWindows = process.platform === "win32";

function runCli(args, env) {
  return spawnSync(process.execPath, [cli, ...args], {
    cwd: root, env, encoding: "utf8", windowsHide: true, timeout: 10000
  });
}

async function stopChild(child) {
  if (child.exitCode === null && child.signalCode === null) {
    const closed = once(child, "close");
    child.kill();
    await closed;
  }
}

function launch(env, home) {
  const child = spawn(process.execPath, [cli, "start"], {
    cwd: root, env, windowsHide: true, stdio: ["ignore", "pipe", "pipe"]
  });
  const ready = new Promise((resolve, reject) => {
    let output = "";
    let errors = "";
    const timer = setTimeout(() => reject(new Error(`Smoke server did not become ready: ${errors}`)), 15000);
    const fail = (error) => { clearTimeout(timer); reject(error); };
    child.once("error", fail);
    child.once("exit", (code) => fail(new Error(`Smoke server exited ${code}: ${errors}`)));
    child.stderr.setEncoding("utf8");
    child.stderr.on("data", (chunk) => { errors += chunk; });
    child.stdout.setEncoding("utf8");
    child.stdout.on("data", (chunk) => {
      output += chunk;
      const match = output.match(/Hostgate listening at http:\/\/127\.0\.0\.1:(\d+)\/mcp/);
      // Verify home isolation before sending any OAuth request that writes state.
      if (match && output.includes(`OAuth state: ${path.join(home, ".local/share/hostgate/oauth-state.json")}`)) {
        clearTimeout(timer);
        resolve(`http://127.0.0.1:${match[1]}`);
      }
    });
  });
  return { child, ready };
}

async function request(url, options = {}) {
  return fetch(url, { ...options, signal: AbortSignal.timeout(10000), redirect: "manual" });
}

async function jsonPost(url, body, headers = {}) {
  return request(url, {
    method: "POST", headers: { "Content-Type": "application/json", ...headers }, body: JSON.stringify(body)
  });
}

let nextId = 0;
async function rpc(base, token, method, params = {}) {
  const response = await jsonPost(`${base}/hostgate/mcp`, {
    jsonrpc: "2.0", id: ++nextId, method, params
  }, {
    Authorization: `Bearer ${token}`, Accept: "application/json, text/event-stream",
    "MCP-Protocol-Version": "2025-03-26"
  });
  assert.equal(response.status, 200);
  const text = await response.text();
  const message = response.headers.get("content-type")?.includes("text/event-stream")
    ? text.split(/\r?\n/).filter((line) => line.startsWith("data: ")).map((line) => JSON.parse(line.slice(6))).find((item) => item.id === nextId)
    : JSON.parse(text);
  assert(message, "Expected an MCP JSON-RPC response");
  assert.equal(message.error, undefined, JSON.stringify(message.error));
  return message.result;
}

test("isolated local CLI, OAuth, and MCP smoke test", { timeout: 90000 }, async (t) => {
  const home = mkdtempSync(path.join(os.tmpdir(), "hostgate-smoke-"));
  const configDir = path.join(home, ".config", "hostgate");
  mkdirSync(configDir, { recursive: true });
  const username = "hostgate-smoke";
  const password = `${crypto.randomUUID()}#\"=literal`;
  writeFileSync(path.join(configDir, ".env"),
    `PORT=0\nHOST=127.0.0.1\nHOSTGATE_OAUTH_USERNAME=${username}\nHOSTGATE_OAUTH_PASSWORD=${password}\n`, { mode: 0o600 });
  const env = { ...shellEnvironment(), HOME: home, USERPROFILE: home };
  // Fixtures are intentionally retained: the smoke test never deletes files.
  t.diagnostic(`Isolated smoke fixture retained at ${home}`);
  let running = launch(env, home);
  t.after(async () => { await stopChild(running.child); });
  let base = await running.ready;

  async function authorization(scope = "all", suppliedPassword = password) {
    const registered = await jsonPost(`${base}/hostgate/oauth/register`, {
      client_name: "Hostgate local smoke test", redirect_uris: ["http://127.0.0.1/callback"]
    });
    assert.equal(registered.status, 201);
    const { client_id: clientId } = await registered.json();
    const verifier = crypto.randomBytes(32).toString("base64url");
    const params = {
      response_type: "code", client_id: clientId, redirect_uri: "http://127.0.0.1/callback",
      code_challenge: crypto.createHash("sha256").update(verifier).digest("base64url"),
      code_challenge_method: "S256", state: "smoke-state", scope
    };
    const response = await request(`${base}/hostgate/oauth/authorize`, {
      method: "POST", headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({ ...params, username, password: suppliedPassword })
    });
    return { response, clientId, verifier, params };
  }

  async function exchange(grant, verifier = grant.verifier) {
    const location = new URL(grant.response.headers.get("location"));
    return jsonPost(`${base}/hostgate/oauth/token`, {
      grant_type: "authorization_code", client_id: grant.clientId,
      redirect_uri: grant.params.redirect_uri, code: location.searchParams.get("code"), code_verifier: verifier
    });
  }

  let allToken;
  let statusToken;
  await t.test("CLI help, errors, and noninteractive onboarding have useful exit codes", () => {
    const help = runCli(["help"], env);
    assert.equal(help.status, 0, help.stderr);
    assert.match(help.stdout, /hostgate start/);
    assert.equal(runCli(["unknown-command"], env).status, 2);
    const onboard = runCli(["onboard"], env);
    assert.equal(onboard.status, 1);
    assert.match(onboard.stderr, /interactive terminal/);
    const missing = runCli(["start"], { ...env, HOSTGATE_OAUTH_PASSWORD: "" });
    assert.equal(missing.status, 1);
    assert.match(missing.stderr, /OAuth password is not configured/);
  });

  await t.test("Windows onboarding configures only its isolated home without installing a service", { skip: !isWindows }, () => {
    const onboardingHome = mkdtempSync(path.join(os.tmpdir(), "hostgate-onboard-"));
    t.diagnostic(`Isolated onboarding fixture retained at ${onboardingHome}`);
    // Simulate terminal answers without exposing the real user's home or enabling Funnel.
    const bootstrap = `
      import readline from "node:readline/promises";
      import { pathToFileURL } from "node:url";
      Object.defineProperty(process.stdin, "isTTY", { value: true });
      Object.defineProperty(process.stdout, "isTTY", { value: true });
      const answers = ["onboard-smoke", ${JSON.stringify(password)}, "no"];
      readline.createInterface = () => ({
        question: async () => {
          if (!answers.length) throw new Error("Unexpected onboarding prompt");
          return answers.shift();
        },
        close() {}
      });
      process.argv = [process.execPath, ${JSON.stringify(cli)}, "onboard"];
      await import(pathToFileURL(process.argv[1]).href);
      if (answers.length) throw new Error("Onboarding did not ask all expected questions");
    `;
    const onboard = spawnSync(process.execPath, ["--input-type=module", "-e", bootstrap], {
      cwd: root, env: { ...env, HOME: onboardingHome, USERPROFILE: onboardingHome },
      encoding: "utf8", windowsHide: true, timeout: 10000
    });
    assert.equal(onboard.status, 0, onboard.stderr);
    assert.match(onboard.stdout, /No Windows service was installed or started/);
    assert.doesNotMatch(onboard.stdout, /Hostgate listening/);
    const config = readFileSync(path.join(onboardingHome, ".config/hostgate/.env"), "utf8");
    assert(config.includes("HOSTGATE_OAUTH_USERNAME=onboard-smoke\n"));
    assert(config.includes(`HOSTGATE_OAUTH_PASSWORD=${password}\n`));
    assert.equal(existsSync(path.join(onboardingHome, ".config/systemd")), false);
    assert.equal(existsSync(path.join(onboardingHome, ".local/share/hostgate/oauth-state.json")), false);
  });

  await t.test("health and discovery work at root and prefix; unauthenticated MCP is rejected", async () => {
    for (const prefix of ["", "/hostgate"]) {
      const health = await request(`${base}${prefix}/health`);
      assert.deepEqual(await health.json(), { ok: true, name: "hostgate" });
      const metadata = await request(`${base}${prefix}/.well-known/oauth-authorization-server`);
      const oauth = await metadata.json();
      assert.equal(oauth.issuer, `${base}${prefix}`);
      assert.deepEqual(oauth.scopes_supported, ["all", "status", "read", "write", "shell"]);
      assert.deepEqual(oauth.code_challenge_methods_supported, ["S256"]);
      const resource = await request(`${base}${prefix}/.well-known/oauth-protected-resource`);
      assert.equal((await resource.json()).resource, `${base}${prefix}/mcp`);
      for (const method of ["tools/list", "tools/call"]) {
        const denied = await jsonPost(`${base}${prefix}/mcp`, { jsonrpc: "2.0", id: 1, method });
        assert.equal(denied.status, 401);
        assert.match(denied.headers.get("www-authenticate"), /oauth-protected-resource/);
      }
    }
    const invalid = await jsonPost(`${base}/hostgate/mcp`, {}, { Authorization: "Bearer invalid-smoke-token" });
    assert.equal(invalid.status, 401);
  });

  await t.test("OAuth rejects bad credentials, unsupported scopes, and invalid PKCE", async () => {
    assert.equal((await authorization("all", "incorrect-smoke-password")).response.status, 401);
    assert.equal((await authorization("unsupported-smoke-scope")).response.status, 400);
    const grant = await authorization();
    assert.equal(grant.response.status, 302);
    assert.equal((await exchange(grant, "wrong-smoke-verifier")).status, 400);
    assert.equal((await exchange(grant)).status, 400, "Authorization codes are single-use even after failed exchange");
  });

  await t.test("OAuth PKCE succeeds with literal password punctuation and existing token semantics", async () => {
    const grant = await authorization();
    assert.equal(grant.response.status, 302);
    assert.equal(new URL(grant.response.headers.get("location")).searchParams.get("state"), "smoke-state");
    const response = await exchange(grant);
    assert.equal(response.status, 200);
    const token = await response.json();
    assert.equal(token.token_type, "Bearer");
    assert.equal(token.expires_in, 86400);
    assert.equal(token.refresh_token, undefined);
    assert(token.scope.split(" ").includes("all"));
    allToken = token.access_token;
    assert.equal((await exchange(grant)).status, 400);
    const limited = await exchange(await authorization("status"));
    assert.equal(limited.status, 200);
    statusToken = (await limited.json()).access_token;
  });

  await t.test("MCP initializes and lists exactly four tools with platform-specific metadata", async () => {
    const initialized = await rpc(base, allToken, "initialize", {
      protocolVersion: "2025-03-26", capabilities: {}, clientInfo: { name: "hostgate-smoke", version: "1.0.0" }
    });
    assert.equal(initialized.serverInfo.name, "hostgate");
    const { tools } = await rpc(base, allToken, "tools/list");
    assert.deepEqual(tools.map((tool) => tool.name).sort(), ["read", "shell", "status", "write"]);
    const shell = tools.find((tool) => tool.name === "shell");
    assert.match(shell.description, isWindows ? /PowerShell/ : /Bash/);
    assert.match(shell.inputSchema.properties.command.description, isWindows ? /powershell\.exe/ : /\/bin\/bash -lc/);
    assert.equal(shell.annotations.destructiveHint, true);
    assert.equal(tools.find((tool) => tool.name === "status").annotations.readOnlyHint, true);
  });

  await t.test("scopes allow status but block read, write, and shell", async () => {
    const status = await rpc(base, statusToken, "tools/call", { name: "status", arguments: {} });
    assert.equal(status.structuredContent.hostname, os.hostname());
    assert.equal(status.structuredContent.platform, process.platform);
    const deniedPath = path.join(home, "must-not-be-written.txt");
    for (const [name, args] of [
      ["read", { path: deniedPath }], ["write", { path: deniedPath, content: "not authorized" }],
      ["shell", { command: isWindows ? "Get-Date" : "date" }]
    ]) {
      const denied = await rpc(base, statusToken, "tools/call", { name, arguments: args });
      assert.equal(denied.isError, true);
      assert.match(denied.content[0].text, new RegExp(`missing required scope: ${name}`));
    }
    assert.equal(existsSync(deniedPath), false);
  });

  await t.test("legacy endpoint rejects an explicitly named-host request before any write", async () => {
    const file = path.join(home, "named-host-must-not-land-on-legacy.txt");
    const result = await rpc(base, allToken, "tools/call", { name: "write", arguments: { path: file, content: "not written", contextId: "project/chat", target: { hostId: crypto.randomUUID(), hostName: "Second laptop", endpoint: "https://second.example.test/mcp" } } });
    assert.equal(result.isError, true); assert.equal(existsSync(file), false);
  });

  await t.test("authorized file tools round-trip UTF-8 only inside the isolated home", async () => {
    const content = "Hostgate write/read test passed.\nUnicode: caf\u00e9 \u2603 \ud83d\ude80\n";
    const relative = "files with spaces/smoke.txt";
    const written = await rpc(base, allToken, "tools/call", {
      name: "write", arguments: { path: `~/${relative}`, content }
    });
    assert.equal(written.structuredContent.bytes, Buffer.byteLength(content));
    const paths = [path.join(home, relative), relative];
    if (isWindows) paths.push("~\\files with spaces\\smoke.txt");
    for (const requestedPath of paths) {
      const read = await rpc(base, allToken, "tools/call", { name: "read", arguments: { path: requestedPath } });
      assert.equal(read.structuredContent.text, content);
      assert.equal(read.structuredContent.bytes, Buffer.byteLength(content));
    }
  });

  await t.test("authorized shell runs only a harmless date command in the smoke server", async () => {
    const command = isWindows ? "Get-Date -Format o" : "date -u +%Y-%m-%dT%H:%M:%SZ";
    const result = await rpc(base, allToken, "tools/call", { name: "shell", arguments: { command } });
    assert.equal(result.structuredContent.exitCode, 0, result.structuredContent.stderr);
    assert.equal(result.structuredContent.command, command);
    assert.match(result.structuredContent.stdout, /^\d{4}-\d{2}-\d{2}T/);
  });

  await t.test("Windows CLI status checks health and logs explains its platform limitation", { skip: !isWindows }, () => {
    const checked = runCli(["status"], { ...env, PORT: new URL(base).port });
    assert.equal(checked.status, 0, checked.stderr);
    assert.match(checked.stdout, /not Windows service status/);
    assert.match(checked.stdout, /Hostgate is responding/);
    for (const args of [["logs"], ["logs", "-f"], ["logs", "--follow"]]) {
      const logs = runCli(args, env);
      assert.equal(logs.status, 1);
      assert.match(logs.stderr, /Windows log history is not managed/);
      assert.doesNotMatch(logs.stderr, /ENOENT|spawn journalctl/);
    }
  });

  await t.test("OAuth token persistence survives a smoke-server restart without touching live state", async () => {
    const statePath = path.join(home, ".local/share/hostgate/oauth-state.json");
    const saved = JSON.parse(readFileSync(statePath, "utf8"));
    assert.equal(saved.version, 1);
    assert(saved.accessTokens.some((token) => token.hash === crypto.createHash("sha256").update(allToken).digest("base64url")));
    assert(!readFileSync(statePath, "utf8").includes(allToken), "Only access-token hashes are persisted");
    const oldPort = new URL(base).port;
    await stopChild(running.child);
    if (isWindows) {
      const stopped = runCli(["status"], { ...env, PORT: oldPort });
      assert.equal(stopped.status, 1);
      assert.match(stopped.stderr, /not responding/);
    }
    running = launch(env, home);
    base = await running.ready;
    const status = await rpc(base, allToken, "tools/call", { name: "status", arguments: {} });
    assert.equal(status.structuredContent.platform, process.platform);
    assert.equal(existsSync(path.join(home, ".config/systemd/user/hostgate.service")), false);
  });
});
