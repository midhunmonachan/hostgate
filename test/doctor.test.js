import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import crypto from "node:crypto";
import { once } from "node:events";
import { mkdirSync, mkdtempSync, readFileSync, readdirSync, writeFileSync } from "node:fs";
import http from "node:http";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";
import { collectDoctor, connectorUrl, formatDoctor, funnelUrls, httpProbe, parseDoctorArgs } from "../src/doctor.js";
import { shellEnvironment } from "../src/shell.js";

const root = fileURLToPath(new URL("../", import.meta.url));
const publicBase = "https://example.ts.net/hostgate";
const scopes = ["all", "status", "read", "write", "shell"];
const config = () => ({ source: "user", values: {
  PORT: "8787", HOST: "127.0.0.1", HOSTGATE_OAUTH_USERNAME: "doctor-user", HOSTGATE_OAUTH_PASSWORD: "doctor-password#\"=literal"
} });
const funnel = () => ({
  TCP: { "443": { HTTPS: true } }, AllowFunnel: { "example.ts.net:443": true },
  Web: { "example.ts.net:443": { Handlers: { "/hostgate": { Proxy: "http://127.0.0.1:8787/hostgate" } } } }
});
function healthy(url) {
  const origin = url.startsWith("https:") ? publicBase : "http://127.0.0.1:8787/hostgate";
  if (url.endsWith("/health")) return { status: 200, data: { ok: true, name: "hostgate" } };
  if (url.endsWith("oauth-authorization-server")) return { status: 200, data: {
    issuer: origin, authorization_endpoint: `${origin}/oauth/authorize`, token_endpoint: `${origin}/oauth/token`,
    registration_endpoint: `${origin}/oauth/register`, code_challenge_methods_supported: ["S256"], scopes_supported: scopes
  } };
  if (url.endsWith("oauth-protected-resource")) return { status: 200, data: {
    resource: `${origin}/mcp`, authorization_servers: [origin], scopes_supported: scopes
  } };
  return { status: 401, data: { error: "authorization_required" },
    challenge: `Bearer resource_metadata="${origin}/.well-known/oauth-protected-resource"` };
}
async function diagnose(options = {}, overrides = {}) {
  const commands = [];
  const urls = [];
  const report = await collectDoctor({ projectRoot: root, platform: "win32", nodeVersion: "22.0.0", env: {}, readConfig: config, ...options }, {
    resolveDependency: () => "/installed",
    run: (cmd, args, opts) => { commands.push({ cmd, args, opts }); return { ok: true,
      stdout: cmd.startsWith("tailscale") ? JSON.stringify(funnel()) : "" }; },
    probe: async (url) => { urls.push(url); return healthy(url); }, ...overrides
  });
  return { report, commands, urls, get: (id) => report.checks.find((check) => check.id === id) };
}

test("doctor reports availability separately from unverified sign-in and boot readiness", async () => {
  const { report, commands, urls, get } = await diagnose();
  assert.equal(report.exitCode, 0);
  for (const id of ["runtime", "dependencies", "npm", "shell", "local", "tunnel", "https", "discovery", "auth-gate"]) assert.equal(get(id).status, "ok", id);
  assert.equal(get("signin").status, "unverified");
  assert.equal(get("background").status, "unverified");
  assert.match(get("restart").message, /restart has not been tested/);
  assert.equal(urls.length, 5);
  assert.deepEqual(commands.find(({ cmd }) => cmd === "tailscale.exe").args, ["funnel", "status", "--json"]);
  assert(!commands.some(({ cmd }) => cmd === "systemctl"));
});

test("doctor detects environment-only credentials without claiming a live service is broken", async () => {
  const { report, get } = await diagnose({ readConfig: () => ({ source: "missing", values: {} }), env: {
    HOSTGATE_OAUTH_PASSWORD: "memory-only-secret", PORT: "8787", HOST: "127.0.0.1"
  } });
  assert.equal(get("restart").status, "attention");
  assert.match(get("restart").nextStep, /Do not stop a working server/);
  assert.equal(get("local").status, "ok");
  assert.equal(report.exitCode, 1);
  assert(!JSON.stringify(report).includes("memory-only-secret"));
});

test("doctor does not fall back to another configuration after a read error", async () => {
  const { report, get, urls } = await diagnose({ readConfig: () => { throw new Error("private-config-detail"); } });
  assert.equal(get("restart").status, "attention");
  assert.equal(get("local").status, "attention");
  assert.equal(urls.length, 0);
  assert(!JSON.stringify(report).includes("private-config-detail"));
});

test("doctor recognizes saved legacy credentials and respects environment binding overrides", async () => {
  const visited = [];
  const { get } = await diagnose({ readConfig: () => ({ ...config(), source: "legacy" }), env: { PORT: "9999", HOST: "::" } }, {
    probe: async (url) => { visited.push(url); return healthy(url); }
  });
  assert.equal(get("restart").status, "unverified");
  assert.equal(visited[0], "http://[::1]:9999/hostgate/health");
  assert.equal(get("tunnel").status, "unverified");
});

test("doctor identifies missing runtime, packages, npm, and shell without trying installation", async () => {
  const calls = [];
  const { report, get } = await diagnose({ nodeVersion: "20.0.0" }, {
    resolveDependency: () => { throw new Error("not installed"); },
    run: (cmd, args) => { calls.push([cmd, ...args]); return { ok: false, stdout: "private-error" }; }
  });
  for (const id of ["runtime", "dependencies", "npm", "shell"]) assert.equal(get(id).status, "attention");
  assert.equal(report.exitCode, 1);
  assert(!JSON.stringify(report).includes("private-error"));
  assert(!calls.flat().some((arg) => ["install", "ci", "onboard", "reset", "start"].includes(arg)));
});

test("Linux probes Bash without loading profiles and checks only user-service status", async () => {
  const { commands, get } = await diagnose({ platform: "linux", env: { XDG_RUNTIME_DIR: "/run/user/example" } });
  assert.deepEqual(commands.find(({ cmd }) => cmd === "/bin/bash").args.slice(0, 3), ["--noprofile", "--norc", "-c"]);
  assert.deepEqual(commands.find(({ cmd }) => cmd === "systemctl").args, ["--user", "is-active", "--quiet", "hostgate.service"]);
  assert.equal(get("background").status, "ok");
  assert.equal(commands.find(({ cmd }) => cmd === "systemctl").opts.env.XDG_RUNTIME_DIR, "/run/user/example");
  assert(!commands.some(({ cmd }) => cmd === "where.exe"));
});

test("missing Linux systemd remains a foreground-compatible diagnostic, not a startup failure", async () => {
  const { get } = await diagnose({ platform: "linux" }, { run: () => ({ ok: false, stdout: "" }) });
  assert.equal(get("background").status, "unverified");
  assert.match(get("background").nextStep, /Foreground operation/);
});

for (const [label, result, expected] of [
  ["unavailable server", { status: null, data: null }, /No health response/],
  ["another service on the port", { status: 200, data: { name: "other" } }, /another program/],
  ["wrong health status", { status: 503, data: { ok: true, name: "hostgate" } }, /another program/]
]) test(`doctor handles ${label}`, async () => {
  const { get } = await diagnose({}, { probe: async () => result });
  assert.equal(get("local").status, "attention");
  assert.match(get("local").message, expected);
  assert.equal(get("https").status, "attention");
});

test("invalid binding and malformed URLs are neither contacted nor echoed", async () => {
  for (const env of [{ PORT: "0" }, { PORT: "65536" }, { HOST: "secret@bad/path" }]) {
    const { get, urls, report } = await diagnose({ env });
    assert.equal(get("local").status, "attention");
    assert.equal(urls.length, 0);
    assert(!JSON.stringify(report).includes("secret@bad/path"));
  }
  const { get, urls } = await diagnose({ publicUrl: "https://user:password@example.invalid/hostgate/mcp" });
  assert.equal(get("https").status, "attention");
  assert.equal(urls.length, 1);
});

test("explicit HTTPS URL works without Tailscale; failed probes remain separate findings", async () => {
  const { get, commands } = await diagnose({ publicUrl: `${publicBase}/mcp` });
  assert.equal(get("https").status, "ok");
  assert(!commands.some(({ cmd }) => cmd.startsWith("tailscale")));
  const unavailable = await diagnose({ publicUrl: `${publicBase}/mcp` }, { probe: async () => { throw new Error("private TLS error"); } });
  assert.equal(unavailable.get("https").status, "attention");
  assert(!JSON.stringify(unavailable.report).includes("private TLS error"));
});

test("doctor will not claim verified HTTPS with certificate validation disabled", async () => {
  const { urls, get } = await diagnose({ publicUrl: `${publicBase}/mcp`, env: { NODE_TLS_REJECT_UNAUTHORIZED: "0" } });
  assert.equal(urls.length, 1);
  assert.equal(get("https").status, "attention");
  assert.match(get("https").message, /certificate validation is disabled/);
});

test("bad or hostile discovery never crashes or leaks body data", async () => {
  const { report, get } = await diagnose({}, { probe: async (url) => url.endsWith("oauth-authorization-server")
    ? { status: 200, data: { issuer: publicBase, authorization_endpoint: `${publicBase}/oauth/authorize`,
      token_endpoint: `${publicBase}/oauth/token`, registration_endpoint: `${publicBase}/oauth/register`,
      code_challenge_methods_supported: {}, private: "do-not-display" } } : healthy(url) });
  assert.equal(get("https").status, "ok");
  assert.equal(get("discovery").status, "attention");
  assert(!JSON.stringify(report).includes("do-not-display"));
});

test("health success never hides a missing authentication challenge", async () => {
  const { get } = await diagnose({}, { probe: async (url) => url.endsWith("/mcp") ? { status: 200, data: {} } : healthy(url) });
  assert.equal(get("https").status, "ok");
  assert.equal(get("auth-gate").status, "attention");
});

test("Funnel discovery ignores unrelated routes, private Serve, missing TLS, and ambiguous URLs", async () => {
  const base = "http://127.0.0.1:8787";
  assert.deepEqual(funnelUrls(funnel(), base), [`${publicBase}/mcp`]);
  for (const value of [null, {}, { ...funnel(), AllowFunnel: {} }, { ...funnel(), TCP: {} }]) assert.deepEqual(funnelUrls(value, base), []);
  assert.deepEqual(funnelUrls(funnel(), "http://127.0.0.1:8888"), []);
  const ambiguous = funnel();
  ambiguous.Web["other.ts.net:443"] = ambiguous.Web["example.ts.net:443"];
  ambiguous.AllowFunnel["other.ts.net:443"] = true;
  const { get, urls } = await diagnose({}, { run: () => ({ ok: true, stdout: JSON.stringify(ambiguous) }) });
  assert.equal(get("tunnel").status, "unverified");
  assert.equal(urls.length, 1);
});

test("credentials never reach diagnostic child environments, JSON, or text reports", async () => {
  const env = { ...config().values, PATH: "/some/path", GITHUB_TOKEN: "private-github-token" };
  const before = JSON.stringify(env);
  const { commands, report } = await diagnose({ env });
  assert.equal(JSON.stringify(env), before);
  for (const { opts } of commands) {
    assert.equal(opts.env.HOSTGATE_OAUTH_PASSWORD, undefined);
    assert.equal(opts.env.HOSTGATE_OAUTH_USERNAME, undefined);
    assert.equal(opts.env.GITHUB_TOKEN, undefined);
  }
  const text = JSON.stringify(report) + formatDoctor(report);
  for (const secret of [env.HOSTGATE_OAUTH_USERNAME, env.HOSTGATE_OAUTH_PASSWORD, env.GITHUB_TOKEN]) assert(!text.includes(secret));
});

test("argument parsing is strict and never echoes secret-bearing arguments", () => {
  assert.deepEqual(parseDoctorArgs([]), { json: false, publicUrl: null });
  assert.deepEqual(parseDoctorArgs(["--json", "--url", `${publicBase}/mcp`]), { json: true, publicUrl: `${publicBase}/mcp` });
  assert.equal(connectorUrl("https://example.test/mcp"), "https://example.test/mcp");
  for (const args of [["--password=secret"], ["--json", "--json"], ["--url"], ["--url", "http://example.test/mcp"],
    ["--url", "https://user:secret@example.test/mcp"], ["--url", "https://example.test/mcp?token=secret"],
    ["--url", "https://example.test/mcp#secret"], ["--url", "https://example.test/other"]]) {
    assert.throws(() => parseDoctorArgs(args), (error) => !error.message.includes("secret"));
  }
});

test("HTTP probes use bounded unauthenticated GETs and reject oversized response bodies", async () => {
  let seen;
  const ok = await httpProbe("https://example.test/health", async (_url, options) => {
    seen = options;
    return new Response(JSON.stringify({ ok: true, name: "hostgate" }), { status: 200 });
  });
  assert.equal(ok.data.name, "hostgate");
  assert.equal(seen.method, "GET");
  assert.equal(seen.redirect, "error");
  assert.equal(seen.credentials, "omit");
  assert.equal(seen.headers.Authorization, undefined);
  assert(seen.signal instanceof AbortSignal);
  const oversized = await httpProbe("https://example.test", async () => new Response("x".repeat(65537)));
  assert.equal(oversized.status, null);
  const broken = await httpProbe("https://example.test", async () => { throw new Error("private fetch failure"); });
  assert.equal(broken.status, null);
  assert(!JSON.stringify(broken).includes("private"));
});

function snapshot(directory) {
  return readdirSync(directory, { withFileTypes: true }).flatMap((entry) => {
    const file = path.join(directory, entry.name);
    return entry.isDirectory() ? [[file, "directory"], ...snapshot(file)] : [[file, crypto.createHash("sha256").update(readFileSync(file)).digest("hex")]];
  });
}

test("real doctor CLI preserves isolated configuration and OAuth state and reports a live endpoint", { timeout: 20000 }, async (t) => {
  const home = mkdtempSync(path.join(os.tmpdir(), "hostgate-doctor-"));
  t.diagnostic(`Isolated doctor fixture retained at ${home}`);
  const server = http.createServer((req, res) => {
    assert.equal(req.method, "GET");
    assert.equal(req.headers.authorization, undefined);
    res.setHeader("Content-Type", "application/json");
    res.end(JSON.stringify({ ok: true, name: "hostgate" }));
  });
  server.listen(0, "127.0.0.1");
  await once(server, "listening");
  t.after(() => new Promise((resolve) => server.close(resolve)));
  const configDir = path.join(home, ".config/hostgate");
  const stateDir = path.join(home, ".local/share/hostgate");
  mkdirSync(configDir, { recursive: true, mode: 0o700 });
  mkdirSync(stateDir, { recursive: true, mode: 0o700 });
  const password = crypto.randomUUID();
  writeFileSync(path.join(configDir, ".env"), `HOST=127.0.0.1\nPORT=${server.address().port}\nHOSTGATE_OAUTH_PASSWORD=${password}\n`, { mode: 0o600 });
  writeFileSync(path.join(stateDir, "oauth-state.json"), '{"version":1,"clients":[],"accessTokens":[]}', { mode: 0o600 });
  // Model existing Windows profile folders; PowerShell initializes these on a fresh home.
  if (process.platform === "win32") mkdirSync(path.join(home, "AppData/Roaming"), { recursive: true });
  const before = snapshot(home);
  const env = { ...shellEnvironment(), HOME: home, USERPROFILE: home, PATH: path.dirname(process.execPath) };
  const child = spawn(process.execPath, [path.join(root, "bin/hostgate.js"), "doctor", "--json"], {
    cwd: root, env, windowsHide: true, stdio: ["ignore", "pipe", "pipe"], timeout: 15000
  });
  let stdout = "";
  let stderr = "";
  child.stdout.setEncoding("utf8"); child.stderr.setEncoding("utf8");
  child.stdout.on("data", (data) => { stdout += data; });
  child.stderr.on("data", (data) => { stderr += data; });
  const [code] = await once(child, "close");
  assert.equal(stderr, "");
  const report = JSON.parse(stdout);
  assert.equal(code, report.exitCode);
  assert.equal(report.checks.find((check) => check.id === "local").status, "ok");
  assert.equal(report.checks.find((check) => check.id === "restart").status, "unverified");
  assert.equal(report.checks.find((check) => check.id === "signin").status, "unverified");
  assert(!stdout.includes(password));
  assert.deepEqual(snapshot(home), before);
});


test("empty credential overrides are not reported as a usable startup environment", async () => {
  const { get } = await diagnose({ env: { HOSTGATE_OAUTH_PASSWORD: "" } });
  assert.equal(get("restart").status, "attention");
  assert.match(get("restart").message, /overrides the saved password with an empty value/);
  assert.equal(get("local").status, "ok");
});
