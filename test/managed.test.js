import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import crypto from "node:crypto";
import fs from "node:fs";
import net from "node:net";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";
import { alive, digest, healthUrl, normalizeEnvironment, queueRequest, readJson, savedEnvironment, sleep, taskMatches, waitRequest, windows, writeJson } from "../src/managed-common.js";
import { parseServiceArgs } from "../src/service-manager.js";
import { stageEnvironment } from "../src/supervisor.js";
import { shellEnvironment } from "../src/shell.js";
import { collectDoctor } from "../src/doctor.js";

const root = fileURLToPath(new URL("../", import.meta.url));
const temporary = (name) => fs.mkdtempSync(path.join(os.tmpdir(), name));
async function waitFor(fn, timeout = 20000) {
  const until = Date.now() + timeout;
  while (Date.now() < until) { const value = await fn(); if (value) return value; await sleep(100); }
  throw new Error("Isolated manager condition timed out.");
}

test("saved environment preserves literal credentials, case, and all account capabilities", () => {
  const original = { Path: "C:\\Tools", PORT: "8787", HOST: "127.0.0.1", HOSTGATE_OAUTH_PASSWORD: 'test#"=secret', EXTRA_VAR: "preserve-me" };
  assert.deepEqual(normalizeEnvironment(original), original);
  assert.deepEqual(original, { ...original });
  assert.equal(stageEnvironment(original).HOSTGATE_OAUTH_PASSWORD, original.HOSTGATE_OAUTH_PASSWORD);
  assert.equal(stageEnvironment(original).PORT, "0");
  assert.equal(stageEnvironment(original).EXTRA_VAR, "preserve-me");
  assert.equal(original.PORT, "8787");
  for (const invalid of [{}, { ...original, PATH: "duplicate" }, { ...original, PORT: "0" }, { ...original, X: 12 }, { ...original, X: "bad\0value" }]) {
    assert.throws(() => normalizeEnvironment(invalid));
  }
  assert.equal(healthUrl({ HOST: "::", PORT: "9000" }), "http://[::1]:9000/hostgate/health");
});

test("install and restart require explicit intent and adoption cannot infer credentials", () => {
  assert.throws(() => parseServiceArgs(["install"]));
  assert.throws(() => parseServiceArgs(["restart"]));
  assert.throws(() => parseServiceArgs(["install", "--yes", "--adopt-pid", "123"]));
  assert.throws(() => parseServiceArgs(["status", "--import-stdin"]));
  assert.throws(() => parseServiceArgs(["install", "--yes", "--yes"]));
  assert.equal(parseServiceArgs(["install", "--yes", "--import-stdin", "--adopt-pid", "123"]).adoptPid, 123);
  assert.equal(parseServiceArgs(["restart", "--yes"]).operation, "restart");
});

test("task identity checks reject changed users, privilege, commands, and disabled recovery", () => {
  const config = { nodePath: "C:\\node.exe", supervisorPath: "C:\\supervisor.js", directory: "C:\\managed", sid: "S-1-test" };
  const task = { exists: true, enabled: true, executable: config.nodePath, arguments: '"C:\\supervisor.js" "C:\\managed"',
    user: config.sid, logonType: 3, runLevel: 0, logonTrigger: true, executionTimeLimit: "PT0S", restartCount: 5 };
  assert(taskMatches(task, config));
  for (const change of [{ user: "different" }, { arguments: "wrong" }, { enabled: false }, { runLevel: 1 }, { logonTrigger: false }, { restartCount: 0 }]) {
    assert(!taskMatches({ ...task, ...change }, config));
  }
});

test("durable request IDs cannot be overwritten by caller fields and receipts survive reread", async () => {
  const dir = temporary("hostgate-request-test-");
  fs.mkdirSync(path.join(dir, "requests")); fs.mkdirSync(path.join(dir, "results"));
  const ticket = queueRequest(dir, "restart", { id: "bad", expectedCommit: "a".repeat(40) });
  assert.match(ticket.id, /^[a-f0-9-]{36}$/);
  assert.equal(readJson(path.join(dir, "requests", ticket.id + ".json")).id, ticket.id);
  writeJson(ticket.resultPath, { success: true });
  assert.deepEqual(await waitRequest(ticket, 200), { success: true });
  assert(fs.existsSync(path.join(dir, "requests", ticket.id + ".json")));
});

test("doctor distinguishes configured, running, restart-ready and logon recovery", async () => {
  for (const ready of [true, false]) {
    const report = await collectDoctor({ projectRoot: root, platform: "win32", env: {}, readConfig: () => ({ source: "missing", values: {} }),
      managed: { configured: true, decryptable: true, running: true, restartReady: ready, autostart: ready, host: "127.0.0.1", port: 8787 } }, {
      resolveDependency: () => "installed", run: () => ({ ok: true, stdout: "{}" }),
      probe: async () => ({ status: 200, data: { ok: true, name: "hostgate" } })
    });
    const get = (id) => report.checks.find((c) => c.id === id);
    assert.equal(get("configured").status, "ok"); assert.equal(get("running").status, "ok");
    assert.equal(get("restart").status, ready ? "ok" : "attention");
    assert.equal(get("background").status, ready ? "ok" : "attention");
  }
});

test("Windows DPAPI roundtrip and ACL setup preserve bytes without plaintext credential files", { skip: process.platform !== "win32" }, () => {
  const dir = temporary("hostgate-dpapi-test-");
  windows("secure", { directory: dir });
  const env = { HOSTGATE_OAUTH_PASSWORD: crypto.randomUUID() + '#"=literal', PORT: "8787", EXTRA: "retain" };
  const protectedValue = windows("protect", { text: JSON.stringify(env) });
  assert(!protectedValue.ciphertext.includes(env.HOSTGATE_OAUTH_PASSWORD));
  fs.writeFileSync(path.join(dir, "environment.dpapi"), protectedValue.ciphertext);
  assert.deepEqual(savedEnvironment(dir), env);
  assert.equal(fs.readdirSync(dir).length, 1);
  assert.throws(() => windows("unprotect", { ciphertext: "corrupt-test-ciphertext" }), /unprotect failed/);
});

test("isolated Windows supervisor handles restart, crash recovery, activation rollback, and disconnect", { skip: process.platform !== "win32", timeout: 90000 }, async (t) => {
  const dir = temporary("hostgate-supervisor-test-");
  windows("secure", { directory: dir });
  for (const name of ["requests", "results", "releases"]) fs.mkdirSync(path.join(dir, name));
  const reservation = net.createServer();
  await new Promise((resolve) => reservation.listen(0, "127.0.0.1", resolve));
  const port = reservation.address().port;
  await new Promise((resolve) => reservation.close(resolve));
  function release(name, failLive = false) {
    const directory = path.join(dir, "releases", name); fs.mkdirSync(path.join(directory, "src"), { recursive: true });
    fs.writeFileSync(path.join(directory, "package.json"), '{"type":"module"}');
    fs.writeFileSync(path.join(directory, "src", "server.js"), `import http from 'node:http';\n${failLive ? "if(process.env.PORT !== '0') process.exit(13);" : ""}\nhttp.createServer((req,res)=>{res.setHeader('Content-Type','application/json');res.end(JSON.stringify({ok:true,name:'hostgate'}));}).listen(Number(process.env.PORT),process.env.HOST);\n`);
    return { path: directory, commit: (failLive ? "b" : name === "initial" ? "a" : "c").repeat(40) };
  }
  const initial = release("initial"); const bad = release("bad", true); const next = release("next");
  const env = { ...shellEnvironment(), HOME: dir, USERPROFILE: dir, HOST: "127.0.0.1", PORT: String(port), HOSTGATE_OAUTH_PASSWORD: crypto.randomUUID() };
  fs.writeFileSync(path.join(dir, "environment.dpapi"), windows("protect", { text: JSON.stringify(env) }).ciphertext);
  const credentialHash = digest(fs.readFileSync(path.join(dir, "environment.dpapi")));
  const config = { schemaVersion: 1, managerApi: 1, directory: dir, repoRoot: dir, nodePath: process.execPath,
    childPath: path.join(root, "src", "managed-child.js"), adapterPath: path.join(root, "src", "windows-manager.ps1"), current: initial, bootstrap: null };
  writeJson(path.join(dir, "deployment.json"), config);
  const controller = spawn(process.execPath, [path.join(root, "src", "supervisor.js"), dir], { windowsHide: true, stdio: ["ignore", "pipe", "pipe"] });
  let errors = ""; controller.stdout.resume(); controller.stderr.on("data", (chunk) => { errors += chunk; });
  t.after(async () => { if (controller.exitCode === null && controller.signalCode === null) controller.kill(); await sleep(500); });
  const status = () => readJson(path.join(dir, "status.json"), {});
  const started = await waitFor(() => status().phase === "running" && status().childPid && status());
  process.kill(started.childPid); // Only the disposable child created by this test.
  const recovered = await waitFor(() => status().phase === "running" && status().childPid !== started.childPid && status().childPid && status());
  assert(alive(recovered.childPid));
  const restarted = await waitRequest(queueRequest(dir, "restart", { expectedCommit: initial.commit }), 20000);
  assert(restarted.success);
  assert.notEqual(restarted.childPid, recovered.childPid);
  const rolledBack = await waitRequest(queueRequest(dir, "activate", { release: bad, expectedCommit: initial.commit }), 25000);
  assert.equal(rolledBack.success, false); assert.equal(rolledBack.rolledBack, true);
  assert.equal(readJson(path.join(dir, "deployment.json")).current.commit, initial.commit);
  const activated = await waitRequest(queueRequest(dir, "activate", { release: next, expectedCommit: initial.commit }), 20000);
  assert(activated.success); assert.equal(readJson(path.join(dir, "deployment.json")).previous.commit, initial.commit);
  const rollback = await waitRequest(queueRequest(dir, "activate", { release: initial, expectedCommit: next.commit }), 20000);
  assert(rollback.success);
  assert.equal(digest(fs.readFileSync(path.join(dir, "environment.dpapi"))), credentialHash);
  assert(!fs.readFileSync(path.join(dir, "events.jsonl"), "utf8").includes(env.HOSTGATE_OAUTH_PASSWORD));
  const lastPid = status().childPid;
  controller.kill();
  await waitFor(() => !alive(lastPid));
  assert.equal(errors, "");
  t.diagnostic(`Isolated manager fixture retained: ${dir}`);
});
