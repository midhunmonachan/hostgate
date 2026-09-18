import assert from "node:assert/strict";
import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { spawnSync } from "node:child_process";
import test from "node:test";
import { fileURLToPath } from "node:url";
import { hostId, hostPaths } from "../src/host-paths.js";
import { addHost, findHost, localHost, readHosts, renameHost, removeHost, selectHost, selectedHost, registryPath, routingCard, hostName, hostEndpoint, contextName, hostCwd, profilePublic, readHostConfig, saveHostConfig } from "../src/host-profiles.js";
import { requireTarget, executionContext, runHostTool } from "../src/host-runtime.js";
import { managedHome } from "../src/managed-common.js";
import { taskSpecification } from "../src/service-plan.js";
import { shellEnvironment } from "../src/shell.js";
const root = fileURLToPath(new URL("../", import.meta.url));
const fixture = () => {
  const home = fs.mkdtempSync(path.join(os.tmpdir(), "hostgate-hosts-test-"));
  const a = addHost({ name: "Primary laptop", kind: "local", endpoint: "https://primary.example.test/hostgate/mcp", cwd: home }, home);
  const b = addHost({ name: "Second laptop", kind: "local", endpoint: "https://second.example.test/hostgate/mcp", cwd: home }, home);
  return { home, a, b };
};

test("profile identities, origins, directories and state never alias each other or legacy", () => {
  const { home, a, b } = fixture();
  assert.notEqual(a.id, b.id); assert.equal(hostId(a.id), a.id);
  const ap = hostPaths(a.id, home), bp = hostPaths(b.id, home);
  for (const key of Object.keys(ap)) { assert.notEqual(ap[key], bp[key]); assert(ap[key].includes(a.id)); }
  assert.equal(managedHome(home, a.id), ap.managed);
  assert.notEqual(managedHome(home, null), ap.managed);
  assert.equal(profilePublic(a, home).credentialsPresent, false);
  assert.equal(fs.existsSync(ap.config), false, "Adding metadata does not install or configure a server");
});
test("duplicate names, IDs, origin aliases and invalid URLs fail without changing registry", () => {
  const { home, a } = fixture(), file = registryPath(home), before = fs.readFileSync(file);
  for (const input of [
    { name: "primary LAPTOP", endpoint: "https://third.example.test/mcp" },
    { name: "Third laptop", endpoint: "https://primary.example.test/mcp" },
    { name: "Third laptop", endpoint: "https://user:password@third.example.test/mcp" },
    { name: "Third laptop", endpoint: "http://third.example.test/mcp" },
    { name: "Third laptop", endpoint: "https://third.example.test/mcp?token=secret" }
  ]) assert.throws(() => addHost({ kind: "local", cwd: home, ...input }, home));
  assert.throws(() => addHost({ kind: "remote", id: a.id, name: "Third laptop", platform: "linux", cwd: "/work", endpoint: "https://third.example.test/mcp" }, home));
  assert.deepEqual(fs.readFileSync(file), before);
});
test("selectors are exact and context selections never become an execution default", () => {
  const { home, a, b } = fixture();
  selectHost(a.id, "ProjectA/chat1", home); selectHost(b.id, "ProjectB/chat2", home);
  assert.equal(selectedHost("ProjectA/chat1", home).id, a.id);
  assert.equal(selectedHost("ProjectB/chat2", home).id, b.id);
  assert.throws(() => findHost(undefined, home)); assert.throws(() => findHost("Primary", home));
  assert.throws(() => selectedHost("ProjectA/another-chat", home));
  assert.equal(routingCard(a, "ProjectA/chat1").target.hostId, a.id);
  assert.equal(readHosts(home).profiles.length, 2);
});
test("rename preserves ID/state, retirement clears only that host's selections and retains files", () => {
  const { home, a, b } = fixture();
  const paths = hostPaths(a.id, home); fs.mkdirSync(paths.data, { recursive: true }); fs.writeFileSync(paths.oauth, "synthetic-retained-state");
  selectHost(a.id, "a", home); selectHost(b.id, "b", home);
  const renamed = renameHost(a.id, "Main laptop", home);
  assert.equal(renamed.id, a.id); assert.throws(() => findHost("Primary laptop", home));
  const result = removeHost(a.id, home); assert.equal(result.stateDeleted, false);
  assert.equal(fs.readFileSync(paths.oauth, "utf8"), "synthetic-retained-state");
  assert.throws(() => findHost(a.id, home)); assert.throws(() => selectedHost("a", home));
  assert.equal(selectedHost("b", home).id, b.id);
  assert.throws(() => addHost({ name: "Main laptop", kind: "local", cwd: home, endpoint: "https://new.example.test/mcp" }, home));
  assert.throws(() => addHost({ name: "New", kind: "local", cwd: home, endpoint: a.endpoint }, home));
});
test("configured managers block profile removal without removing deployment or credentials", () => {
  const { home, a } = fixture(), paths = hostPaths(a.id, home);
  fs.mkdirSync(paths.managed, { recursive: true }); fs.writeFileSync(path.join(paths.managed, "deployment.json"), "retained");
  assert.throws(() => removeHost(a.id, home), /Managed deployment/);
  assert(findHost(a.id, home).active);
});
test("registry lock and invalid metadata fail closed without replacing work", () => {
  const { home, a } = fixture(), file = registryPath(home), before = fs.readFileSync(file);
  fs.writeFileSync(path.join(path.dirname(file), "hosts.lock"), "another-writer");
  assert.throws(() => renameHost(a.id, "No change", home), /busy|locked/);
  assert.deepEqual(fs.readFileSync(file), before);
  const bad = JSON.parse(before); bad.profiles[0].password = "not-allowed"; fs.writeFileSync(file, JSON.stringify(bad));
  assert.throws(() => readHosts(home), /Invalid profile/);
});
test("remote profiles and profiles bound to another machine cannot execute locally", () => {
  const { home } = fixture();
  const remote = addHost({ kind: "remote", name: "Remote Linux", id: crypto.randomUUID(), platform: "linux", endpoint: "https://remote.example.test/mcp", cwd: "/srv/project" }, home);
  assert.throws(() => localHost(remote.id, home), /not a local profile/);
  const registry = readHosts(home); registry.profiles[0].machine = "some-other-machine"; fs.writeFileSync(registryPath(home), JSON.stringify(registry));
  assert.throws(() => localHost(registry.profiles[0].id, home), /not a local profile/);
});
test("validation rejects unsafe names, paths, contexts and profile IDs", () => {
  for (const s of ["", "../private", "bad\nname", "Primary\tLaptop", "https://secret@host"]) assert.throws(() => hostName(s));
  for (const s of ["__proto__", "constructor", "", "x\n", "../x with spaces"]) assert.throws(() => contextName(s));
  for (const s of ["../x", "", "a".repeat(36)]) assert.throws(() => hostId(s));
  for (const s of ["C:relative", "\\\\remote\\share", "bad"]) assert.throws(() => hostCwd(s, "win32"));
  assert.equal(hostEndpoint("https://PRIMARY.EXAMPLE.test:443/mcp"), "https://primary.example.test/mcp");
});
test("all named tool calls require the exact identity; targeted calls cannot land on legacy", async () => {
  const identity = { hostId: crypto.randomUUID(), hostName: "Primary laptop", endpoint: "https://primary.example.test/mcp" };
  const runtime = { identity, assertCurrent() {}, audit() {} }; let executed = 0;
  for (const args of [{}, { target: identity }, { target: { ...identity, hostName: "Second laptop" }, contextId: "chat-a" }, { target: { ...identity, endpoint: "https://other.example.test/mcp" }, contextId: "chat-a" }]) {
    const r = await runHostTool(runtime, {}, "write", args, {}, async () => { executed++; return {}; }); assert.equal(r.isError, true);
  }
  assert.equal(executed, 0);
  assert.throws(() => requireTarget(null, { target: identity }));
  assert.doesNotThrow(() => requireTarget(runtime, { target: identity, contextId: "project/chat" }));
});
test("execution correlation is distinct per request, host, OAuth connection and conversation", () => {
  const a = { identity: { hostId: crypto.randomUUID() } }, b = { identity: { hostId: crypto.randomUUID() } };
  const req = { hostgateToken: { clientId: "client-a" } }, args = { contextId: "project/chat" }, extra = { _meta: { "openai/session": "opaque-session" } };
  const first = executionContext(a, req, args, extra), second = executionContext(a, req, args, extra);
  assert.notEqual(first.executionId, second.executionId); assert.equal(first.contextKey, second.contextKey);
  assert.notEqual(first.contextKey, executionContext(b, req, args, extra).contextKey);
  assert.notEqual(first.contextKey, executionContext(a, { hostgateToken: { clientId: "client-b" } }, args, extra).contextKey);
  assert.notEqual(first.contextKey, executionContext(a, req, args, { _meta: { "openai/session": "another" } }).contextKey);
  assert(!JSON.stringify(first).includes("opaque-session"));
});
test("each profile has host/endpoint-bound credentials; no overwrite or legacy inheritance", async () => {
  const { home, a, b } = fixture();
  const first = { HOST: "127.0.0.1", PORT: "12345", HOSTGATE_OAUTH_USERNAME: "fixture-a", HOSTGATE_OAUTH_PASSWORD: crypto.randomUUID() };
  const second = { ...first, PORT: "12346", HOSTGATE_OAUTH_USERNAME: "fixture-b", HOSTGATE_OAUTH_PASSWORD: crypto.randomUUID() };
  const receipt = await saveHostConfig(a, first, home); await saveHostConfig(b, second, home);
  assert(!JSON.stringify(receipt).includes(first.HOSTGATE_OAUTH_PASSWORD));
  assert.deepEqual(await readHostConfig(a, home), first); assert.deepEqual(await readHostConfig(b, home), second);
  await assert.rejects(saveHostConfig(a, second, home), /already exist/);
  fs.copyFileSync(hostPaths(a.id, home).credentials, hostPaths(b.id, home).credentials);
  await assert.rejects(readHostConfig(b, home), /another host/);
  assert.deepEqual(await readHostConfig(a, home), first);
});
test("profile task names and directories are separate in a pure plan", () => {
  const sid = "S-1-5-21-123-456-789-1001", commit = "a".repeat(40), first = crypto.randomUUID(), second = crypto.randomUUID();
  const a = taskSpecification(`C:\\profile\\${first}`, commit, sid, first), b = taskSpecification(`C:\\profile\\${second}`, commit, sid, second);
  assert.notEqual(a.name, b.name); assert.notEqual(a.directory, b.directory); assert.notEqual(a.arguments, b.arguments);
});
test("CLI profile editing is explicit; listing/selection do not start anything or expose credentials", () => {
  const { home, a } = fixture();
  const env = { ...shellEnvironment(), HOME: home, USERPROFILE: home };
  const call = args => spawnSync(process.execPath, [path.join(root, "bin", "hostgate.js"), "host", ...args], { env, encoding: "utf8", windowsHide: true, timeout: 10000 });
  assert.equal(call(["list"]).status, 0);
  assert.equal(call(["select", a.id, "--context", "project/chat", "--yes"]).status, 0);
  assert.equal(call(["inspect", "--context", "project/chat"]).status, 0);
  assert.notEqual(call(["remove", a.id]).status, 0);
  assert.notEqual(call(["configure", a.id, "--yes"]).status, 0);
  assert.notEqual(call(["start"]).status, 0);
  assert.equal(fs.existsSync(hostPaths(a.id, home).status), false);
});


test("saved project/chat directories stay separate and never change the host default", () => {
  const { home, a, b } = fixture();
  const one = path.join(home, "one"), two = path.join(home, "two");
  selectHost(a.id, "project/one", home, one); selectHost(a.id, "project/two", home, two);
  assert.equal(selectedHost("project/one", home).cwd, one); assert.equal(selectedHost("project/two", home).cwd, two);
  assert.equal(findHost(a.id, home).cwd, home); assert.equal(findHost(b.id, home).cwd, home);
  removeHost(a.id, home); assert.throws(() => selectedHost("project/one", home));
});


test("registry write failure closes its handle, retains incomplete lock, and preserves registry", t => {
  const { home, a } = fixture(), file = registryPath(home), before = fs.readFileSync(file);
  const write = fs.writeFileSync, close = fs.closeSync; let failedFd = null, closed = false;
  t.mock.method(fs, "writeFileSync", function(fd, ...args) {
    if (typeof fd === "number" && failedFd === null) { failedFd = fd; throw new Error("isolated write failure"); }
    return write.call(this, fd, ...args);
  });
  t.mock.method(fs, "closeSync", function(fd) { if (fd === failedFd) closed = true; return close.call(this, fd); });
  assert.throws(() => renameHost(a.id, "Never applied", home), /isolated write failure/);
  assert(closed); assert.deepEqual(fs.readFileSync(file), before);
  assert(fs.existsSync(path.join(path.dirname(file), "hosts.lock")));
});
