import assert from "node:assert/strict";
import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { execFileSync } from "node:child_process";
import { assertIntent, checkUpdate, cleanCheckout, git, githubOrigin, performUpdate, prepareRelease, safeReleaseTree } from "../src/updates.js";
import { readJson, runCommand, writeJson } from "../src/managed-common.js";

function fixture() {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "hostgate-update-test-"));
  const repo = path.join(dir, "source"); fs.mkdirSync(repo);
  const g = (...args) => execFileSync("git", ["-C", repo, ...args], { encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] }).trim();
  g("init", "-b", "main"); g("config", "user.name", "Hostgate isolated test"); g("config", "user.email", "hostgate-test@example.invalid");
  g("remote", "add", "origin", "https://github.com/example/hostgate");
  fs.mkdirSync(path.join(repo, "src"));
  fs.writeFileSync(path.join(repo, "src", "server.js"), "// Isolated release fixture.\n");
  fs.writeFileSync(path.join(repo, "package.json"), JSON.stringify({ name: "hostgate", type: "module", hostgateManagerApi: 1,
    scripts: { check: "node --check src/server.js", test: "node --check src/server.js" } }));
  fs.writeFileSync(path.join(repo, "package-lock.json"), '{"name":"hostgate","lockfileVersion":3,"packages":{}}');
  fs.writeFileSync(path.join(repo, ".gitignore"), "node_modules/\n");
  g("add", "."); g("-c", "commit.gpgsign=false", "commit", "-m", "Initial isolated test release");
  const first = g("rev-parse", "HEAD");
  fs.appendFileSync(path.join(repo, "src", "server.js"), "// Next isolated version.\n");
  g("add", "."); g("-c", "commit.gpgsign=false", "commit", "-m", "Second isolated test release");
  const second = g("rev-parse", "HEAD");
  g("update-ref", "refs/remotes/origin/main", second);
  const manager = path.join(dir, "manager"); fs.mkdirSync(manager); fs.mkdirSync(path.join(manager, "releases"));
  const config = { repoRoot: repo, origin: "https://github.com/example/hostgate", gitPath: "git", nodePath: process.execPath,
    current: { commit: first, path: path.join(manager, "releases", "first") } };
  writeJson(path.join(manager, "deployment.json"), config);
  const npmCli = path.join(dir, "fake-npm.js");
  fs.writeFileSync(npmCli, "if(!process.argv.includes('ci')||!process.argv.includes('--ignore-scripts'))process.exit(9);\n");
  return { dir, repo, manager, config, first, second, g, npmCli };
}

test("update origin validation excludes secrets, alternate hosts and transport injection", () => {
  for (const value of ["https://github.com/user/hostgate", "https://github.com/user/hostgate.git", "git@github.com:user/hostgate.git"]) assert.equal(githubOrigin(value), value);
  for (const value of ["https://user:secret@github.com/user/hostgate", "http://github.com/user/hostgate", "https://elsewhere.invalid/repo", "file:///repo", "https://github.com/user/repo?token=secret", "-upload-pack=bad"]) {
    assert.throws(() => githubOrigin(value), (error) => !error.message.includes("secret"));
  }
});

test("update intent requires explicit consent and a full pinned commit", () => {
  assert.throws(() => assertIntent({ expected: "a".repeat(40) }));
  assert.throws(() => assertIntent({ yes: true, expected: "abc123" }));
  assertIntent({ yes: true, expected: "a".repeat(40) });
});

test("clean-tree check detects tracked and untracked changes without altering them", () => {
  const f = fixture(); assert(cleanCheckout(f.repo));
  fs.writeFileSync(path.join(f.repo, "unrelated.txt"), "retain exactly");
  assert(!cleanCheckout(f.repo));
  assert.equal(fs.readFileSync(path.join(f.repo, "unrelated.txt"), "utf8"), "retain exactly");
  assert.equal(f.g("rev-parse", "HEAD"), f.second);
});

test("unsafe tracked state is rejected before release creation", () => {
  const f = fixture();
  fs.writeFileSync(path.join(f.repo, ".env"), "only-a-test-fixture");
  f.g("add", ".env"); f.g("-c", "commit.gpgsign=false", "commit", "-m", "Unsafe fixture only");
  assert.throws(() => safeReleaseTree(f.repo, f.g("rev-parse", "HEAD")), /sensitive or generated/);
});

test("missing npm refuses preparation without touching deployment or source", async () => {
  const f = fixture(); const before = fs.readFileSync(path.join(f.manager, "deployment.json"));
  await assert.rejects(prepareRelease({ repoRoot: f.repo, commit: f.second, directory: f.manager, npmCli: null }), /npm is unavailable/);
  assert.deepEqual(fs.readFileSync(path.join(f.manager, "deployment.json")), before);
  assert.deepEqual(fs.readdirSync(path.join(f.manager, "releases")), []);
  assert(cleanCheckout(f.repo));
});

test("real Git release staging installs and validates only in a new retained directory", { timeout: 30000 }, async () => {
  const f = fixture(); const calls = [];
  const release = await prepareRelease({ repoRoot: f.repo, commit: f.second, directory: f.manager, npmCli: f.npmCli }, {
    run: async (command, args, options) => { calls.push({ command, args }); return runCommand(command, args, options); }
  });
  assert.equal(git(release.path, ["rev-parse", "HEAD"]), f.second);
  assert(calls.some((c) => c.args.includes("ci") && c.args.includes("--ignore-scripts")));
  assert(calls.some((c) => c.args.join(" ") === "--run test"));
  assert(cleanCheckout(f.repo));
  assert.equal(readJson(path.join(f.manager, "deployment.json")).current.commit, f.first);
});

test("failed candidate checks retain prior deployment and source", async () => {
  const f = fixture(); let invoked = 0;
  await assert.rejects(prepareRelease({ repoRoot: f.repo, commit: f.second, directory: f.manager, npmCli: f.npmCli }, {
    run: async (command, args, options) => { if (args.join(" ") === "--run check") throw new Error("Fixture check failure"); invoked++; return runCommand(command, args, options); }
  }), /Fixture check failure/);
  assert(invoked >= 3); assert(cleanCheckout(f.repo));
  assert.equal(readJson(path.join(f.manager, "deployment.json")).current.commit, f.first);
});

function info(f, changes = {}) {
  return { origin: f.config.origin, cleanWorkingTree: true, checkoutCommit: f.second, remoteCommit: f.second, ...changes };
}

test("dirty checkout and changed remote are rejected before fetch or preparation", async () => {
  for (const changes of [{ cleanWorkingTree: false }, { remoteCommit: "b".repeat(40) }]) {
    const f = fixture(); let mutations = 0;
    await assert.rejects(performUpdate({ directory: f.manager, expected: f.second, yes: true }, {
      check: async () => info(f, changes), run: async () => { mutations++; }, prepare: async () => { mutations++; }
    }));
    assert.equal(mutations, 0);
    assert.equal(readJson(path.join(f.manager, "deployment.json")).current.commit, f.first);
  }
});

test("no-change apply does not reinstall dependencies or restart", async () => {
  const f = fixture(); f.config.current.commit = f.second; writeJson(path.join(f.manager, "deployment.json"), f.config);
  const result = await performUpdate({ directory: f.manager, expected: f.second, yes: true }, {
    check: async () => info(f), run: async () => assert.fail("No fetch expected"), queue: () => assert.fail("No restart expected")
  });
  assert.equal(result.noChange, true);
});

test("validated update activation reports rollback and never writes environment or OAuth state", async () => {
  const f = fixture();
  fs.writeFileSync(path.join(f.manager, "environment.dpapi"), crypto.randomUUID());
  fs.writeFileSync(path.join(f.manager, "oauth-state-test.json"), "retain unchanged");
  const before = fs.readFileSync(path.join(f.manager, "environment.dpapi"));
  let queued = 0;
  const result = await performUpdate({ directory: f.manager, expected: f.second, yes: true }, {
    check: async () => info(f), run: async () => "",
    prepare: async () => ({ commit: f.second, path: path.join(f.manager, "releases", "candidate") }),
    queue: (_directory, op, payload) => { queued++; assert.equal(op, "activate"); assert.equal(payload.expectedCommit, f.first); return {}; },
    wait: async () => ({ success: false, rolledBack: true, commit: f.first })
  });
  assert.equal(queued, 1); assert.equal(result.rolledBack, true); assert.equal(result.sourceCheckoutUnchanged, true);
  assert.deepEqual(fs.readFileSync(path.join(f.manager, "environment.dpapi")), before);
  assert.equal(fs.readFileSync(path.join(f.manager, "oauth-state-test.json"), "utf8"), "retain unchanged");
  assert(cleanCheckout(f.repo));
});

test("source mutation during preparation prevents activation", async () => {
  const f = fixture();
  await assert.rejects(performUpdate({ directory: f.manager, expected: f.second, yes: true }, {
    check: async () => info(f), run: async () => "",
    prepare: async () => { fs.writeFileSync(path.join(f.repo, "concurrent-work.txt"), "other work"); return { commit: f.second, path: "unused" }; },
    queue: () => assert.fail("Do not activate concurrent changes")
  }), /changed during preparation/);
  assert.equal(fs.readFileSync(path.join(f.repo, "concurrent-work.txt"), "utf8"), "other work");
});


test("retired profile deployment refuses updates before any prepare, fetch or activation", async () => {
  const f = fixture(); const state = { ...f.config, profileId: crypto.randomUUID() };
  writeJson(path.join(f.manager, "deployment.json"), state);
  const before = fs.readFileSync(path.join(f.manager, "deployment.json"));
  await assert.rejects(performUpdate({ yes: true, expected: f.second, directory: f.manager }, {
    check: () => assert.fail("No network/checkout check should be reached"),
    prepare: () => assert.fail("No release preparation should be reached"),
    queue: () => assert.fail("No activation should be queued")
  }), /explicit migration/);
  assert.deepEqual(fs.readFileSync(path.join(f.manager, "deployment.json")), before);
});
