import assert from "node:assert/strict";
import fs from "node:fs";
import test from "node:test";
import { approvalToken, collectInstallPlan, formatInstallPlan, localWindowsPath, parsePlanArgs, PLAN_WARNING, servicePlanCli, taskSpecification } from "../src/service-plan.js";
import { createPlanProbes, metadataOnly, plannerProcessEnvironment, supportsNode } from "../src/plan-probes.js";

const commit = "a".repeat(40);
const ctx = Object.freeze({ platform: "win32", repoRoot: "C:\\source", home: "C:\\Users\\owner", nodePath: "C:\\Node\\node.exe", nodeVersion: "24.19.0" });
const options = () => parsePlanArgs(["--npm-cli", "C:\\npm\\bin\\npm-cli.js"]);
function fixture(overrides = {}) {
  const called = [];
  const probes = {
    repository: () => ({ commit, branch: "main", origin: "https://github.com/example/hostgate", clean: true, requiredFiles: true, compatible: true, statusFingerprint: "clean", remoteHeadChecked: false }),
    presence: (file) => file.endsWith("npm-cli.js") ? "file" : "absent",
    runtime: () => ({ state: "file", sha256: "runtime-hash" }),
    npm: () => ({ found: true, valid: true, version: "12.0.2", runtimeCompatible: true, cliSha256: "cli-hash", executed: false }),
    windowsInspect: () => ({ sid: "S-1-5-21-1001", elevated: false, dpapiAvailable: true, acl: { readable: true, createChildIndicated: true, descriptorSha256: "acl-hash", effectiveAccessTested: false } }),
    validateTask: () => ({ xmlValid: true, commandMatches: true, existingTask: false, validationFlag: 1, taskRegistered: false }), ...overrides
  };
  return { called, probes: new Proxy(probes, { get(target, key) {
    assert(key in target, `No effect adapter is available: ${String(key)}`);
    return (...args) => { called.push(key); return target[key](...args); };
  } }) };
}
const get = (report, id) => report.plan.checks.find((item) => item.id === id);

test("planner performs only observations and separates pass from unverified activation", () => {
  const { probes, called } = fixture();
  const result = collectInstallPlan(options(), ctx, probes);
  assert.equal(result.exitCode, 0);
  assert.equal(get(result, "environment-source").status, "unverified");
  assert.equal(get(result, "acl").status, "unverified");
  assert.deepEqual(result.plan.effectsPerformed, []);
  assert.equal(result.plan.environmentSource.valuesRead, false);
  assert.equal(result.plan.environmentSource.stdinConsumed, false);
  assert.equal(result.plan.task.registered, false);
  assert.equal(result.plan.task.commandExecuted, false);
  assert.equal(result.plan.warning, PLAN_WARNING);
  assert.match(result.tokenPurpose, /No installer consumes it/);
  assert(called.every((name) => ["repository", "presence", "runtime", "npm", "windowsInspect", "validateTask"].includes(name)));
});

test("token is stable across JSON formatting, object key order, and repeated inspection", () => {
  const a = collectInstallPlan(options(), ctx, fixture().probes);
  const b = collectInstallPlan({ ...options(), json: true }, ctx, fixture().probes);
  assert.equal(a.approvalToken, b.approvalToken);
  assert.match(a.approvalToken, /^hostgate-plan-v1:[a-f0-9]{64}$/);
  assert.equal(approvalToken({ a: 1, b: { x: 2, z: 3 } }), approvalToken({ b: { z: 3, x: 2 }, a: 1 }));
  assert(!JSON.stringify(a).includes("createdAt"));
  assert.match(formatInstallPlan(a), /Shell and write remain potentially destructive/);
});

test("token binds source, runtime, npm, account, ACL, destination and environment-source observations", () => {
  const initial = collectInstallPlan(options(), ctx, fixture().probes).approvalToken;
  const variants = [
    [{}, fixture({ repository: () => ({ commit: "b".repeat(40), branch: "main", origin: "https://github.com/example/hostgate", clean: true, requiredFiles: true, compatible: true }) })],
    [{}, fixture({ runtime: () => ({ state: "file", sha256: "different-runtime" }) })],
    [{}, fixture({ npm: () => ({ valid: true, runtimeCompatible: true, version: "11.0.0" }) })],
    [{}, fixture({ windowsInspect: () => ({ sid: "S-1-5-21-1002", elevated: false, dpapiAvailable: true, acl: { readable: true, createChildIndicated: true } }) })],
    [{}, fixture({ windowsInspect: () => ({ sid: "S-1-5-21-1001", elevated: false, dpapiAvailable: true, acl: { readable: true, createChildIndicated: true, descriptorSha256: "changed" } }) })],
    [{ home: "C:\\Users\\other" }, fixture()]
  ];
  for (const [context, f] of variants) assert.notEqual(collectInstallPlan(options(), { ...ctx, ...context }, f.probes).approvalToken, initial);
  assert.notEqual(collectInstallPlan({ ...options(), environmentSource: "launcher" }, ctx, fixture().probes).approvalToken, initial);
});

test("no live environment enumeration or secret value influences the plan", () => {
  const original = process.env;
  let a;
  try {
    process.env = new Proxy({}, { get() { throw new Error("Environment value read"); }, ownKeys() { throw new Error("Environment enumerated"); } });
    a = collectInstallPlan(options(), { ...ctx, secret: "not-a-real-secret" }, fixture().probes);
  } finally { process.env = original; }
  const b = collectInstallPlan(options(), ctx, fixture().probes);
  assert.equal(a.approvalToken, b.approvalToken);
  assert(!JSON.stringify(a).includes("not-a-real-secret"));
});

test("saved-file availability uses presence only and preserves source precedence", () => {
  const calls = [];
  const { probes } = fixture({ presence: (file) => { calls.push(file); return file.endsWith(".env") || file.endsWith("npm-cli.js") ? "file" : "absent"; } });
  const result = collectInstallPlan({ ...options(), environmentSource: "saved-file" }, ctx, probes);
  assert.equal(result.plan.environmentSource.availability, "user-file");
  assert.equal(result.plan.environmentSource.credentialValidity, "not-verified");
  assert.equal(get(result, "environment-source").status, "unverified");
  assert(calls.some((p) => p.endsWith(".env")));
  assert(!calls.some((p) => p.endsWith("oauth-state.json")));
});

for (const state of ["directory", "file", "linked", "inaccessible", "invalid-ancestor"]) {
  test(`existing/unsafe destination (${state}) blocks installation planning without opening state`, () => {
    const { probes } = fixture({ presence: (file) => file.endsWith("npm-cli.js") ? "file" : file.endsWith("managed") ? state : "absent" });
    const report = collectInstallPlan(options(), ctx, probes);
    assert.equal(get(report, "destination").status, "blocked");
    assert.equal(report.exitCode, 1);
    assert.deepEqual(report.plan.effectsPerformed, []);
  });
}

for (const [id, override] of [
  ["repository", { repository: () => { throw new Error("secret error content"); } }],
  ["runtime", { runtime: () => ({ state: "absent" }) }],
  ["npm", { npm: () => ({ valid: true, runtimeCompatible: null }) }],
  ["account", { windowsInspect: () => ({ sid: "S-1-5-21-1001", elevated: true, acl: {} }) }],
  ["acl", { windowsInspect: () => ({ sid: "S-1-5-21-1001", elevated: false, dpapiAvailable: true, acl: { readable: false } }) }],
  ["task", { validateTask: () => ({ xmlValid: true, commandMatches: true, existingTask: true }) }],
  ["task", { validateTask: () => { throw new Error("secret error content"); } }]
]) test(`failed ${id} check cannot trigger a fallback or leak raw errors`, () => {
  const report = collectInstallPlan(options(), ctx, fixture(override).probes);
  assert.equal(get(report, id).status, "blocked");
  assert.equal(report.exitCode, 1);
  assert(!JSON.stringify(report).includes("secret error content"));
});

test("wrong commit, dirty source, missing metadata and missing saved source are explicit blockers", () => {
  const report = collectInstallPlan({ ...options(), expectedCommit: "b".repeat(40), environmentSource: "saved-file" }, ctx,
    fixture({ repository: () => ({ commit, branch: "feature", clean: false, requiredFiles: false, compatible: false, origin: null }) }).probes);
  for (const id of ["commit", "repository", "origin", "environment-source"]) assert.equal(get(report, id).status, "blocked");
});

test("non-Windows planning returns an explicit limitation before any probes", () => {
  const { probes, called } = fixture();
  const report = collectInstallPlan(options(), { ...ctx, platform: "linux" }, probes);
  assert.equal(report.exitCode, 1);
  assert.deepEqual(called, []);
  assert.match(get(report, "platform").message, /Linux startup is unchanged/);
});

test("parser rejects mutations, token redemption, secret input and unsafe paths without echo", () => {
  for (const args of [["--yes"], ["--import-stdin"], ["--adopt-pid", "123"], ["--apply"], ["--approval-token", "secret"],
    ["--json", "--json"], ["--expect", "abc"], ["--npm-cli", "C:\\secret.env"], ["--environment-source", "secret"], ["secret"]]) {
    assert.throws(() => parsePlanArgs(args), (error) => !error.message.includes("secret"));
  }
  for (const value of ["relative", "\\\\server\\share", "C:\\unsafe\npath", "C:\\%SECRET%", "C:\\file:stream", "C:\\NUL", "C:\\path.", 'C:\\quoted"path']) assert.throws(() => localWindowsPath(value));
  assert.equal(parsePlanArgs(["--expect", commit]).expectedCommit, commit);
  assert.equal(localWindowsPath("C:/Users/owner/space here"), "C:\\Users\\owner\\space here");
});

test("help and invalid options do not load probes or attempt installation", async (t) => {
  const out = [];
  t.mock.method(console, "log", (value) => out.push(value));
  t.mock.method(console, "error", () => {});
  assert.equal(await servicePlanCli(["--help"], "not-a-repository"), 0);
  assert.match(out[0], /not a release build/);
  assert.equal(await servicePlanCli(["--import-stdin"], "not-a-repository"), 2);
});

test("task XML quotes paths, uses exact current-user command, and contains no execution at planning time", () => {
  const task = taskSpecification("C:\\Users\\O'Neil & Co\\managed", commit, "S-1-5-21-1001");
  assert(task.xml.includes("O&apos;Neil &amp; Co"));
  assert.equal(task.arguments, `"${task.supervisor}" "${task.directory}"`);
  assert.match(task.xml, /<LogonType>InteractiveToken<\/LogonType>/);
  assert.match(task.xml, /<RunLevel>LeastPrivilege<\/RunLevel>/);
  assert.equal((task.xml.match(/<Exec>/g) || []).length, 1);
  assert.equal((task.xml.match(/<LogonTrigger>/g) || []).length, 1);
  assert.throws(() => taskSpecification("C:\\safe", commit, 'S-1-<injection>'));
});

test("npm engine checks are static, conservative and never execute npm", () => {
  assert.equal(supportsNode("^22.22.2 || ^24.15.0 || >=26.0.0", "24.19.0"), true);
  assert.equal(supportsNode("^22.22.2 || ^24.15.0 || >=26.0.0", "22.16.0"), false);
  assert.equal(supportsNode(">=22.0.0 <25.0.0", "24.19.0"), true);
  assert.equal(supportsNode("^0.2.1", "0.3.0"), false);
  assert.equal(supportsNode("latest", "24.19.0"), null);
  assert.equal(supportsNode("22.x", "24.19.0"), null);
});

test("metadata probes never read file contents; links and inaccessible paths fail closed", (t) => {
  t.mock.method(fs, "readFileSync", () => assert.fail("Contents must not be opened"));
  const directory = { isDirectory: () => true, isSymbolicLink: () => false, isFile: () => false };
  t.mock.method(fs, "lstatSync", (filename) => {
    if (filename.endsWith("environment.dpapi")) return { ...directory, isDirectory: () => false, isFile: () => true };
    if (filename.includes("linked")) return { ...directory, isSymbolicLink: () => true };
    if (filename.includes("denied")) throw Object.assign(new Error("private"), { code: "EACCES" });
    return directory;
  });
  assert.equal(metadataOnly("C:\\existing\\environment.dpapi"), "file");
  assert.equal(metadataOnly("C:\\linked\\.env"), "linked");
  assert.equal(metadataOnly("C:\\denied\\.env"), "inaccessible");
});

test("Git probes use read-only commands and refuse before status reads tracked private files", (t) => {
  t.mock.method(fs, "lstatSync", () => ({ isDirectory: () => true, isSymbolicLink: () => false }));
  const calls = [];
  const probes = createPlanProbes(ctx, options(), { spawn: (cmd, args, settings) => {
    calls.push(args);
    assert(args.includes("--no-optional-locks"));
    assert(args.includes("core.fsmonitor=false"));
    assert.equal(settings.env.GIT_CONFIG_GLOBAL, "NUL");
    assert(!Object.hasOwn(settings.env, "HOSTGATE_OAUTH_PASSWORD"));
    const command = args[args.indexOf("-C") + 2];
    const output = { "rev-parse": commit, "ls-tree": "package.json\0.env\0", "ls-files": ".env\0", remote: "https://user:secret@github.com/example/hostgate", show: '{"name":"hostgate","hostgateManagerApi":1}', branch: "main", config: "" };
    assert(Object.hasOwn(output, command), "Only permitted metadata reads run");
    return { status: 0, stdout: output[command] };
  } });
  const result = probes.repository(ctx.repoRoot);
  assert.equal(result.clean, false);
  assert.equal(result.origin, null);
  assert(!JSON.stringify(result).includes("secret"));
  assert(!calls.some((args) => args.includes("status")));
});

test("planner has no mutation-capable imports or execution-policy override", () => {
  const plan = fs.readFileSync(new URL("../src/service-plan.js", import.meta.url), "utf8");
  const probes = fs.readFileSync(new URL("../src/plan-probes.js", import.meta.url), "utf8");
  const adapter = fs.readFileSync(new URL("../src/windows-plan.wsf", import.meta.url), "utf8");
  for (const source of [plan, probes]) {
    const text = source.replace(/^\s*\/\/.*$/gm, "");
    assert(!/from ["']\.\/(?:service-manager|managed-common|supervisor|updates|doctor)/.test(text));
    assert(!/fs\.(?:write|mkdir|rename|unlink|rm|copy|chmod|append)/.test(text));
    assert(!/process\.env\s*(?:\[|\.|\)|,)|\.\.\.process\.env/.test(text));
  }
  assert.equal((adapter.match(/\.RegisterTask\(/g) || []).length, 1);
  assert.match(adapter, /\.RegisterTask\(name, taskXml, 1, sid, null, 3\)/);
  assert(!/RegisterTaskDefinition|SetSecurityDescriptor|CreateFolder|CreateTextFile|OpenTextFile|CopyFile|DeleteFile|\.Run\(|\.Exec\(|GetEnvironmentVariable|\.Environment/.test(adapter));
  assert(!/ExecutionPolicy|EncodedCommand/.test(probes));
  assert.equal(plannerProcessEnvironment(ctx.home).LOCALAPPDATA, "C:\\Users\\owner\\AppData\\Local");
  assert.equal(plannerProcessEnvironment(ctx.home).HOSTGATE_OAUTH_PASSWORD, undefined);
  assert(!probes.includes("powershell.exe"));
});


test("configured external Git filters are refused without running status or filter commands", (t) => {
  t.mock.method(fs, "lstatSync", () => ({ isDirectory: () => true, isSymbolicLink: () => false }));
  const calls = [];
  const probes = createPlanProbes(ctx, options(), { spawn: (_command, args) => {
    const operation = args[args.indexOf("-C") + 2]; calls.push(operation);
    const values = { "rev-parse": commit, "ls-tree": "package.json", "ls-files": "package.json", config: "filter.example.process", remote: "https://github.com/example/hostgate", show: '{"name":"hostgate","hostgateManagerApi":1}', branch: "main" };
    assert(Object.hasOwn(values, operation));
    return { status: 0, stdout: values[operation] };
  } });
  const result = probes.repository(ctx.repoRoot);
  assert.equal(result.externalFiltersConfigured, true);
  assert.equal(result.clean, false);
  assert(!calls.includes("status"));
});

test("npm path inspection cannot be redirected to an environment file", () => {
  const probes = createPlanProbes(ctx, options(), { spawn: () => assert.fail("No executable should run") });
  assert.throws(() => probes.npm("C:\\private\\.env", ctx.nodeVersion));
  assert.throws(() => probes.runtime("C:\\private\\environment.dpapi"));
});
