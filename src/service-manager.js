import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { digest, environmentValue, managedHome, managedStatus, normalizeEnvironment, queueRequest, readJson, requireWindows,
  savedEnvironment, sourceDir, taskMatches, windows, writeJson } from "./managed-common.js";
import { findNpm, git, githubOrigin, prepareRelease } from "./updates.js";

export function parseServiceArgs(args) {
  const [operation = "status", ...rest] = args;
  const options = { operation, yes: false, importStdin: false, adoptPid: null, adoptFrom: null, npmCli: null };
  const seen = new Set();
  for (let i = 0; i < rest.length; i++) {
    if (seen.has(rest[i])) throw new Error("Duplicate service option.");
    seen.add(rest[i]);
    if (rest[i] === "--yes") options.yes = true;
    else if (rest[i] === "--import-stdin") options.importStdin = true;
    else if (rest[i] === "--adopt-pid" && /^[1-9][0-9]*$/.test(rest[i + 1] || "")) options.adoptPid = Number(rest[++i]);
    else if (rest[i] === "--adopt-from" && rest[i + 1]) options.adoptFrom = path.resolve(rest[++i]);
    else if (rest[i] === "--npm-cli" && rest[i + 1]) options.npmCli = path.resolve(rest[++i]);
    else throw new Error("Usage: hostgate service install --yes [--import-stdin --adopt-pid PID] [--npm-cli PATH], start, restart --yes, status, or result ID.");
  }
  if (!["install", "start", "restart", "repair", "status"].includes(operation)) throw new Error("Unsupported service command.");
  if (["install", "restart", "repair"].includes(operation) && !options.yes) throw new Error("This service operation requires explicit --yes.");
  if (operation !== "install" && (options.importStdin || options.adoptPid || options.adoptFrom || options.npmCli)) throw new Error("Import and adoption options apply only to installation.");
  if (options.adoptFrom && !options.adoptPid) throw new Error("--adopt-from requires a verified adoption PID.");
  if (options.adoptPid && !options.importStdin) throw new Error("Adoption requires --import-stdin containing the verified original environment.");
  return options;
}
export async function installManaged(repoRoot, environment, options = {}, io = {}) {
  requireWindows();
  if (!options.yes) throw new Error("Installation requires explicit --yes.");
  const directory = managedHome();
  const adapter = io.windows || windows;
  const existing = readJson(path.join(directory, "deployment.json"));
  if (existing) throw new Error("A managed installation already exists. Use service start/restart/status; credentials were not overwritten.");
  const env = normalizeEnvironment(environment);
  const home = environmentValue(env, "USERPROFILE") || environmentValue(env, "HOME") || os.homedir();
  if (path.resolve(home).toLowerCase() !== path.resolve(os.homedir()).toLowerCase()) throw new Error("The imported environment belongs to a different home directory.");
  if (environmentValue(env, "HOME") && path.resolve(environmentValue(env, "HOME")).toLowerCase() !== path.resolve(os.homedir()).toLowerCase()) throw new Error("HOME must remain this Windows account's home directory.");
  if (git(repoRoot, ["branch", "--show-current"]) !== "main" || git(repoRoot, ["diff", "HEAD", "--name-only"])) throw new Error("Install only committed main code. Tracked edits must be reviewed and committed first.");
  const commit = git(repoRoot, ["rev-parse", "HEAD"]);
  const origin = githubOrigin(git(repoRoot, ["remote", "get-url", "origin"]));
  const secured = adapter("secure", { directory });
  if (secured.elevated) throw new Error("Run installation from an ordinary, non-elevated terminal; do not silently change an elevated server token.");
  for (const name of ["runtime", "releases", "builds", "requests", "results", "updates"]) fs.mkdirSync(path.join(directory, name), { recursive: true, mode: 0o700 });
  const taskName = `Hostgate-${digest(secured.sid).slice(0, 12)}`;
  if (adapter("inspect-task", { name: taskName }).exists) throw new Error("The target task name is occupied. No existing task was overwritten.");
  let bootstrap = null;
  if (options.adoptPid) {
    const adoptRoot = options.adoptFrom || repoRoot;
    if (githubOrigin(git(adoptRoot, ["remote", "get-url", "origin"])) !== origin) throw new Error("Adoption source does not match the trusted GitHub repository.");
    bootstrap = adapter("process", { pid: options.adoptPid });
    if (!bootstrap.exists || bootstrap.sid !== secured.sid || !bootstrap.executable?.toLowerCase().endsWith("\\node.exe") ||
        !(bootstrap.commandLine.includes(path.join(adoptRoot, "src", "server.js")) || bootstrap.commandLine.endsWith("src/server.js"))) {
      throw new Error("The adoption PID is not this account's identified Hostgate Node process.");
    }
  }
  const runtime = path.join(directory, "runtime", commit);
  fs.mkdirSync(runtime, { recursive: false, mode: 0o700 });
  const nodePath = path.join(runtime, "node.exe");
  fs.copyFileSync(process.execPath, nodePath, fs.constants.COPYFILE_EXCL);
  if (digest(fs.readFileSync(nodePath)) !== digest(fs.readFileSync(process.execPath))) throw new Error("Bundled runtime verification failed.");
  for (const name of ["managed-common.js", "supervisor.js", "managed-child.js", "windows-manager.ps1"]) fs.copyFileSync(path.join(sourceDir, name), path.join(runtime, name), fs.constants.COPYFILE_EXCL);
  fs.writeFileSync(path.join(runtime, "package.json"), '{"type":"module"}\n', { flag: "wx", mode: 0o600 });
  const npmCli = options.npmCli || findNpm(process.execPath, directory);
  const release = await (io.prepare || prepareRelease)({ repoRoot, commit, directory, nodePath, npmCli });
  const protectedEnv = adapter("protect", { text: JSON.stringify(env) });
  const encryptedPath = path.join(directory, "environment.dpapi");
  fs.writeFileSync(encryptedPath, protectedEnv.ciphertext + "\n", { flag: "wx", mode: 0o600 });
  const decoded = savedEnvironment(directory);
  if (JSON.stringify(decoded) !== JSON.stringify(env)) throw new Error("Saved environment verification failed. Original server was not stopped.");
  const config = { schemaVersion: 1, managerApi: 1, directory, homeDir: os.homedir(), repoRoot, origin, sid: secured.sid,
    taskName, nodePath, npmCli, gitPath: gitExecutable(), supervisorPath: path.join(runtime, "supervisor.js"),
    childPath: path.join(runtime, "managed-child.js"), adapterPath: path.join(runtime, "windows-manager.ps1"),
    current: release, previous: null, bootstrap, installedAt: new Date().toISOString() };
  writeJson(path.join(directory, "deployment.json"), config);
  // Stable fresh-terminal entry point uses a private runtime, not PATH or a temporary preload.
  const wrapper = `import fs from 'node:fs'; import {pathToFileURL} from 'node:url';\nconst c=JSON.parse(fs.readFileSync(${JSON.stringify(path.join(directory, "deployment.json"))},'utf8'));\nprocess.argv=[process.execPath,c.current.path+'/bin/hostgate.js',...process.argv.slice(2)];\nawait import(pathToFileURL(process.argv[1]).href);\n`;
  fs.writeFileSync(path.join(directory, "control.mjs"), wrapper, { flag: "wx", mode: 0o600 });
  fs.writeFileSync(path.join(directory, "hostgate.cmd"), `@echo off\r\n"${nodePath}" "${path.join(directory, "control.mjs")}" %*\r\n`, { flag: "wx", mode: 0o600 });
  adapter("install-task", { name: taskName, executable: nodePath, arguments: `"${config.supervisorPath}" "${directory}"`, directory }, config.adapterPath);
  if (!taskMatches(adapter("inspect-task", { name: taskName }, config.adapterPath), config)) throw new Error("Scheduled task verification failed. Nothing was stopped; inspect service status.");
  adapter("start-task", { name: taskName }, config.adapterPath);
  return { installed: true, taskName, commit, directory, environmentVerified: true,
    note: "Supervisor validates the candidate before adopting the original PID. Inspect service status for activation; reboot recovery occurs at this user's logon." };
}
function gitExecutable() {
  const result = windowsShellWhere("git.exe");
  return result || "git";
}
import { spawnSync } from "node:child_process";
function windowsShellWhere(name) {
  const result = spawnSync("where.exe", [name], { encoding: "utf8", windowsHide: true });
  return result.status === 0 ? result.stdout.trim().split(/\r?\n/)[0] : null;
}
export async function serviceCli(args, repoRoot, environmentProvider) {
  if (args[0] === "result") {
    if (args.length !== 2 || !/^[a-f0-9-]{36}$/.test(args[1])) throw new Error("Usage: hostgate service result <request ID>");
    console.log(JSON.stringify(readJson(path.join(managedHome(), "results", `${args[1]}.json`), { pending: true }), null, 2)); return;
  }
  const options = parseServiceArgs(args);
  requireWindows();
  const directory = managedHome();
  if (options.operation === "status") { console.log(JSON.stringify(await managedStatus(directory), null, 2)); return; }
  if (options.operation === "install") {
    let environment;
    if (options.importStdin) {
      let text = "";
      for await (const chunk of process.stdin) { text += chunk; if (text.length > 4194304) throw new Error("Environment input too large."); }
      try { environment = JSON.parse(text); } catch { throw new Error("Invalid environment JSON; no values were printed."); }
    } else environment = environmentProvider();
    console.log(JSON.stringify(await installManaged(repoRoot, environment, options), null, 2)); return;
  }
  const config = readJson(path.join(directory, "deployment.json"));
  if (!config) throw new Error("Managed startup is not configured.");
  let task = windows("inspect-task", { name: config.taskName }, config.adapterPath);
  if (options.operation === "repair" && !task.exists) {
    windows("install-task", { name: config.taskName, executable: config.nodePath, arguments: `"${config.supervisorPath}" "${directory}"`, directory }, config.adapterPath);
    task = windows("inspect-task", { name: config.taskName }, config.adapterPath);
  }
  if (!taskMatches(task, config)) throw new Error("Task definition does not match the installed launcher; no unrelated task will be started.");
  if (["start", "repair"].includes(options.operation)) {
    windows("start-task", { name: config.taskName }, config.adapterPath);
    console.log("Managed startup requested. Inspect hostgate service status."); return;
  }
  const current = await managedStatus(directory);
  if (!current.running) throw new Error("Managed instance is not running. Use service start; no unidentified process was stopped.");
  console.log(JSON.stringify({ queued: true, ...queueRequest(directory, "restart", { expectedCommit: config.current.commit }) }, null, 2));
}
