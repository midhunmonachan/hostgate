import { spawn, spawnSync } from "node:child_process";
import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { alive, managedHome, managedStatus, queueRequest, readJson, requireWindows, runCommand, sleep, sourceDir, waitRequest, writeJson } from "./managed-common.js";
import { shellEnvironment } from "./shell.js";

export function githubOrigin(value) {
  if (/^git@github\.com:[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+(?:\.git)?$/.test(value)) return value;
  let url;
  try { url = new URL(value); } catch { throw new Error("origin must be an explicit GitHub repository URL."); }
  if (url.protocol !== "https:" || url.hostname !== "github.com" || url.username || url.password || url.port || url.search || url.hash ||
      !/^\/[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+(?:\.git)?$/.test(url.pathname)) throw new Error("origin must be a credential-free GitHub HTTPS or git@github.com repository URL.");
  return value;
}
export function git(repo, args, gitPath = "git") {
  const result = spawnSync(gitPath, ["-C", repo, ...args], { encoding: "utf8", windowsHide: true, timeout: 30000, maxBuffer: 1048576 });
  if (result.error || result.status !== 0) throw new Error("Git verification failed; no checkout or deployment was replaced.");
  return result.stdout.trim();
}
export function cleanCheckout(repo, gitPath = "git") {
  const dirty = git(repo, ["status", "--porcelain=v1", "--untracked-files=all"], gitPath);
  return dirty === "";
}
export function assertIntent(options) {
  if (options.yes !== true || !/^[a-f0-9]{40}$/.test(options.expected || "")) throw new Error("Applying an update requires --yes --expect <full commit from update check>.");
}
export async function checkUpdate(repoRoot, config = null, gitPath = "git") {
  if (git(repoRoot, ["branch", "--show-current"], gitPath) !== "main") throw new Error("Update source must be on main. No branch was switched.");
  const origin = githubOrigin(git(repoRoot, ["remote", "get-url", "origin"], gitPath));
  if (config && origin !== config.origin) throw new Error("origin differs from the installed deployment's trusted remote. Review the remote before reinstalling.");
  const output = await runCommand(gitPath, ["-C", repoRoot, "ls-remote", "--exit-code", "origin", "refs/heads/main"], { timeout: 30000 });
  const remoteCommit = output.match(/^([a-f0-9]{40})\s+refs\/heads\/main\s*$/)?.[1];
  if (!remoteCommit) throw new Error("Could not resolve exactly origin/main.");
  const checkoutCommit = git(repoRoot, ["rev-parse", "HEAD"], gitPath);
  return { origin, checkoutCommit, deployedCommit: config?.current.commit || null, remoteCommit,
    updateAvailable: (config?.current.commit || checkoutCommit) !== remoteCommit,
    cleanWorkingTree: cleanCheckout(repoRoot, gitPath),
    note: "Apply refuses ALL tracked and untracked changes. Ignored local files are never copied into a release." };
}
export function findNpm(nodePath, directory) {
  const candidates = [path.join(directory, "tools", "npm", "package", "bin", "npm-cli.js"),
    path.join(path.dirname(nodePath), "node_modules", "npm", "bin", "npm-cli.js"),
    path.join(path.dirname(process.execPath), "node_modules", "npm", "bin", "npm-cli.js")];
  if (process.platform === "win32") {
    const found = spawnSync("where.exe", ["npm.cmd"], { encoding: "utf8", windowsHide: true });
    if (found.status === 0) for (const filename of found.stdout.trim().split(/\r?\n/)) candidates.push(path.join(path.dirname(filename), "node_modules", "npm", "bin", "npm-cli.js"));
  } else {
    for (const entry of (process.env.PATH || "").split(path.delimiter)) {
      try { const executable = fs.realpathSync(path.join(entry, "npm")); candidates.push(executable); } catch {}
    }
  }
  return candidates.find((file) => fs.existsSync(file)) || null;
}
export function safeReleaseTree(repo, commit, gitPath = "git") {
  const paths = git(repo, ["ls-tree", "-r", "--name-only", commit], gitPath).split("\n");
  if (!paths.includes("src/server.js") || !paths.includes("package-lock.json") || !paths.includes("package.json")) throw new Error("Candidate is missing required Hostgate source or npm lockfile.");
  if (paths.some((file) => /(^|\/)(node_modules|\.config|\.local|oauth-state\.json)(\/|$)/.test(file) || /(^|\/)\.env($|\.)/.test(file) && file !== ".env.example")) {
    throw new Error("Candidate tracks sensitive or generated paths; refusing to deploy.");
  }
}
export async function prepareRelease({ repoRoot, commit, directory, nodePath = process.execPath, npmCli, gitPath = "git" }, io = {}) {
  if (!/^[a-f0-9]{40}$/.test(commit)) throw new Error("An exact commit is required.");
  if (!npmCli || !fs.existsSync(npmCli)) throw new Error("npm is unavailable. Install npm or provide its npm-cli.js; the active server and dependencies are unchanged.");
  safeReleaseTree(repoRoot, commit, gitPath);
  const releasePath = path.join(directory, "releases", `${commit}-${crypto.randomUUID().slice(0, 8)}`);
  const run = io.run || runCommand;
  await run(gitPath, ["clone", "--no-hardlinks", "--no-checkout", "--", repoRoot, releasePath], { timeout: 120000 });
  await run(gitPath, ["-C", releasePath, "-c", "core.hooksPath=", "checkout", "--detach", commit], { timeout: 60000 });
  const manifest = JSON.parse(fs.readFileSync(path.join(releasePath, "package.json"), "utf8"));
  if (manifest.name !== "hostgate" || manifest.hostgateManagerApi !== 1 || !manifest.scripts?.check || !manifest.scripts?.test) throw new Error("Candidate does not declare compatible manager API and checks/tests. Release retained without activation.");
  const buildHome = path.join(directory, "builds", crypto.randomUUID());
  fs.mkdirSync(buildHome, { recursive: true, mode: 0o700 });
  const env = { ...shellEnvironment(), HOME: buildHome, USERPROFILE: buildHome, npm_config_cache: path.join(buildHome, "npm-cache"),
    npm_config_userconfig: path.join(buildHome, "empty-npmrc"), npm_config_audit: "false", npm_config_fund: "false" };
  // A candidate and its tests run with NO production OAuth environment. They are trusted code
  // from the explicitly approved GitHub commit, not sandboxed against the OS account.
  await run(nodePath, [npmCli, "ci", "--ignore-scripts", "--no-audit", "--no-fund"], { cwd: releasePath, env, timeout: 180000 });
  await run(nodePath, ["--run", "check"], { cwd: releasePath, env, timeout: 60000 });
  await run(nodePath, ["--run", "test"], { cwd: releasePath, env, timeout: 180000 });
  if (git(releasePath, ["rev-parse", "HEAD"], gitPath) !== commit || !cleanCheckout(releasePath, gitPath)) throw new Error("Candidate files changed during validation; no activation performed.");
  return { path: releasePath, commit, validatedAt: new Date().toISOString() };
}
export async function performUpdate(job, io = {}) {
  assertIntent(job);
  const directory = job.directory;
  const configPath = path.join(directory, "deployment.json");
  const before = readJson(configPath);
  if (!before) throw new Error("Install Windows managed startup before applying updates.");
  const inspect = io.check || checkUpdate;
  const info = await inspect(before.repoRoot, before, before.gitPath);
  if (!info.cleanWorkingTree) throw new Error("Source working tree is not clean, including untracked files. Nothing was stashed, deleted, reset, or deployed.");
  if (info.remoteCommit !== job.expected) throw new Error("origin/main changed after confirmation. Run update check again and confirm the new full commit.");
  if (before.current.commit === job.expected) return { success: true, noChange: true, commit: job.expected };
  const run = io.run || runCommand;
  await run(before.gitPath, ["-C", before.repoRoot, "fetch", "--no-tags", "origin", "refs/heads/main:refs/remotes/origin/main"], { timeout: 60000 });
  if (git(before.repoRoot, ["rev-parse", "refs/remotes/origin/main"], before.gitPath) !== job.expected) throw new Error("Remote moved during fetch; explicit confirmation must be renewed.");
  git(before.repoRoot, ["merge-base", "--is-ancestor", before.current.commit, job.expected], before.gitPath);
  git(before.repoRoot, ["merge-base", "--is-ancestor", info.checkoutCommit, job.expected], before.gitPath);
  const release = await (io.prepare || prepareRelease)({ repoRoot: before.repoRoot, commit: job.expected, directory,
    nodePath: before.nodePath, npmCli: before.npmCli || findNpm(before.nodePath, directory), gitPath: before.gitPath });
  if (!cleanCheckout(before.repoRoot, before.gitPath) || git(before.repoRoot, ["rev-parse", "HEAD"], before.gitPath) !== info.checkoutCommit ||
      readJson(configPath).current.commit !== before.current.commit) throw new Error("Source or deployment changed during preparation; candidate retained but not activated.");
  const ticket = (io.queue || queueRequest)(directory, "activate", { release, expectedCommit: before.current.commit });
  const receipt = await (io.wait || waitRequest)(ticket, 90000);
  return { ...receipt, releasePath: release.path, sourceCheckoutUnchanged: true, previousCommit: before.current.commit };
}
export async function updateCli(args, repoRoot) {
  const [operation = "check", ...flags] = args;
  const directory = managedHome();
  const config = readJson(path.join(directory, "deployment.json"));
  if (operation === "check") {
    if (flags.length) throw new Error("Usage: hostgate update check");
    console.log(JSON.stringify(await checkUpdate(config?.repoRoot || repoRoot, config, config?.gitPath || "git"), null, 2));
    return;
  }
  if (operation === "status") {
    if (flags.length !== 1 || !/^[a-f0-9-]{36}$/.test(flags[0])) throw new Error("Usage: hostgate update status <job ID>");
    console.log(JSON.stringify(readJson(path.join(directory, "updates", `${flags[0]}.result.json`), { pending: true }), null, 2)); return;
  }
  requireWindows();
  if (!config) throw new Error("Install managed Windows startup first.");
  if (operation === "recover-lock") {
    if (flags.join(" ") !== "--yes") throw new Error("Lock recovery requires --yes.");
    const lock = path.join(directory, "updates", "apply.lock");
    const owner = readJson(lock);
    if (!owner) { console.log("No update lock is present."); return; }
    if (alive(owner.pid)) throw new Error("Update owner process is still present; refusing lock recovery.");
    fs.renameSync(lock, path.join(directory, "updates", `recovered-${crypto.randomUUID()}.json`));
    console.log("Stale lock retained as a recovery record; active deployment unchanged."); return;
  }
  if (operation === "rollback") {
    if (flags.join(" ") !== "--yes" || !config.previous) throw new Error("Rollback requires --yes and a retained previous release.");
    const result = queueRequest(directory, "activate", { release: config.previous, expectedCommit: config.current.commit });
    console.log(JSON.stringify({ queued: true, ...result })); return;
  }
  if (operation !== "apply" || flags.length !== 3 || flags[0] !== "--yes" || flags[1] !== "--expect") throw new Error("Usage: hostgate update apply --yes --expect <full commit from update check>");
  const job = { yes: true, expected: flags[2], directory };
  assertIntent(job);
  // Rejection here is synchronous and read-only; do not queue a known-dirty source.
  if (!cleanCheckout(config.repoRoot, config.gitPath)) throw new Error("Update refused: source has tracked or untracked changes. Your files were not modified.");
  const status = await managedStatus(directory);
  if (!status.running || !status.restartReady) throw new Error("Managed server is not running/restart-ready; repair startup before updating.");
  const id = crypto.randomUUID();
  const filename = path.join(directory, "updates", `${id}.json`);
  writeJson(filename, { ...job, id, phase: "requested" });
  const child = spawn(config.nodePath, [path.join(sourceDir, "updates.js"), "--worker", filename], {
    detached: true, windowsHide: true, stdio: "ignore", cwd: directory
  });
  child.on("error", () => {}); child.unref();
  console.log(JSON.stringify({ queued: true, id, resultPath: filename.replace(/\.json$/, ".result.json") }));
}
if (process.argv[2] === "--worker" && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const filename = path.resolve(process.argv[3]);
  const resultFile = filename.replace(/\.json$/, ".result.json");
  const job = readJson(filename);
  // An exclusive local lock prevents concurrent installers; a crash leaves an explicit recovery marker.
  const lock = path.join(job.directory, "updates", "apply.lock");
  let locked = false;
  try {
    fs.writeFileSync(lock, JSON.stringify({ pid: process.pid, id: job.id }), { flag: "wx", mode: 0o600 }); locked = true;
    writeJson(resultFile, { id: job.id, pending: true, phase: "validating", startedAt: new Date().toISOString() });
    const result = await performUpdate(job);
    writeJson(resultFile, { id: job.id, ...result, pending: false, completedAt: new Date().toISOString() });
  } catch (error) {
    writeJson(resultFile, { id: job.id, success: false, pending: false, error: error.message,
      recovery: "Inspect service status. Old releases/environment are retained. No Git reset or source checkout change was performed." });
  } finally {
    // Release only our own lock by retaining it under this job's audit name, never deleting unrelated files.
    if (locked) fs.renameSync(lock, path.join(job.directory, "updates", `${job.id}.lock-completed.json`));
  }
}
