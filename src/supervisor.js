import { fork } from "node:child_process";
import crypto from "node:crypto";
import fs from "node:fs";
import net from "node:net";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { alive, digest, health, healthUrl, readJson, savedEnvironment, sleep, windows, writeJson } from "./managed-common.js";

export function stageEnvironment(environment) {
  return { ...Object.fromEntries(Object.entries(environment).filter(([key]) => !["HOST", "PORT"].includes(key.toUpperCase()))), HOST: "127.0.0.1", PORT: "0", ...(environment.HOSTGATE_PROFILE_ID ? { HOSTGATE_PROFILE_STAGING: "1" } : {}) };
}
export async function startChild(config, release, environment, { staged = false } = {}) {
  const child = fork(config.childPath, [release.path], {
    execPath: config.nodePath, execArgv: [], cwd: config.workingDirectory || config.repoRoot, env: staged ? stageEnvironment(environment) : environment,
    windowsHide: true, stdio: ["ignore", "pipe", "pipe", "ipc"]
  });
  // Never persist raw stdout/stderr: arbitrary future code might print environment values.
  child.stdout.resume(); child.stderr.resume();
  const readiness = new Promise((resolve, reject) => {
    const timer = setTimeout(() => reject(new Error("Server startup did not become ready.")), 15000);
    child.once("error", () => { clearTimeout(timer); reject(new Error("Server process could not be started.")); });
    child.once("exit", () => { clearTimeout(timer); reject(new Error("Server exited before becoming ready.")); });
    child.on("message", (message) => {
      if (message?.type === "ready" && message.pid === child.pid) { clearTimeout(timer); resolve(message); }
      if (message?.type === "failed") { clearTimeout(timer); reject(new Error("Server imports failed.")); }
    });
  });
  try {
    const ready = await readiness;
    const url = staged ? `http://127.0.0.1:${ready.port}/hostgate/health` : healthUrl(environment);
    if (!await health(url, 3000, config.profileId ? { hostId: config.profileId, endpoint: config.profileEndpoint } : null)) throw new Error("Server health verification failed.");
    if (child.exitCode !== null || child.signalCode !== null) throw new Error("Server exited during verification.");
    return child;
  } catch (error) { await stopChild(child); throw error; }
}
export async function stopChild(child) {
  if (!child || child.exitCode !== null || child.signalCode !== null) return;
  const closed = new Promise((resolve) => child.once("exit", resolve));
  if (child.connected) child.send({ operation: "shutdown" }, () => {});
  const timer = setTimeout(() => child.kill(), 11000);
  await closed;
  clearTimeout(timer);
}

export async function supervise(directory) {
  const configPath = path.join(directory, "deployment.json");
  let config = readJson(configPath);
  if (!config || config.schemaVersion !== 1 || config.managerApi !== 1) throw new Error("Unsupported manager configuration.");
  const pipe = process.platform === "win32" ? `\\\\.\\pipe\\hostgate-supervisor-${digest(directory.toLowerCase()).slice(0, 24)}` : path.join(directory, "supervisor.sock");
  const lock = net.createServer((socket) => socket.destroy()); // Exclusivity only; no network management API.
  const acquired = await new Promise((resolve) => { lock.once("error", () => resolve(false)); lock.listen(pipe, () => resolve(true)); });
  if (!acquired) return;
  const environment = savedEnvironment(directory, config.adapterPath);
  if (config.profileId && environment.HOSTGATE_PROFILE_ID !== config.profileId) throw new Error("Managed profile environment mismatch.");
  const environmentHash = digest(fs.readFileSync(path.join(directory, "environment.dpapi")));
  let currentChild = null;
  const state = { schemaVersion: 1, supervisorPid: process.pid, instance: crypto.randomUUID(), phase: "starting", environmentHash };
  const save = () => writeJson(path.join(directory, "status.json"), { ...state, childPid: currentChild?.pid || null,
    commit: config.current.commit, releasePath: config.current.path, heartbeat: new Date().toISOString() });
  const event = (name, details = {}) => fs.appendFileSync(path.join(directory, "events.jsonl"), JSON.stringify({ at: new Date().toISOString(), event: name, ...details }) + "\n", { mode: 0o600 });
  const heartbeat = setInterval(save, 3000);
  save();
  async function preflight(release) {
    const candidate = await startChild(config, release, environment, { staged: true });
    await stopChild(candidate);
  }
  async function launch(release) {
    currentChild = await startChild(config, release, environment);
    state.phase = "running";
    state.lastSuccessfulStart = new Date().toISOString();
    save();
  }
  async function transition(release) {
    const previous = config.current;
    state.phase = "validating"; save();
    await preflight(release); // Old instance stays live until this succeeds.
    event("candidate-ready", { commit: release.commit });
    state.phase = "restarting"; save();
    await stopChild(currentChild);
    currentChild = null;
    try {
      await launch(release);
      config = { ...config, current: release, previous: release.path !== previous.path ? previous : config.previous, bootstrap: null };
      writeJson(configPath, config);
      save();
      event("activated", { commit: release.commit, childPid: currentChild.pid });
      return { success: true, commit: release.commit, childPid: currentChild.pid, rolledBack: false };
    } catch {
      await stopChild(currentChild); currentChild = null;
      config = { ...config, current: previous };
      writeJson(configPath, config);
      try {
        await launch(previous);
        event("rollback-restored", { commit: previous.commit });
        return { success: false, rolledBack: true, commit: previous.commit, error: "Candidate failed activation; previous runtime restored." };
      } catch {
        state.phase = "recovery-needed"; save();
        return { success: false, rolledBack: false, commit: previous.commit, error: "Candidate and previous runtime failed health checks. Saved environment and releases retained." };
      }
    }
  }
  try {
    await preflight(config.current);
    if (config.bootstrap) {
      event("adoption-preflight-passed", { previousPid: config.bootstrap.pid });
      // Allow the installation command to return through the old MCP connection.
      await sleep(3000);
      windows("stop-exact", config.bootstrap, config.adapterPath);
    }
    await launch(config.current);
    config = { ...config, bootstrap: null };
    writeJson(configPath, config);
    event("started", { commit: config.current.commit, childPid: currentChild.pid });
    let failures = 0;
    while (true) {
      const pending = fs.readdirSync(path.join(directory, "requests")).filter((name) => /^[a-f0-9-]{36}\.json$/.test(name) && !fs.existsSync(path.join(directory, "results", name))).sort();
      for (const name of pending) {
        const job = readJson(path.join(directory, "requests", name));
        if (!job || Date.now() - Date.parse(job.requestedAt) < 2000) continue; // Let the initiating MCP reply finish.
        let result;
        try {
          if (job.expectedCommit && job.expectedCommit !== config.current.commit) throw new Error("Deployment changed after this request was prepared.");
          if (job.operation === "restart") result = await transition(config.current);
          else if (job.operation === "activate") {
            const candidate = path.resolve(job.release.path);
            const releases = path.resolve(directory, "releases") + path.sep;
            if (!candidate.startsWith(releases) || !/^[a-f0-9]{40}$/.test(job.release.commit) || !fs.existsSync(path.join(candidate, "src", "server.js"))) throw new Error("Invalid managed release.");
            if (config.profileId && readJson(path.join(candidate, "package.json"))?.hostgateHostProfilesApi !== 1) throw new Error("Release lacks named-host routing support.");
            result = await transition(job.release);
          } else throw new Error("Unsupported manager request.");
        } catch (error) {
          state.phase = currentChild && alive(currentChild.pid) ? "running" : "recovery-needed";
          save();
          result = { success: false, rolledBack: false, error: error.message, commit: config.current.commit };
        }
        writeJson(path.join(directory, "results", name), { id: job.id, ...result, completedAt: new Date().toISOString() });
      }
      if (!currentChild || currentChild.exitCode !== null || currentChild.signalCode !== null) {
        state.phase = "recovering"; save();
        event("child-exited", { attempt: ++failures });
        await sleep(Math.min(60000, 1000 * 2 ** Math.min(failures - 1, 6)));
        try { await launch(config.current); event("recovered", { childPid: currentChild.pid }); } catch {
          // Publishing status/events can fail after startChild succeeded. Retain ownership
          // until that exact child is stopped; otherwise it can strand the listener.
          await stopChild(currentChild); currentChild = null;
        }
      } else if (Date.now() - Date.parse(state.lastSuccessfulStart) > 60000) failures = 0;
      await sleep(500);
    }
  } finally {
    clearInterval(heartbeat);
    await stopChild(currentChild);
    lock.close();
  }
}
if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  supervise(path.resolve(process.argv[2])).catch(() => {
    // The task retries failure; raw exceptions could contain private paths/values.
    process.stderr.write("Hostgate supervisor stopped. Inspect protected manager status and lifecycle events.\n");
    process.exit(1);
  });
}
