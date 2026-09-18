import { spawn, spawnSync } from "node:child_process";
import crypto from "node:crypto";
import fs from "node:fs";
import http from "node:http";
import { isIP } from "node:net";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";

export const MANAGER_API = 1;
export const sourceDir = path.dirname(fileURLToPath(import.meta.url));
export const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));
export const digest = (bytes) => crypto.createHash("sha256").update(bytes).digest("hex");
export const managedHome = (home = os.homedir()) => path.join(home, ".config", "hostgate", "managed");
export function readJson(file, fallback = null) {
  try { return JSON.parse(fs.readFileSync(file, "utf8").replace(/^\uFEFF/, "")); }
  catch (error) { if (error.code === "ENOENT") return fallback; throw new Error("Managed state is unreadable; no state was replaced."); }
}
export function writeJson(file, value) {
  const temporary = `${file}.${crypto.randomUUID()}.tmp`;
  fs.writeFileSync(temporary, JSON.stringify(value, null, 2) + "\n", { flag: "wx", mode: 0o600 });
  fs.renameSync(temporary, file);
}
export function requireWindows() {
  if (process.platform !== "win32") throw new Error("This manager uses Windows Task Scheduler and current-user DPAPI. Linux systemd/foreground operation is unchanged.");
}
export function windows(action, data = {}, adapter = path.join(sourceDir, "windows-manager.ps1")) {
  requireWindows();
  const env = { ...process.env };
  env.SystemRoot ||= env.WINDIR || "C:\\Windows";
  env.USERPROFILE ||= os.homedir();
  env.APPDATA ||= path.join(os.homedir(), "AppData", "Roaming");
  env.LOCALAPPDATA ||= path.join(os.homedir(), "AppData", "Local");
  env.TEMP ||= path.join(env.LOCALAPPDATA, "Temp");
  const executable = path.win32.join(env.SystemRoot, "System32", "WindowsPowerShell", "v1.0", "powershell.exe");
  const result = spawnSync(executable, ["-NoLogo", "-NoProfile", "-NonInteractive", "-EncodedCommand",
    Buffer.from((action === "capture" ? fs.readFileSync(path.join(path.dirname(adapter), "windows-process.ps1"), "utf8") + "\n" : "") + fs.readFileSync(adapter, "utf8"), "utf16le").toString("base64")], {
    env, input: JSON.stringify({ ...data, action }), encoding: "utf8", windowsHide: true,
    stdio: ["pipe", "pipe", "pipe"], timeout: 30000, maxBuffer: 4 * 1024 * 1024
  });
  if (result.error || result.status !== 0) throw new Error(`Windows ${action} failed. Check account permissions and Task Scheduler; no credentials are shown.`);
  try { return JSON.parse(result.stdout.trim()); } catch { throw new Error(`Windows ${action} returned an invalid response.`); }
}
export function normalizeEnvironment(input) {
  if (!input || typeof input !== "object" || Array.isArray(input)) throw new Error("A saved environment object is required.");
  const result = {};
  const seen = new Set();
  for (const [key, value] of Object.entries(input)) {
    if (!key || key.includes("=") || key.includes("\0") || typeof value !== "string" || value.includes("\0")) throw new Error("Invalid saved environment entry.");
    if (seen.has(key.toUpperCase())) throw new Error("Duplicate case-insensitive environment entries.");
    seen.add(key.toUpperCase());
    if (!/^(NODE_CHANNEL_FD|NODE_CHANNEL_SERIALIZATION_MODE)$/i.test(key)) result[key] = value;
  }
  const get = (key) => Object.entries(result).find(([name]) => name.toUpperCase() === key)?.[1];
  if (!get("HOSTGATE_OAUTH_PASSWORD")) throw new Error("Existing OAuth password is missing. Do not replace a working instance's credentials.");
  const port = Number(get("PORT") || 8787);
  if (!Number.isInteger(port) || port < 1 || port > 65535) throw new Error("Managed operation requires a fixed valid PORT.");
  const host = get("HOST") || "127.0.0.1";
  const address = host.replace(/^\[|\]$/g, "");
  if (!isIP(address) && !/^[A-Za-z0-9.-]+$/.test(address)) throw new Error("Invalid saved HOST binding.");
  return result;
}
export function environmentValue(env, key) {
  return Object.entries(env).find(([name]) => name.toUpperCase() === key.toUpperCase())?.[1];
}
export function savedEnvironment(directory, adapter) {
  const file = path.join(directory, "environment.dpapi");
  const result = windows("unprotect", { ciphertext: fs.readFileSync(file, "utf8").trim() }, adapter);
  return normalizeEnvironment(JSON.parse(result.text));
}
export function healthUrl(env) {
  let host = environmentValue(env, "HOST") || "127.0.0.1";
  if (host === "0.0.0.0") host = "127.0.0.1";
  if (host === "::") host = "::1";
  if (host.includes(":" ) && !host.startsWith("[")) host = `[${host}]`;
  return `http://${host}:${environmentValue(env, "PORT") || 8787}/hostgate/health`;
}
export function health(url, timeout = 3000) {
  return new Promise((resolve) => {
    let finished = false;
    const done = (ok) => { if (!finished) { finished = true; clearTimeout(timer); resolve(ok); } };
    const req = http.get(url, { agent: false, headers: { Accept: "application/json" } }, (res) => {
      let text = "";
      res.setEncoding("utf8");
      res.on("data", (chunk) => { text += chunk; if (text.length > 4096) { done(false); res.destroy(); } });
      res.on("error", () => done(false));
      res.on("end", () => { try { const body = JSON.parse(text); done(res.statusCode === 200 && body.ok === true && body.name === "hostgate"); } catch { done(false); } });
    });
    const timer = setTimeout(() => { done(false); req.destroy(); }, timeout);
    req.on("error", () => done(false));
  });
}
export function alive(pid) {
  if (!Number.isInteger(pid) || pid <= 0) return false;
  try { process.kill(pid, 0); return true; } catch { return false; }
}
export function taskMatches(task, config) {
  return task?.exists && task.enabled && task.executable?.toLowerCase() === config.nodePath.toLowerCase() &&
    task.arguments === `"${config.supervisorPath}" "${config.directory}"` && task.user === config.sid &&
    task.logonType === 3 && task.runLevel === 0 && task.logonTrigger && task.executionTimeLimit === "PT0S" && task.restartCount >= 1;
}
export async function managedStatus(directory = managedHome()) {
  const config = readJson(path.join(directory, "deployment.json"));
  if (!config) return { configured: false, running: false, restartReady: false, autostart: false };
  const state = readJson(path.join(directory, "status.json"), {});
  let env;
  let decryptable = false;
  let task = null;
  try { env = savedEnvironment(directory, config.adapterPath); decryptable = true; } catch {}
  try { task = windows("inspect-task", { name: config.taskName }, config.adapterPath); } catch {}
  const runtimePresent = [config.nodePath, config.supervisorPath, config.childPath, config.adapterPath,
    path.join(config.current.path, "src", "server.js")].every((p) => typeof p === "string" && fs.existsSync(p));
  const recent = Date.now() - Date.parse(state.heartbeat || "") < 15000;
  const running = recent && alive(state.supervisorPid) && alive(state.childPid) && state.phase === "running" &&
    state.commit === config.current.commit && state.releasePath === config.current.path && !!env && await health(healthUrl(env));
  const startMatches = !!state.lastSuccessfulStart && state.environmentHash === digest(fs.readFileSync(path.join(directory, "environment.dpapi")));
  return { configured: true, running: !!running, restartReady: !!(runtimePresent && decryptable && startMatches && state.commit === config.current.commit && state.releasePath === config.current.path && taskMatches(task, config)),
    autostart: !!taskMatches(task, config), decryptable, runtimePresent,
    npmAvailable: !!config.npmCli && fs.existsSync(config.npmCli),
    host: env ? environmentValue(env, "HOST") || "127.0.0.1" : undefined,
    port: env ? Number(environmentValue(env, "PORT") || 8787) : undefined,
    supervisorPid: state.supervisorPid, childPid: running ? state.childPid : null,
    commit: config.current.commit, releasePath: config.current.path, taskName: config.taskName,
    phase: state.phase || "not-started", lastSuccessfulStart: state.lastSuccessfulStart || null,
    logonAfterReboot: "Configured logon recovery is not proof of an actual reboot test." };
}
export function queueRequest(directory, operation, extra = {}) {
  const id = crypto.randomUUID();
  writeJson(path.join(directory, "requests", `${id}.json`), { ...extra, id, operation, requestedAt: new Date().toISOString() });
  return { id, resultPath: path.join(directory, "results", `${id}.json`) };
}
export async function waitRequest(ticket, timeout = 60000) {
  const until = Date.now() + timeout;
  while (Date.now() < until) { const result = readJson(ticket.resultPath); if (result) return result; await sleep(300); }
  throw new Error(`Manager request is still pending. Read service status and its receipt: ${ticket.resultPath}`);
}
export function runCommand(command, args, options = {}) {
  return new Promise((resolve, reject) => {
    const { timeout = 120000, ...rest } = options;
    const child = spawn(command, args, { ...rest, shell: false, windowsHide: true, stdio: ["ignore", "pipe", "pipe"] });
    let stdout = "";
    let stderr = "";
    let timedOut = false;
    const timer = setTimeout(() => { timedOut = true; child.kill(); }, timeout);
    child.stdout.setEncoding("utf8"); child.stderr.setEncoding("utf8");
    child.stdout.on("data", (chunk) => { if (stdout.length < 1048576) stdout += chunk; });
    child.stderr.on("data", (chunk) => { if (stderr.length < 65536) stderr += chunk; });
    child.once("error", () => { clearTimeout(timer); reject(new Error("Required executable is unavailable.")); });
    child.once("close", (code) => { clearTimeout(timer); if (code !== 0 || timedOut) reject(new Error(timedOut ? "Operation exceeded its deadline." : "Command failed; active deployment was not discarded.")); else resolve(stdout); });
  });
}
