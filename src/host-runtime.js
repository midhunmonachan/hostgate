import crypto from "node:crypto";
import fs from "node:fs";
import net from "node:net";
import os from "node:os";
import path from "node:path";
import { activeHostId, hostPaths } from "./host-paths.js";
import { localHost, readHostConfig, atomicJson, noStorageLinks, contextName } from "./host-profiles.js";

const hash = (value) => crypto.createHash("sha256").update(value).digest("hex");
export async function loadHostRuntime() {
  const id = activeHostId();
  if (!id) return null; // Legacy startup never reads or selects a profile.
  const profile = localHost(id), values = await readHostConfig(profile), paths = hostPaths(id);
  const staged = process.env.HOSTGATE_PROFILE_STAGING === "1" && typeof process.send === "function";
  if (!fs.statSync(profile.cwd).isDirectory()) throw new Error("Profile working directory is unavailable.");
  noStorageLinks(paths.data);
  if (!staged) {
    if (process.platform === "win32") { const { windows } = await import("./managed-common.js"); windows("secure", { directory: paths.data }); }
    else fs.mkdirSync(paths.data, { recursive: true, mode: 0o700 });
  }
  const identity = Object.freeze({ hostId: id, hostName: profile.name, endpoint: profile.endpoint });
  const instanceId = crypto.randomUUID();
  return { profile, paths, identity, instanceId, staged,
    values: staged ? { ...values, HOST: "127.0.0.1", PORT: "0" } : values,
    assertCurrent() {
      const current = localHost(id);
      if (JSON.stringify(current) !== JSON.stringify(profile)) throw new Error("Host profile changed or was retired. Explicitly inspect and restart this host; no routing fallback.");
    },
    audit(event) {
      if (!staged) fs.appendFileSync(paths.logs, JSON.stringify({ version: 1, hostId: id, instanceId, ...event }) + "\n", { mode: 0o600 });
    }
  };
}
export function requireTarget(runtime, args) {
  if (!runtime) {
    if (args.target !== undefined || args.contextId !== undefined) throw new Error("This legacy server is not a named host. Refusing a targeted request; do not drop the target to bypass this check.");
    return;
  }
  runtime.assertCurrent();
  const t = args.target;
  if (!t || t.hostId !== runtime.identity.hostId || t.hostName !== runtime.identity.hostName || t.endpoint !== runtime.identity.endpoint) throw new Error("Host target mismatch. No tool action was executed; use the explicitly named connection without substituting another host.");
  contextName(args.contextId);
}
export function executionContext(runtime, req, args, extra = {}) {
  const host = runtime?.identity || null;
  const connectionId = hash(JSON.stringify([host?.hostId || "legacy", req.hostgateToken?.clientId || "unknown"]));
  const session = extra._meta?.["openai/session"];
  const conversationId = typeof session === "string" && session.length <= 512 ? hash(JSON.stringify([connectionId, session])) : null;
  const contextId = args.contextId || null;
  return { host, requestId: req.hostgateRequestId || crypto.randomUUID(), executionId: crypto.randomUUID(), connectionId, conversationId,
    contextId, contextKey: hash(JSON.stringify([host?.hostId || "legacy", connectionId, conversationId, contextId])), startedAt: new Date().toISOString() };
}
export async function runHostTool(runtime, req, name, args, extra, handler) {
  const execution = executionContext(runtime, req, args, extra);
  const clock = performance.now();
  const finish = (result) => {
    const completed = { ...execution, finishedAt: new Date().toISOString(), durationMs: performance.now() - clock };
    // Metadata only: never commands, paths, content, tokens, or raw exception text.
    try { runtime?.audit({ event: "tool-completed", requestId: execution.requestId, executionId: execution.executionId,
      connectionId: execution.connectionId, conversationId: execution.conversationId, contextKey: execution.contextKey, tool: name,
      success: !result.isError, durationMs: completed.durationMs }); } catch { completed.auditRecorded = false; }
    if (!runtime) return result; // Preserve legacy model-visible result shapes.
    return { ...result, content: [{ type: "text", text: `Host: ${runtime.identity.hostName} [${runtime.identity.hostId}]; context: ${execution.contextId}; execution: ${execution.executionId}` }, ...(result.content || [])],
      structuredContent: { ...(result.structuredContent || {}), host: runtime.identity, execution: completed } };
  };
  try { requireTarget(runtime, args); return finish(await handler(args, execution)); }
  catch (error) { return finish({ isError: true, content: [{ type: "text", text: error instanceof Error ? error.message : "Host execution failed." }] }); }
}
export function resolveExecutionDirectory(runtime, value) {
  if (value === undefined) return runtime?.profile.cwd || os.homedir();
  if (typeof value !== "string" || !value || value.includes("\0")) throw new Error("Invalid working directory.");
  const cwd = value === "~" ? os.homedir() : /^~[\\/]/.test(value) ? path.resolve(os.homedir(), value.slice(2)) : path.resolve(os.homedir(), value);
  if (!fs.statSync(cwd).isDirectory()) throw new Error("Working directory must exist.");
  return cwd;
}
export function profileFilePath(runtime, requested, cwd) {
  if (!requested || requested.includes("\0")) throw new Error("Path is required.");
  if (requested === "~") return os.homedir();
  if (requested.startsWith("~/") || process.platform === "win32" && requested.startsWith("~\\")) return path.resolve(os.homedir(), requested.slice(2));
  if (path.isAbsolute(requested)) return path.normalize(requested);
  if (runtime && cwd === undefined) throw new Error("A relative file path needs an explicit per-call cwd on a named host.");
  return path.resolve(resolveExecutionDirectory(runtime, cwd), requested);
}
export async function withHostLease(runtime, launch) {
  if (!runtime || runtime.staged) return launch();
  const key = hash(runtime.paths.data);
  // An exclusive OS listener prevents concurrent servers sharing one OAuth state file.
  // No control messages or commands are accepted here; this is not an MCP proxy.
  const address = process.platform === "win32" ? `\\\\.\\pipe\\hostgate-profile-${key}` : `\0hostgate-profile-${key}`;
  const lease = net.createServer(socket => socket.destroy());
  await new Promise((resolve, reject) => { lease.once("error", () => reject(new Error("This host profile already has a runtime, or its lease is unavailable."))); lease.listen(address, resolve); });
  try {
    const listener = launch();
    listener.once("listening", () => {
      atomicJson(runtime.paths.status, { version: 1, ...runtime.identity, instanceId: runtime.instanceId, pid: process.pid,
        cwd: runtime.profile.cwd, address: listener.address(), startedAt: new Date().toISOString() });
    });
    listener.once("close", () => lease.close());
    return listener;
  } catch (error) { lease.close(); throw error; }
}
