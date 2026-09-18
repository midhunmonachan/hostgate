// Per-request metadata and path resolution, independent of host catalogs or routing.
import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";

const hash = value => crypto.createHash("sha256").update(JSON.stringify(value)).digest("hex");
export function executionContext(instanceId, req, args = {}, extra = {}) {
  const connectionId = hash([instanceId, req.hostgateToken?.clientId || "unknown"]);
  const session = extra._meta?.["openai/session"];
  const conversationId = typeof session === "string" && session.length <= 512 ? hash([connectionId, session]) : null;
  const contextId = args.contextId ?? null;
  return { instanceId, requestId: req.hostgateRequestId || crypto.randomUUID(), executionId: crypto.randomUUID(),
    connectionId, conversationId, contextId, contextKey: hash([connectionId, conversationId, contextId]), startedAt: new Date().toISOString() };
}

export function executionLogPath(home = os.homedir()) {
  return path.join(home, ".local", "share", "hostgate", "executions.jsonl");
}
export function appendExecution(event) {
  const file = executionLogPath();
  fs.mkdirSync(path.dirname(file), { recursive: true, mode: 0o700 });
  fs.appendFileSync(file, JSON.stringify(event) + "\n", { mode: 0o600 });
}
export async function runTool(instanceId, req, name, args, extra, handler, audit = appendExecution) {
  const execution = executionContext(instanceId, req, args, extra);
  const clock = performance.now();
  let result;
  try { result = await handler(args, execution); }
  catch (error) { result = { isError: true, content: [{ type: "text", text: error instanceof Error ? error.message : "Tool execution failed." }] }; }
  const completed = { ...execution, finishedAt: new Date().toISOString(), durationMs: performance.now() - clock };
  const commandFailed = result.structuredContent && Object.hasOwn(result.structuredContent, "exitCode") && result.structuredContent.exitCode !== 0;
  // Telemetry only: exclude commands, paths, raw context/session labels, content,
  // credentials, tokens and exception details. Logging failure never replays a tool.
  try {
    await audit({ version: 1, event: "tool-completed", instanceId, requestId: execution.requestId,
      executionId: execution.executionId, connectionId: execution.connectionId, conversationId: execution.conversationId,
      contextKey: execution.contextKey, tool: name, success: !result.isError && !commandFailed,
      startedAt: completed.startedAt, finishedAt: completed.finishedAt, durationMs: completed.durationMs });
    completed.auditRecorded = true;
  } catch { completed.auditRecorded = false; }
  return { ...result, content: [...(result.content || []), { type: "text", text: `Execution: ${execution.executionId}; request: ${execution.requestId}` }],
    structuredContent: { ...(result.structuredContent || {}), execution: completed } };
}

export function resolveExecutionDirectory(value, home = os.homedir()) {
  if (value === undefined) return home;
  if (typeof value !== "string" || !value || value.includes("\0")) throw new Error("Invalid working directory.");
  const expanded = value === "~" ? home : value.startsWith("~/") || process.platform === "win32" && value.startsWith("~\\")
    ? path.resolve(home, value.slice(2)) : value;
  // Avoid Windows drive-relative paths and dependence on a caller's process cwd.
  if (!path.isAbsolute(expanded) || process.platform === "win32" && !/^(?:[A-Za-z]:[\\/]|\\\\)/.test(expanded)) {
    throw new Error("Use an absolute working directory or a home-relative ~/ path.");
  }
  const cwd = path.normalize(expanded);
  if (!fs.statSync(cwd).isDirectory()) throw new Error("Working directory must exist.");
  return cwd;
}
export function resolveFilePath(requested, cwd, home = os.homedir()) {
  if (typeof requested !== "string" || !requested || requested.includes("\0")) throw new Error("Path is required.");
  if (process.platform === "win32" && /^[A-Za-z]:(?![\\/])/.test(requested)) throw new Error("Use an absolute path, not a drive-relative path.");
  // Validate a supplied cwd even for absolute paths so malformed context fails visibly.
  const directory = resolveExecutionDirectory(cwd, home);
  if (requested === "~") return home;
  if (requested.startsWith("~/") || process.platform === "win32" && requested.startsWith("~\\")) return path.resolve(home, requested.slice(2));
  return path.isAbsolute(requested) ? path.normalize(requested) : path.resolve(directory, requested);
}
