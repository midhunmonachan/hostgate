import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { pathToFileURL } from "node:url";
import { addHost, findHost, localHost, profilePublic, readHosts, readHostConfig, saveHostConfig, renameHost, removeHost, selectHost, selectedHost, routingCard, hostCwd } from "./host-profiles.js";
import { hostPaths } from "./host-paths.js";
import { shellEnvironment } from "./shell.js";

const HELP = `Hostgate named hosts (no remote proxy and no implicit execution default)
  host list
  host add NAME --local --endpoint HTTPS_MCP_URL --cwd ABSOLUTE_PATH --yes
  host add NAME --remote --id TARGET_UUID --platform win32|linux --endpoint HTTPS_MCP_URL --cwd ABSOLUTE_PATH --yes
  host rename NAME_OR_ID NEW_NAME --yes
  host select NAME_OR_ID --context PROJECT/CHAT [--cwd ABSOLUTE_PATH] --yes
  host inspect NAME_OR_ID
  host inspect --context PROJECT/CHAT
  host route NAME_OR_ID --context PROJECT/CHAT [--cwd ABSOLUTE_PATH]
  host remove NAME_OR_ID --yes          Retire catalog entry; retain state and credentials
  host configure NAME_OR_ID --import-stdin --yes
  host start NAME_OR_ID                 Start a local named-host foreground runtime
  host status NAME_OR_ID
  host doctor NAME_OR_ID
  host logs NAME_OR_ID
  host service NAME_OR_ID plan|prepare|status|install|start|restart|result ...
  host update NAME_OR_ID check|apply|status|rollback ...
Selections are per-context routing cards only. Every operation still names its host.
Configuration JSON is read only by configure --import-stdin; never paste credentials into a chat.
Shell/write remain unrestricted and potentially destructive. A host profile is not a sandbox.`;
function flags(args, allowed) {
  const result = {};
  for (let i = 0; i < args.length; i++) {
    const flag = args[i];
    if (!Object.hasOwn(allowed, flag) || Object.hasOwn(result, flag)) throw new Error("Unknown or duplicate host option. Use host help.");
    if (allowed[flag] === "boolean") result[flag] = true;
    else { if (!args[i + 1] || args[i + 1].startsWith("--")) throw new Error("Missing host option value."); result[flag] = args[++i]; }
  }
  return result;
}
function consent(value) { if (value !== true) throw new Error("This profile change requires explicit --yes."); }
const emit = value => console.log(JSON.stringify(value, null, 2));
export async function hostStatus(p) {
  const profile = profilePublic(p), result = { host: { hostId: p.id, hostName: p.name, endpoint: p.endpoint }, configured: profile.credentialsPresent,
    running: false, managedConfigured: profile.managedConfigured, restartReady: false, remoteContacted: false };
  if (p.kind !== "local") return { ...result, note: "Remote runtime status must be obtained from this host's authenticated status tool. The catalog never sends another host's credentials." };
  localHost(p.id);
  try {
    const values = await readHostConfig(p);
    const authority = values.HOST === "::1" ? "[::1]" : values.HOST;
    const response = await fetch(`http://${authority}:${values.PORT}/hostgate/health`, { redirect: "error", signal: AbortSignal.timeout(3000) });
    if (Number(response.headers.get("content-length")) > 4096) throw new Error();
    const text = await response.text(); if (text.length > 4096) throw new Error();
    const health = JSON.parse(text), identity = health.host;
    const state = JSON.parse(fs.readFileSync(hostPaths(p.id).status, "utf8"));
    result.running = response.ok && identity?.hostId === p.id && identity.hostName === p.name && identity.endpoint === p.endpoint && health.instanceId === state.instanceId && state.hostId === p.id;
    if (result.running) { result.pid = state.pid; result.instanceId = state.instanceId; result.cwd = p.cwd; }
  } catch { result.note = "This host's configuration or identity-matched health could not be verified. No fallback was contacted."; }
  if (profile.managedConfigured) {
    const { managedStatus } = await import("./managed-common.js");
    const managed = await managedStatus(hostPaths(p.id).managed);
    result.restartReady = managed.restartReady && managed.profileId === p.id;
    result.autostart = managed.autostart;
  }
  return result;
}
export async function hostCli(args, repoRoot) {
  const [operation = "help", selector, ...rest] = args;
  if (["help", "--help", "-h"].includes(operation)) { console.log(HELP); return; }
  if (operation === "list") {
    if (selector) throw new Error("host list takes no arguments.");
    const r = readHosts(); emit({ hosts: r.profiles.map(p => profilePublic(p)), selections: r.selections, executionDefault: null }); return;
  }
  if (operation === "add") {
    const f = flags(rest, { "--local": "boolean", "--remote": "boolean", "--yes": "boolean", "--id": "value", "--platform": "value", "--endpoint": "value", "--cwd": "value" });
    consent(f["--yes"]); if (!!f["--local"] === !!f["--remote"]) throw new Error("Choose exactly one of --local or --remote.");
    emit(profilePublic(addHost({ name: selector, kind: f["--local"] ? "local" : "remote", id: f["--id"], platform: f["--platform"], endpoint: f["--endpoint"], cwd: f["--cwd"] }))); return;
  }
  if (operation === "inspect" && selector === "--context") {
    if (rest.length !== 1) throw new Error("Use host inspect --context PROJECT/CHAT."); emit(routingCard(selectedHost(rest[0]), rest[0])); return;
  }
  const p = findHost(selector);
  if (operation === "inspect") { if (rest.length) throw new Error("Unexpected inspect arguments."); emit(profilePublic(p)); return; }
  if (operation === "select" || operation === "route") {
    const f = flags(rest, { "--context": "value", "--cwd": "value", ...(operation === "select" ? { "--yes": "boolean" } : {}) });
    if (operation === "select") { consent(f["--yes"]); selectHost(p.id, f["--context"], os.homedir(), f["--cwd"] || null); }
    emit(routingCard(f["--cwd"] ? { ...p, cwd: hostCwd(f["--cwd"], p.platform) } : p, f["--context"])); return;
  }
  if (operation === "rename") { if (rest.length !== 2 || rest[1] !== "--yes") throw new Error("Use host rename NAME_OR_ID NEW_NAME --yes."); emit(profilePublic(renameHost(p.id, rest[0]))); return; }
  if (operation === "remove") { const f = flags(rest, { "--yes": "boolean" }); consent(f["--yes"]); emit(removeHost(p.id)); return; }
  if (operation === "status") { if (rest.length) throw new Error("Unexpected status arguments."); emit(await hostStatus(p)); return; }
  localHost(p.id); // Remote catalog entries can NEVER invoke local execution/lifecycle commands.
  if (operation === "configure") {
    const f = flags(rest, { "--yes": "boolean", "--import-stdin": "boolean" }); consent(f["--yes"]);
    if (!f["--import-stdin"]) throw new Error("Configuration requires explicit --import-stdin.");
    let text = ""; for await (const chunk of process.stdin) { text += chunk; if (text.length > 65536) throw new Error("Profile configuration input too large."); }
    let values; try { values = JSON.parse(text); } catch { throw new Error("Invalid profile configuration JSON; no values were printed."); }
    emit(await saveHostConfig(p, values)); return;
  }
  if (operation === "logs") {
    if (rest.length) throw new Error("host logs returns a bounded snapshot, not raw shell output.");
    const file = hostPaths(p.id).logs;
    if (!fs.existsSync(file)) { emit({ hostId: p.id, events: [] }); return; }
    const fd = fs.openSync(file, "r"); let text;
    try { const size = fs.fstatSync(fd).size, start = Math.max(0, size - 65536), buffer = Buffer.alloc(size - start); fs.readSync(fd, buffer, 0, buffer.length, start); text = buffer.toString("utf8"); if (start) text = text.slice(text.indexOf("\n") + 1); } finally { fs.closeSync(fd); }
    const events = text.trim().split(/\r?\n/).filter(Boolean).slice(-100).map(line => {
      const e = JSON.parse(line); if (e.hostId !== p.id) throw new Error("Log host identity mismatch.");
      return { hostId: p.id, instanceId: e.instanceId, event: e.event, requestId: e.requestId, executionId: e.executionId, connectionId: e.connectionId, conversationId: e.conversationId, contextKey: e.contextKey, tool: e.tool, success: e.success, durationMs: e.durationMs };
    }); emit({ hostId: p.id, events }); return;
  }
  if (operation === "doctor") {
    if (rest.length) throw new Error("Use host doctor NAME_OR_ID.");
    const { collectDoctor, formatDoctor } = await import("./doctor.js");
    const values = await readHostConfig(p);
    const { managedStatus } = await import("./managed-common.js");
    const managed = process.platform === "win32" ? await managedStatus(hostPaths(p.id).managed) : null;
    const report = await collectDoctor({ projectRoot: repoRoot, env: shellEnvironment(), profile: p, publicUrl: p.endpoint, managed,
      readConfig: () => ({ source: "user", values }) });
    console.log(formatDoctor(report)); process.exitCode = report.exitCode; return;
  }
  if (operation === "service" && ["plan", "prepare"].includes(rest[0])) {
    const { servicePlanCli } = await import("./service-plan.js");
    process.exitCode = await servicePlanCli(rest.slice(1), repoRoot, p); return;
  }
  // This CLI invocation pins one identity. Selections are never consulted, and
  // no request handler changes process.env or process.cwd to switch projects.
  process.env.HOSTGATE_PROFILE_ID = p.id;
  if (operation === "start") {
    if (rest.length) throw new Error("host start takes one explicit profile only.");
    process.chdir(p.cwd);
    await import(pathToFileURL(path.join(repoRoot, "src", "server.js")).href); return;
  }
  if (operation === "service") {
    if (rest.includes("--import-stdin") || rest.includes("--adopt-pid") || rest.includes("--adopt-from")) throw new Error("Profile installation uses only its own configured credentials. Legacy PID adoption/migration is not automatic.");
    const { serviceCli } = await import("./service-manager.js");
    // Read secret values only for the explicitly approved local installation.
    const environment = rest[0] === "install" && rest.includes("--yes") ? { ...shellEnvironment(), ...await readHostConfig(p), HOSTGATE_PROFILE_ID: p.id } : null;
    await serviceCli(rest, repoRoot, () => { if (!environment) throw new Error("Explicit profile installation intent is required."); return environment; }); return;
  }
  if (operation === "update") { const { updateCli } = await import("./updates.js"); await updateCli(rest, repoRoot); return; }
  throw new Error("Unsupported host command. Use host help; no fallback action was performed.");
}
