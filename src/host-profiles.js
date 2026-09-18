import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import crypto from "node:crypto";
import { hostId, hostPaths } from "./host-paths.js";

export function hostName(value) {
  if (typeof value !== "string" || value !== value.trim() || !/^[\p{L}\p{N}][\p{L}\p{N} ._()-]{0,63}$/u.test(value) || /^[a-f0-9-]{36}$/.test(value)) throw new Error("Use a distinct 1-64 character host name without control characters or URLs.");
  return value.normalize("NFC");
}
export function contextName(value) {
  if (typeof value !== "string" || !/^[A-Za-z0-9][A-Za-z0-9._:/-]{0,127}$/.test(value) || ["__proto__", "constructor", "prototype"].includes(value)) throw new Error("Use an explicit project/chat context label (1-128 letters, digits or ._:/-).");
  return value;
}
export function hostEndpoint(value) {
  if (typeof value !== "string" || !/^https:\/\//.test(value) || /[\s\\#?]/.test(value)) throw new Error("Host endpoints must be HTTPS /mcp or /hostgate/mcp URLs without secrets or queries.");
  const u = new URL(value);
  if (u.username || u.password || !["/mcp", "/hostgate/mcp"].includes(u.pathname) || !u.hostname || u.hostname.endsWith(".")) throw new Error("Invalid host endpoint; credentials in URLs are not accepted.");
  return u.href;
}
export function hostCwd(value, platform) {
  const p = platform === "win32" ? path.win32 : path.posix;
  if (typeof value !== "string" || !p.isAbsolute(value) || /[\u0000-\u001f\u007f]/.test(value) || (platform === "win32" && !/^[A-Za-z]:[\\/]/.test(value))) throw new Error("The host working directory must be an explicit absolute path for its platform.");
  return p.normalize(value);
}
const key = (name) => hostName(name).toLowerCase();
export const registryPath = (home = os.homedir()) => path.join(home, ".config", "hostgate", "hosts.json");
// Reject linked storage ancestors. This protects Hostgate's own metadata; file/shell
// tools remain unrestricted and do not use this check as a sandbox.
export function noStorageLinks(filename) {
  let current = path.resolve(filename);
  for (;;) {
    try { if (fs.lstatSync(current).isSymbolicLink()) throw new Error("Host profile storage must not contain links."); }
    catch (error) { if (error.code !== "ENOENT") throw error; }
    const parent = path.dirname(current); if (parent === current) break; current = parent;
  }
}
function validateProfile(p) {
  const fields = ["id", "name", "endpoint", "platform", "kind", "cwd", "machine", "active"];
  if (!p || typeof p !== "object" || Object.keys(p).some((k) => !fields.includes(k))) throw new Error("Invalid profile metadata; no values were displayed.");
  hostId(p.id); hostName(p.name); hostEndpoint(p.endpoint);
  if (!["win32", "linux"].includes(p.platform) || !["local", "remote"].includes(p.kind) || typeof p.active !== "boolean" || typeof p.machine !== "string") throw new Error("Invalid host profile.");
  if (hostCwd(p.cwd, p.platform) !== p.cwd || hostEndpoint(p.endpoint) !== p.endpoint) throw new Error("Noncanonical host profile.");
  return p;
}
export function readHosts(home = os.homedir()) {
  const file = registryPath(home); noStorageLinks(file);
  if (!fs.existsSync(file)) return { version: 1, profiles: [], selections: {} };
  let r;
  try { if (fs.statSync(file).size > 1048576) throw new Error(); r = JSON.parse(fs.readFileSync(file, "utf8")); }
  catch { throw new Error("Host profile registry is unreadable; it was not replaced."); }
  if (r.version !== 1 || !Array.isArray(r.profiles) || !r.selections || typeof r.selections !== "object" || Array.isArray(r.selections) || Object.keys(r).some(k => !["version", "profiles", "selections"].includes(k))) throw new Error("Unsupported host registry.");
  const ids = new Set(), names = new Set(), origins = new Set();
  for (const p of r.profiles) {
    validateProfile(p);
    const origin = new URL(p.endpoint).origin;
    if (ids.has(p.id) || names.has(key(p.name)) || origins.has(origin)) throw new Error("Host IDs, names and origins must be unique, including retired profiles.");
    ids.add(p.id); names.add(key(p.name)); origins.add(origin);
  }
  for (const [ctx, selection] of Object.entries(r.selections)) {
    contextName(ctx); const id = typeof selection === "string" ? selection : selection?.hostId; hostId(id);
    const p = r.profiles.find(p => p.id === id && p.active); if (!p) throw new Error("Invalid context selection.");
    if (typeof selection !== "string" && (Object.keys(selection).some(k => !["hostId", "cwd"].includes(k)) || hostCwd(selection.cwd, p.platform) !== selection.cwd)) throw new Error("Invalid context working directory.");
  }
  return r;
}
export function atomicJson(file, value) {
  noStorageLinks(file);
  const temporary = `${file}.${crypto.randomUUID()}.tmp`;
  const fd = fs.openSync(temporary, "wx", 0o600);
  try { fs.writeFileSync(fd, JSON.stringify(value, null, 2) + "\n"); fs.fsyncSync(fd); }
  finally { fs.closeSync(fd); }
  fs.renameSync(temporary, file);
}
function changeHosts(home, fn) {
  const file = registryPath(home), directory = path.dirname(file); noStorageLinks(file);
  fs.mkdirSync(directory, { recursive: true, mode: 0o700 });
  const lock = path.join(directory, "hosts.lock"), owner = crypto.randomUUID(); let fd;
  try { fd = fs.openSync(lock, "wx", 0o600); }
  catch { throw new Error("Host registry is busy or locked by an interrupted edit. No update was applied; inspect the lock locally."); }
  try {
    fs.writeFileSync(fd, JSON.stringify({ pid: process.pid, owner }));
    const r = readHosts(home); const result = fn(r); atomicJson(file, r); return result;
  }
  finally {
    fs.closeSync(fd);
    let lockOwner;
    try { lockOwner = JSON.parse(fs.readFileSync(lock, "utf8")).owner; } catch { /* Retain an incomplete lock for explicit local recovery. */ }
    if (lockOwner === owner) fs.unlinkSync(lock);
    // Never remove a lock another writer has replaced.
  }
}
export function findHost(selector, home = os.homedir(), includeRetired = false) {
  if (typeof selector !== "string" || !selector) throw new Error("An explicit host name or ID is required; selection is never an execution default.");
  const found = readHosts(home).profiles.filter(p => (p.id === selector || p.name.toLowerCase() === selector.normalize("NFC").toLowerCase()) && (includeRetired || p.active));
  if (found.length !== 1) throw new Error("Unknown, retired, or ambiguous host. No fallback host was selected.");
  return Object.freeze({ ...found[0] });
}
export function localHost(selector, home = os.homedir()) {
  const p = findHost(selector, home);
  if (p.kind !== "local" || p.platform !== process.platform || p.machine !== os.hostname()) throw new Error("This is not a local profile for this machine. Use its own authenticated ChatGPT connection; no remote action was attempted.");
  return p;
}
export function addHost(input, home = os.homedir()) {
  const kind = input.kind;
  if (!["local", "remote"].includes(kind)) throw new Error("Choose --local or --remote explicitly.");
  if (kind === "remote" && !input.id || kind === "local" && input.id) throw new Error("Remote profiles need the existing target UUID; local profiles generate their own UUID.");
  const p = { id: kind === "local" ? crypto.randomUUID() : hostId(input.id), name: hostName(input.name), endpoint: hostEndpoint(input.endpoint),
    platform: kind === "local" ? process.platform : input.platform, kind, cwd: hostCwd(input.cwd, kind === "local" ? process.platform : input.platform), machine: kind === "local" ? os.hostname() : "", active: true };
  validateProfile(p);
  if (kind === "local" && !fs.statSync(p.cwd).isDirectory()) throw new Error("Local working directory is not a directory.");
  return changeHosts(home, r => {
    if (r.profiles.some(other => other.id === p.id || key(other.name) === key(p.name) || new URL(other.endpoint).origin === new URL(p.endpoint).origin)) throw new Error("Host ID/name/origin already exists or is retired. Nothing was reassigned.");
    r.profiles.push(p); return p;
  });
}
export function renameHost(selector, name, home = os.homedir()) {
  const old = findHost(selector, home); name = hostName(name);
  return changeHosts(home, r => {
    if (r.profiles.some(p => p.id !== old.id && key(p.name) === key(name))) throw new Error("Host name is already reserved.");
    const p = r.profiles.find(p => p.id === old.id && p.active); if (!p) throw new Error("Profile changed; retry inspection.");
    p.name = name; return p;
  });
}
export function selectHost(selector, context, home = os.homedir(), cwd = null) {
  const p = findHost(selector, home); contextName(context);
  return changeHosts(home, r => { if (!r.profiles.some(x => x.id === p.id && x.active)) throw new Error("Profile changed."); Object.defineProperty(r.selections, context, { value: cwd === null ? p.id : { hostId: p.id, cwd: hostCwd(cwd, p.platform) }, writable: true, enumerable: true, configurable: true }); return { context, hostId: p.id, executionDefault: false }; });
}
export function selectedHost(context, home = os.homedir()) {
  contextName(context); const selection = readHosts(home).selections[context];
  if (!selection) throw new Error("No host is selected for this explicit context.");
  const p = findHost(typeof selection === "string" ? selection : selection.hostId, home);
  return typeof selection === "string" ? p : Object.freeze({ ...p, cwd: selection.cwd });
}
export function removeHost(selector, home = os.homedir()) {
  const p = findHost(selector, home), paths = hostPaths(p.id, home);
  if (fs.existsSync(path.join(paths.managed, "deployment.json"))) throw new Error("Managed deployment still exists. Retiring it requires a separate lifecycle operation; no tasks or state were removed.");
  if (fs.existsSync(paths.status)) {
    let state; try { state = JSON.parse(fs.readFileSync(paths.status, "utf8")); } catch { throw new Error("Host runtime status is unreadable; cannot safely retire it."); }
    if (Number.isInteger(state.pid)) { let live = false; try { process.kill(state.pid, 0); live = true; } catch {} if (live) throw new Error("Host runtime may still be running. Stop it separately before retiring the profile."); }
  }
  return changeHosts(home, r => { const entry = r.profiles.find(x => x.id === p.id); entry.active = false; for (const [ctx, id] of Object.entries(r.selections)) if (id === p.id || id?.hostId === p.id) delete r.selections[ctx]; return { hostId: p.id, retired: true, stateDeleted: false, credentialsRevoked: false }; });
}
export function profilePublic(p, home = os.homedir()) {
  const paths = hostPaths(p.id, home);
  return { ...p, origin: new URL(p.endpoint).origin, paths,
    credentialsPresent: fs.existsSync(paths.credentials), oauthStatePresent: fs.existsSync(paths.oauth), managedConfigured: fs.existsSync(path.join(paths.managed, "deployment.json")),
    remoteContacted: false };
}
export function routingCard(p, context) {
  return { connectionName: `Hostgate - ${p.name}`, target: { hostId: p.id, hostName: p.name, endpoint: p.endpoint }, contextId: contextName(context), cwd: p.cwd,
    instruction: "Use only this named connection and include this exact target/context in every call. Never substitute another connection or change target fields to make a rejection pass. Each shell or relative file call must supply its own cwd. No host fallback." };
}
// Explicit configuration never inherits another host's or the legacy environment.
export function validateHostConfig(input) {
  if (!input || typeof input !== "object" || Array.isArray(input) || Object.keys(input).some(k => !["HOST", "PORT", "HOSTGATE_OAUTH_USERNAME", "HOSTGATE_OAUTH_PASSWORD"].includes(k))) throw new Error("Profile configuration accepts only HOST, PORT, HOSTGATE_OAUTH_USERNAME and HOSTGATE_OAUTH_PASSWORD.");
  for (const k of ["HOSTGATE_OAUTH_USERNAME", "HOSTGATE_OAUTH_PASSWORD"]) if (typeof input[k] !== "string" || !input[k] || /[\0\r\n]/.test(input[k])) throw new Error("Explicit profile credentials are required; no values were displayed.");
  if (typeof input.HOST !== "string" || !["127.0.0.1", "::1"].includes(input.HOST) || typeof input.PORT !== "string" || !/^[0-9]+$/.test(input.PORT) || Number(input.PORT) < 1 || Number(input.PORT) > 65535) throw new Error("Profile configuration needs a fixed PORT and loopback HOST; HTTPS terminates at the explicit endpoint/proxy.");
  return { ...input };
}
export async function saveHostConfig(p, input, home = os.homedir()) {
  localHost(p.id, home); const values = validateHostConfig(input), paths = hostPaths(p.id, home);
  noStorageLinks(paths.credentials);
  if (fs.existsSync(paths.credentials)) throw new Error("Profile credentials already exist; no rotation or overwrite is performed.");
  const envelope = JSON.stringify({ version: 1, hostId: p.id, endpoint: p.endpoint, values });
  if (process.platform === "win32") {
    const { windows } = await import("./managed-common.js");
    windows("secure", { directory: paths.config });
    const result = windows("protect", { text: envelope });
    fs.writeFileSync(paths.credentials, result.ciphertext + "\n", { flag: "wx", mode: 0o600 });
  } else {
    fs.mkdirSync(paths.config, { recursive: true, mode: 0o700 });
    fs.writeFileSync(paths.credentials, envelope + "\n", { flag: "wx", mode: 0o600 });
  }
  return { hostId: p.id, configured: true, valuesPrinted: false, serverStarted: false };
}
export async function readHostConfig(p, home = os.homedir()) {
  const file = hostPaths(p.id, home).credentials; noStorageLinks(file);
  let envelope;
  try {
    if (process.platform === "win32") { const { windows } = await import("./managed-common.js"); envelope = JSON.parse(windows("unprotect", { ciphertext: fs.readFileSync(file, "utf8").trim() }).text); }
    else { if ((fs.statSync(file).mode & 0o077) !== 0) throw new Error(); envelope = JSON.parse(fs.readFileSync(file, "utf8")); }
    if (envelope.version !== 1 || envelope.hostId !== p.id || envelope.endpoint !== p.endpoint) throw new Error();
    return validateHostConfig(envelope.values);
  } catch { throw new Error("This host's protected configuration is unavailable or belongs to another host. No legacy/selected-host fallback was attempted."); }
}
