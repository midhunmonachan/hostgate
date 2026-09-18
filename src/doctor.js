import { spawnSync } from "node:child_process";
import { createRequire } from "node:module";
import net from "node:net";
import path from "node:path";
import process from "node:process";
import { shellCommand, shellEnvironment } from "./shell.js";

const TIMEOUT = 3000;
const MAX_BYTES = 65536;
const DEPENDENCIES = ["@modelcontextprotocol/sdk/server/mcp.js", "express", "zod"];
const SCOPES = ["all", "status", "read", "write", "shell"];

// Validate before displaying or contacting a URL; never accept credentials in it.
export function connectorUrl(value) {
  const url = new URL(value);
  if (url.protocol !== "https:" || url.username || url.password || url.search || url.hash ||
      !["/mcp", "/hostgate/mcp"].includes(url.pathname)) {
    throw new Error("Use an HTTPS URL ending in /hostgate/mcp or /mcp, without credentials, a query, or a fragment.");
  }
  return url.href;
}

export function parseDoctorArgs(args) {
  const options = { json: false, publicUrl: null };
  for (let i = 0; i < args.length; i++) {
    if (args[i] === "--json" && !options.json) options.json = true;
    else if (args[i] === "--url" && options.publicUrl === null && args[i + 1]) {
      try { options.publicUrl = connectorUrl(args[++i]); }
      catch { throw new Error("doctor --url needs an HTTPS /hostgate/mcp or /mcp URL without credentials, a query, or a fragment."); }
    } else {
      // Do not echo unknown arguments: a mistakenly pasted argument may be a secret.
      throw new Error("Usage: hostgate doctor [--json] [--url https://your-host/hostgate/mcp]");
    }
  }
  return options;
}

function localBase(values) {
  const port = Number(values.PORT || 8787);
  let host = values.HOST || "127.0.0.1";
  if (!Number.isInteger(port) || port < 1 || port > 65535 || typeof host !== "string") return null;
  if (host.startsWith("[") && host.endsWith("]")) host = host.slice(1, -1);
  if (!net.isIP(host) && !/^[a-zA-Z0-9.-]+$/.test(host)) return null;
  if (host === "0.0.0.0") host = "127.0.0.1";
  if (host === "::") host = "::1";
  try { return new URL(`http://${host.includes(":") ? `[${host}]` : host}:${port}`).origin; }
  catch { return null; }
}

// Only use the existing /hostgate Funnel mapping to this configured backend.
// Other services in the Tailscale configuration are neither probed nor displayed.
export function funnelUrls(config, base) {
  if (!base) return [];
  const urls = [];
  for (const [authority, web] of Object.entries(config?.Web || {})) {
    try {
      const proxy = new URL(web?.Handlers?.["/hostgate"]?.Proxy);
      if (proxy.href.replace(/\/$/, "") !== `${base}/hostgate`) continue;
      const origin = new URL(`https://${authority}`);
      if (origin.pathname !== "/" || origin.search || origin.hash || origin.username || origin.password) continue;
      if (config.AllowFunnel?.[authority] !== true || config.TCP?.[origin.port || "443"]?.HTTPS !== true) continue;
      urls.push(connectorUrl(`${origin.origin}/hostgate/mcp`));
    } catch { /* An unsupported mapping is not evidence of public exposure. */ }
  }
  return [...new Set(urls)];
}

// These bounds apply only to diagnostic probes, never to authorized MCP tools.
export function commandProbe(command, args, options = {}) {
  const result = spawnSync(command, args, {
    ...options, encoding: "utf8", windowsHide: true, shell: false,
    timeout: TIMEOUT, maxBuffer: MAX_BYTES, stdio: ["ignore", "pipe", "pipe"]
  });
  // Raw stderr/errors may contain secrets, paths or terminal control sequences.
  return { ok: !result.error && result.status === 0, stdout: result.stdout || "" };
}

export async function httpProbe(url, fetchImpl = globalThis.fetch) {
  let reader;
  try {
    const response = await fetchImpl(url, {
      method: "GET", redirect: "error", credentials: "omit",
      headers: { Accept: "application/json" }, signal: AbortSignal.timeout(TIMEOUT)
    });
    const chunks = [];
    let size = 0;
    if (response.body) {
      reader = response.body.getReader();
      while (true) {
        const { done, value } = await reader.read();
        if (done) break;
        size += value.byteLength;
        if (size > MAX_BYTES) throw new Error("Diagnostic response too large.");
        chunks.push(Buffer.from(value));
      }
    }
    let data = null;
    try { data = JSON.parse(Buffer.concat(chunks).toString("utf8")); } catch { /* Not JSON. */ }
    return { status: response.status, data, challenge: response.headers.get("www-authenticate") || "" };
  } catch {
    return { status: null, data: null, challenge: "" };
  } finally {
    if (reader) {
      try { await reader.cancel(); } catch { /* Already closed/aborted. */ }
      reader.releaseLock();
    }
  }
}

/** Collect read-only findings. Injected I/O keeps tests off the user's machine and network. */
export async function collectDoctor(options, io = {}) {
  const { projectRoot, readConfig, platform = process.platform, nodeVersion = process.versions.node,
    env = process.env, publicUrl = null } = options;
  const run = io.run || commandProbe;
  const probe = async (url) => {
    try { return await (io.probe || httpProbe)(url); }
    catch { return { status: null, data: null, challenge: "" }; }
  };
  const require = createRequire(path.join(projectRoot, "package.json"));
  const resolveDependency = io.resolveDependency || ((name) => require.resolve(name));
  const commandEnv = shellEnvironment(platform, env);
  for (const key of ["XDG_RUNTIME_DIR", "DBUS_SESSION_BUS_ADDRESS"]) {
    if (env[key] !== undefined) commandEnv[key] = env[key];
  }
  const checks = [];
  const add = (id, status, message, nextStep = "") => checks.push({ id, status, message, nextStep });
  const invoke = (command, args) => {
    try { return run(command, args, { cwd: projectRoot, env: commandEnv }); }
    catch { return { ok: false, stdout: "" }; }
  };
  // Fixed commands only. No shell interpolation of configuration or user input.
  const found = (name) => invoke(platform === "win32" ? "where.exe" : "/bin/sh",
    platform === "win32" ? [name] : ["-c", 'command -v "$1"', "sh", name]).ok;
  const cli = "node bin/hostgate.js";
  const supportedNode = Number(nodeVersion.split(".")[0]) >= 22;
  add("runtime", supportedNode ? "ok" : "attention",
    supportedNode ? "Node.js meets the version requirement." : "Node.js 22 or newer is required.",
    supportedNode ? "" : "Install a supported Node.js release that includes npm, then reopen your terminal.");
  const missing = DEPENDENCIES.filter((name) => { try { resolveDependency(name); return false; } catch { return true; } });
  add("dependencies", missing.length ? "attention" : "ok",
    missing.length ? `Required packages are missing: ${missing.join(", ")}.` : "Required package entry points are installed (not a version or integrity audit).",
    missing.length ? `In your checkout, run ${platform === "win32" ? "npm.cmd" : "npm"} ci after installing npm.` : "");
  const npm = options.managed?.npmAvailable || found(platform === "win32" ? "npm.cmd" : "npm");
  add("npm", npm ? "ok" : "attention", npm ? (options.managed?.npmAvailable ? "npm is configured for managed updates." : "npm is on PATH.") : "npm was not found in this terminal.",
    npm ? "" : "Use a Node.js installation that includes npm and reopen the terminal. An already running Hostgate can still work.");

  if (["win32", "linux"].includes(platform)) {
    const spec = platform === "win32" ? shellCommand("$PSVersionTable.PSVersion.ToString()", platform, env)
      : { cmd: "/bin/bash", args: ["--noprofile", "--norc", "-c", "printf '%s' \"$BASH_VERSION\""] };
    const shell = invoke(spec.cmd, spec.args);
    add("shell", shell.ok ? "ok" : "attention",
      shell.ok ? `${platform === "win32" ? "Windows PowerShell" : "Bash"} starts successfully.` : "The required command shell could not be started.",
      shell.ok ? "" : platform === "win32" ? "Check that Windows PowerShell is installed and accessible; do not disable execution policies." : "Install Bash at /bin/bash and rerun this check.");
  } else add("shell", "attention", "Guided setup supports Windows and Linux.", "Use a supported platform; no service changes were attempted.");

  let config = { source: "missing", values: {} };
  let configReadable = true;
  try { config = readConfig(); } catch { configReadable = false; }
  const saved = ["user", "legacy"].includes(config.source) && Boolean(config.values.HOSTGATE_OAUTH_PASSWORD);
  const values = { ...config.values, ...env }; // Same precedence and raw-value parser as CLI start.
  const emptyOverride = saved && !values.HOSTGATE_OAUTH_PASSWORD;
  add("restart", configReadable && saved && !emptyOverride ? "unverified" : "attention",
    emptyOverride ? "This terminal overrides the saved password with an empty value; startup would fail."
      : !configReadable ? "Saved configuration could not be read." : saved
      ? "Saved credentials are present; a restart has not been tested."
      : "Saved restart credentials were not found. A running server may rely on a different environment.",
    emptyOverride ? "Review the terminal environment; do not replace the saved password or stop a working server."
      : saved && configReadable ? "Environment overrides are not saved. Do not assume boot/autostart or a fresh-shell restart is verified."
      : `Do not stop a working server. Review its deployment settings first; for a new installation run ${cli} onboard.`);
  const managed = options.managed;
  if (managed?.configured) {
    const restart = checks.find((c) => c.id === "restart");
    restart.status = managed.restartReady ? "ok" : "attention";
    restart.message = managed.restartReady ? "Saved managed environment and runtime passed a real start; fresh-terminal restart is ready." : "Managed configuration exists but restart prerequisites or a successful launch are missing.";
    restart.nextStep = "Use hostgate service status. This does not claim an actual reboot has been tested.";
    add("configured", managed.decryptable ? "ok" : "attention", managed.decryptable ? "Managed settings are decryptable by this Windows account." : "Managed settings cannot be decrypted by this account.");
    add("running", managed.running ? "ok" : "attention", managed.running ? "The managed process and its current release are running and healthy." : "The managed runtime is not currently verified running.");
  } else add("configured", saved && configReadable ? "ok" : "attention", saved && configReadable ? "Foreground settings are present; no managed installation is configured." : "Saved startup configuration is missing.");
  const base = managed?.configured && managed.host ? localBase({ HOST: managed.host, PORT: String(managed.port) }) : configReadable ? localBase(values) : null;
  if (!base) add("local", "attention", "The configured HOST/PORT cannot be checked (or configuration is unreadable).",
    "Review the existing configuration. Use a valid host and a fixed port from 1 to 65535; diagnostic output never prints invalid values.");
  else {
    const health = await probe(`${base}/hostgate/health`);
    const ok = health.status === 200 && health.data?.ok === true && health.data?.name === "hostgate";
    add("local", ok ? "ok" : "attention", ok ? `Hostgate is responding at ${base}.`
      : health.status === null ? `No health response from ${base}.` : `The endpoint at ${base} did not return Hostgate health; another program or proxy may be answering.`,
    ok ? "This checks availability, not credentials or which commit is running."
      : `Check the Hostgate terminal and configured address. Start with ${cli} start only after checking for an existing instance; do not stop an unidentified process.`);
  }

  if (platform === "linux" && options.profile) add("background", "unverified", "This named Linux profile has no automatic systemd installer. Use an explicit per-profile launcher; the legacy service is not inspected.");
  else if (platform === "linux") {
    const active = invoke("systemctl", ["--user", "is-active", "--quiet", "hostgate.service"]);
    add("background", active.ok ? "ok" : "unverified", active.ok ? "The Linux user service is active; boot behavior is not verified." : "No active Linux user service was verified.",
      active.ok ? "" : `Foreground operation remains available with ${cli} start. Automatic onboarding needs a working systemd user session.`);
  } else if (managed?.configured) add("background", managed.autostart ? "ok" : "attention", managed.autostart ? "The verified user-logon task will start the supervisor after this account logs in." : "User-logon recovery task is missing or differs from the installed definition.", "User-logon recovery is not a pre-login Windows service or proof of a completed reboot test.");
  else add("background", "unverified", "Windows background service and autostart are not managed by this CLI.",
    "Keep the foreground terminal open. A separately managed launcher is not verified by this check.");

  let url = null;
  let invalidUrl = false;
  if (publicUrl !== null) { try { url = connectorUrl(publicUrl); } catch { invalidUrl = true; } }
  if (!url && !invalidUrl) {
    const status = invoke(platform === "win32" ? "tailscale.exe" : "tailscale", ["funnel", "status", "--json"]);
    let candidates = [];
    try { if (status.ok) candidates = funnelUrls(JSON.parse(status.stdout), base); } catch { /* Unrecognized output. */ }
    if (candidates.length === 1) url = candidates[0];
    add("tunnel", url ? "ok" : "unverified", url ? "An existing public Funnel route matches this Hostgate address."
      : "No single matching public Funnel route was verified; Tailscale may be absent, stopped, or configured differently.",
    url ? "Funnel exposes this endpoint to the public internet. No tunnel settings were changed."
      : `For an existing HTTPS deployment, use ${cli} doctor --url https://your-host/hostgate/mcp. Tailscale is optional.`);
  }
  if (!url) add("https", "attention", invalidUrl ? "The supplied connection URL is not a supported HTTPS MCP URL." : "No public HTTPS connection URL was verified.",
    `Use ${cli} doctor --url https://your-host/hostgate/mcp for your existing endpoint. Do not include passwords or tokens.`);
  else if (env.NODE_TLS_REJECT_UNAUTHORIZED === "0") add("https", "attention", "TLS certificate validation is disabled in this environment; HTTPS cannot be verified.",
    "Rerun from a terminal with normal certificate validation. Do not bypass certificate checks.");
  else {
    const remoteBase = url.slice(0, -"/mcp".length);
    const health = await probe(`${remoteBase}/health`);
    const ok = health.status === 200 && health.data?.ok === true && health.data?.name === "hostgate";
    add("https", ok ? "ok" : "attention", ok ? `HTTPS health responds from this computer. Connection URL: ${url}` : "The HTTPS endpoint did not return valid Hostgate health.",
      ok ? "Remote ChatGPT reachability still requires a connection test." : "Check the server, certificate, DNS, and existing HTTPS proxy. Redirects and invalid certificates are not accepted.");
    if (ok) {
      const [oauth, resource, gate] = await Promise.all([
        probe(`${remoteBase}/.well-known/oauth-authorization-server`),
        probe(`${remoteBase}/.well-known/oauth-protected-resource`), probe(url)
      ]);
      const auth = oauth.data;
      const res = resource.data;
      const discovery = oauth.status === 200 && resource.status === 200 && auth?.issuer === remoteBase &&
        auth.authorization_endpoint === `${remoteBase}/oauth/authorize` && auth.token_endpoint === `${remoteBase}/oauth/token` &&
        auth.registration_endpoint === `${remoteBase}/oauth/register` &&
        Array.isArray(auth.code_challenge_methods_supported) && auth.code_challenge_methods_supported.includes("S256") &&
        res?.resource === url && Array.isArray(res.authorization_servers) && res.authorization_servers.includes(remoteBase) &&
        Array.isArray(auth.scopes_supported) && Array.isArray(res.scopes_supported) &&
        SCOPES.every((scope) => auth.scopes_supported.includes(scope) && res.scopes_supported.includes(scope));
      add("discovery", discovery ? "ok" : "attention", discovery ? "OAuth discovery matches the connection URL, S256, and Hostgate scopes." : "OAuth discovery does not match the expected Hostgate endpoint.",
        discovery ? "" : "Verify that your proxy forwards the complete Hostgate prefix, including OAuth and discovery, using the public HTTPS origin.");
      const denied = gate.status === 401 && gate.data?.error === "authorization_required" &&
        gate.challenge.includes(`resource_metadata="${remoteBase}/.well-known/oauth-protected-resource"`);
      add("auth-gate", denied ? "ok" : "attention", denied ? "An unauthenticated MCP GET is rejected with the expected OAuth challenge." : "The expected unauthenticated MCP rejection was not verified.",
        denied ? "This is a single unauthenticated probe, not a security audit."
          : "Review authentication and proxy routing before using this endpoint. This check changes no exposure settings.");
    }
  }
  add("signin", "unverified", "ChatGPT sign-in, granted tools, and reconnection have not been tested.",
    "Follow README > Connect for your interface, then ask Hostgate status for the hostname. No login, token exchange, or tool call was performed by doctor.");
  // No environment, credential values, raw command output, or HTTP response bodies leave this function.
  const secrets = [env.HOSTGATE_OAUTH_USERNAME, env.HOSTGATE_OAUTH_PASSWORD,
    config.values.HOSTGATE_OAUTH_USERNAME, config.values.HOSTGATE_OAUTH_PASSWORD].filter((v) => typeof v === "string" && v.length);
  for (const check of checks) {
    for (const key of ["message", "nextStep"]) {
      for (const secret of secrets) check[key] = check[key].split(secret).join("[redacted]");
      check[key] = check[key].replace(/[\u0000-\u001f\u007f-\u009f]/g, " ");
    }
  }
  return { schemaVersion: 1, platform, checks, exitCode: checks.some((check) => check.status === "attention") ? 1 : 0 };
}

export function formatDoctor(report) {
  const labels = { ok: "OK", attention: "NEEDS ATTENTION", unverified: "NOT VERIFIED" };
  return ["Hostgate setup check (read-only)", "",
    ...report.checks.flatMap((check) => [`${labels[check.status].padEnd(17)} ${check.message}`,
      ...(check.nextStep ? [`                  ${check.nextStep}`] : [])]), "",
    "No fixes applied. Availability does not prove authentication, restart readiness, or perimeter security."
  ].join("\n");
}
