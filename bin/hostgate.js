#!/usr/bin/env node
import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import os from "node:os";
import path from "node:path";
import process from "node:process";
import readline from "node:readline/promises";
import { fileURLToPath, pathToFileURL } from "node:url";
import { spawnSync } from "node:child_process";
import { managedHome, managedStatus, savedEnvironment } from "../src/managed-common.js";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const projectRoot = path.resolve(__dirname, "..");
const serviceName = "hostgate.service";
const isWindows = process.platform === "win32";
const configDir = path.join(os.homedir(), ".config/hostgate");
const serviceDir = path.join(os.homedir(), ".config/systemd/user");
const servicePath = path.join(serviceDir, serviceName);
const envPath = path.join(configDir, ".env");
const legacyEnvPath = path.join(projectRoot, ".env");
const envExamplePath = path.join(projectRoot, ".env.example");
const serverPath = path.join(projectRoot, "src/server.js");

function usage() {
  console.log(`Hostgate service manager

Usage:
  hostgate onboard      Configure; install/start a user service on Linux only
  hostgate start        Run in the foreground with saved configuration
  hostgate service      Windows managed install/start/restart/status
  hostgate service plan Read-only install preview (prepare is an alias)
  hostgate update       Check/apply a confirmed GitHub update or rollback
  hostgate doctor [--json] [--url HTTPS_URL]  Check setup without changing it
  hostgate status       Linux: service status; Windows: HTTP health check
  hostgate logs [-f]     Linux: journal logs; Windows: use foreground output
  hostgate help         Show this help

Windows: service install --yes creates user-logon recovery with protected settings.
Foreground start remains available. Managed lifecycle logs: hostgate logs.
`);
}

function run(command, args, options = {}) {
  const result = spawnSync(command, args, {
    cwd: projectRoot,
    encoding: "utf8",
    stdio: options.capture ? "pipe" : "inherit"
  });
  if (result.error) {
    throw result.error;
  }
  if (result.status !== 0 && !options.allowFailure) {
    process.exit(result.status ?? 1);
  }
  return result;
}

function systemctl(args, options) {
  if (process.platform !== "linux") {
    throw new Error("Automatic service management requires Linux with systemd --user. Use hostgate start for foreground operation.");
  }
  return run("systemctl", ["--user", ...args], options);
}

function commandExists(command) {
  const result = spawnSync(isWindows ? "where.exe" : "sh",
    isWindows ? [command] : ["-lc", 'command -v "$1"', "sh", command],
    { encoding: "utf8", windowsHide: true });
  return !result.error && result.status === 0;
}

function parseEnv(text) {
  const values = new Map();
  for (const line of text.split(/\r?\n/)) {
    if (!line || line.trimStart().startsWith("#")) {
      continue;
    }
    const index = line.indexOf("=");
    if (index === -1) {
      continue;
    }
    values.set(line.slice(0, index), line.slice(index + 1));
  }
  return values;
}

function serializeEnv(values) {
  const keys = [
    "PORT",
    "HOST",
    "HOSTGATE_OAUTH_USERNAME",
    "HOSTGATE_OAUTH_PASSWORD"
  ];
  return `${keys.map((key) => `${key}=${values.get(key) ?? ""}`).join("\n")}\n`;
}

function defaultEnvValues() {
  if (existsSync(envPath)) {
    return parseEnv(readFileSync(envPath, "utf8"));
  }
  if (existsSync(legacyEnvPath)) {
    return parseEnv(readFileSync(legacyEnvPath, "utf8"));
  }
  if (process.platform === "win32" && existsSync(path.join(os.homedir(), ".config/hostgate/managed/environment.dpapi"))) {
    return new Map(Object.entries(savedEnvironment(managedHome())));
  }
  if (existsSync(envExamplePath)) {
    return parseEnv(readFileSync(envExamplePath, "utf8"));
  }
  return new Map();
}

async function ask(rl, question, currentValue, fallback = "") {
  const current = currentValue || fallback;
  const suffix = current ? ` [${current}]` : "";
  const answer = await rl.question(`${question}${suffix}: `);
  return answer.trim() || current;
}

async function askRequired(rl, question, currentValue, fallback = "") {
  while (true) {
    const answer = await ask(rl, question, currentValue, fallback);
    if (answer) {
      return answer;
    }
    console.log("This value is required.");
  }
}

async function askYesNo(rl, question, fallback = false) {
  const fallbackText = fallback ? "yes" : "no";
  while (true) {
    const answer = (await ask(rl, `${question} (yes/no)`, fallbackText)).toLowerCase();
    if (["yes", "y", "true", "1"].includes(answer)) {
      return true;
    }
    if (["no", "n", "false", "0"].includes(answer)) {
      return false;
    }
    console.log("Enter yes or no.");
  }
}

async function askPassword(rl, currentValue) {
  const hasExisting = Boolean(currentValue);
  if (hasExisting) {
    const answer = await rl.question("OAuth password [keep existing; type new value]: ");
    const trimmed = answer.trim();
    if (!trimmed) {
      return { value: currentValue, changed: false };
    }
    return { value: trimmed, changed: true };
  }

  while (true) {
    const answer = await rl.question("OAuth password: ");
    const trimmed = answer.trim();
    if (trimmed) {
      return { value: trimmed, changed: true };
    }
    console.log("OAuth password is required.");
  }
}

function localTargetHost(host) {
  return host === "0.0.0.0" || host === "::" ? "127.0.0.1" : host;
}

function tailscaleHost() {
  if (!commandExists("tailscale")) {
    return "";
  }
  const result = run("tailscale", ["status", "--json"], { capture: true, allowFailure: true });
  if (result.status !== 0) {
    return "";
  }
  try {
    const status = JSON.parse(result.stdout);
    return String(status.Self?.DNSName || status.CertDomains?.[0] || "").replace(/\.$/, "");
  } catch {
    return "";
  }
}

function configureTailscale(values) {
  if (!commandExists("tailscale")) {
    return { ok: false, message: "Tailscale CLI was not found on PATH." };
  }

  const port = values.get("PORT") || "8787";
  const host = localTargetHost(values.get("HOST") || "127.0.0.1");
  const target = `http://${host}:${port}/hostgate`;
  const result = run("tailscale", ["funnel", "--yes", "--bg", "--set-path=/hostgate", target], {
    capture: true,
    allowFailure: true
  });
  if (result.status !== 0) {
    return {
      ok: false,
      message: (result.stderr || result.stdout || "Tailscale Funnel setup failed.").trim()
    };
  }

  const hostName = tailscaleHost();
  return {
    ok: true,
    url: hostName ? `https://${hostName}/hostgate/mcp` : "",
    message: "Tailscale Funnel is configured for /hostgate."
  };
}

function serviceIsActive() {
  if (isWindows) {
    return false;
  }
  const result = systemctl(["is-active", "--quiet", serviceName], { capture: true, allowFailure: true });
  return result.status === 0;
}

function serviceStatusText(serviceOk) {
  if (isWindows) {
    return "Configuration saved. No Windows service was installed or started.\nStart in a terminal: hostgate start";
  }
  return serviceOk ? `${serviceName} installed and running` : `${serviceName} installed but not running`;
}

function writeServiceFile() {
  mkdirSync(serviceDir, { recursive: true });
  writeFileSync(servicePath, serviceFile());
}

function installService() {
  if (isWindows) {
    return;
  }
  writeServiceFile();
  systemctl(["daemon-reload"]);
  systemctl(["enable", serviceName]);
  systemctl(["restart", serviceName]);
}

function printOnboardSummary(values, exposure, serviceOk) {
  const connectorUrl = exposure?.ok && exposure.url ? exposure.url : "https://<your-domain>/hostgate/mcp";

  console.log("");
  console.log(isWindows ? "Configured" : "Ready");
  console.log("-----");
  console.log(serviceStatusText(serviceOk));
  if (exposure?.ok && exposure.url) {
    console.log(`Tailscale Funnel: ${exposure.url}`);
  } else if (exposure?.ok) {
    console.log("Tailscale Funnel: configured");
  } else {
    console.log("Public URL: not configured");
  }

  console.log("");
  console.log("Connect in ChatGPT");
  console.log("------------------");
  console.log("1. Open the ChatGPT website.");
  console.log("2. Go to Settings -> Apps -> Advanced settings.");
  console.log("3. Enable Developer Mode.");
  console.log("4. Create an app.");
  console.log("5. Enter:");
  console.log(`   Name: Hostgate`);
  console.log("   Description: Remote host operations");
  console.log(`   MCP Server URL: ${connectorUrl}`);
  console.log("   Authentication: OAuth");
  console.log("6. Open Advanced OAuth settings only if you need to choose scopes.");
  console.log("7. Check \"I understand and want to continue\".");
  console.log("8. Click Create.");
  console.log("9. In the OAuth page, enter the username/password you set here, then click Authorize.");
  console.log("10. To use it, start a new chat, press +, select Hostgate, then ask it to run a task.");
  console.log("");
  console.log("Note: ChatGPT memories are not available to developer-mode apps.");

  if (exposure && !exposure.ok) {
    const port = values.get("PORT") || "8787";
    const host = localTargetHost(values.get("HOST") || "127.0.0.1");
    console.log("");
    console.log(`Tailscale was not configured: ${exposure.message}`);
    console.log(`Run later: tailscale funnel --yes --bg --set-path=/hostgate http://${host}:${port}/hostgate`);
  }

  if (!serviceOk) {
    console.log("");
    console.log(isWindows
      ? "Logs appear in the hostgate start terminal. Windows service installation, autostart, and log history are not managed by this CLI."
      : "Check logs: hostgate logs -f");
  }
}

async function onboard() {
  if (!isWindows && process.platform !== "linux") {
    throw new Error("Onboarding supports Windows (foreground) and Linux (systemd --user). Configure the environment and use hostgate start on other platforms.");
  }
  if (!isWindows && !commandExists("systemctl")) {
    throw new Error("Linux onboarding requires systemctl on PATH and a working systemd --user session. Use hostgate start for foreground operation.");
  }
  if (!process.stdin.isTTY || !process.stdout.isTTY) {
    throw new Error("hostgate onboard must be run in an interactive terminal.");
  }

  const values = defaultEnvValues();
  let exposeWithTailscale = false;
  const rl = readline.createInterface({ input: process.stdin, output: process.stdout });
  try {
    console.log("Hostgate onboarding");
    console.log("-------------------");
    console.log("Password input is visible in this terminal. Do not record or share this session.");
    if (isWindows) {
      console.log("Windows foreground mode: no service or autostart will be installed.");
      console.log(`Protect ${configDir} with Windows ACLs; POSIX file modes do not restrict Windows access.`);
    }
    values.set("PORT", values.get("PORT") || "8787");
    values.set("HOST", values.get("HOST") || "127.0.0.1");
    values.set("HOSTGATE_OAUTH_USERNAME", await askRequired(rl, "OAuth username", values.get("HOSTGATE_OAUTH_USERNAME"), "admin"));

    const password = await askPassword(rl, values.get("HOSTGATE_OAUTH_PASSWORD"));
    values.set("HOSTGATE_OAUTH_PASSWORD", password.value);
    values.set("__HOSTGATE_PASSWORD_STATUS", password.changed ? "changed" : "unchanged");
    exposeWithTailscale = await askYesNo(rl, "Expose at /hostgate with Tailscale Funnel", false);
  } finally {
    rl.close();
  }

  mkdirSync(configDir, { recursive: true, mode: 0o700 });
  writeFileSync(envPath, serializeEnv(values), { mode: 0o600 });
  installService();
  const serviceOk = serviceIsActive();
  const exposure = exposeWithTailscale ? configureTailscale(values) : null;
  printOnboardSummary(values, exposure, serviceOk);
}

function serviceFile() {
  return `[Unit]
Description=Hostgate MCP Server
After=network-online.target

[Service]
Type=simple
WorkingDirectory=${projectRoot}
EnvironmentFile=${envPath}
ExecStart=${process.execPath} ${serverPath}
Restart=always
RestartSec=3

[Install]
WantedBy=default.target
`;
}

function logs(follow) {
  if (isWindows && existsSync(path.join(managedHome(), "deployment.json"))) {
    const log = path.join(managedHome(), "events.jsonl");
    console.log(existsSync(log) ? readFileSync(log, "utf8").trim().split(/\r?\n/).slice(-100).join("\n") : "No managed lifecycle events yet.");
    if (follow) console.log("Snapshot only; rerun logs to refresh. Raw tool output is not recorded.");
    return;
  }
  if (isWindows) {
    throw new Error("Windows log history is not managed by Hostgate. Run hostgate start and read stdout/stderr in that terminal; configure your own protected log capture if needed.");
  }
  if (process.platform !== "linux") {
    throw new Error("hostgate logs requires Linux journalctl. Foreground logs are written to stdout/stderr.");
  }
  run("journalctl", ["--user", "-u", serviceName, "-n", "100", "--no-pager", ...(follow ? ["-f"] : [])]);
}

function serverEnvironment() {
  // Keep the existing raw KEY=VALUE format: quotes and # in passwords are literal.
  return { ...Object.fromEntries(defaultEnvValues()), ...process.env };
}

async function startForeground() {
  const env = serverEnvironment();
  if (!env.HOSTGATE_OAUTH_PASSWORD) {
    throw new Error("OAuth password is not configured. Run hostgate onboard or set HOSTGATE_OAUTH_PASSWORD before hostgate start.");
  }
  for (const [key, value] of Object.entries(env)) {
    process.env[key] = value;
  }
  // Run in this process so Ctrl+C does not leave an unmanaged server child behind.
  await import(pathToFileURL(serverPath).href);
}

async function status() {
  if (!isWindows) {
    systemctl(["status", serviceName, "--no-pager"]);
    return;
  }
  if (existsSync(path.join(managedHome(), "deployment.json"))) {
    const report = await managedStatus();
    console.log(JSON.stringify(report, null, 2));
    process.exitCode = report.running ? 0 : 1;
    return;
  }
  const env = serverEnvironment();
  const configuredHost = env.HOST || "127.0.0.1";
  const host = configuredHost === "::" ? "::1" : localTargetHost(configuredHost);
  const authority = host.includes(":") && !host.startsWith("[") ? `[${host}]` : host;
  const url = `http://${authority}:${env.PORT || "8787"}/hostgate/health`;
  console.log("Windows: checking HTTP health, not Windows service status.");
  try {
    const response = await fetch(url, { signal: AbortSignal.timeout(3000), redirect: "error" });
    const health = await response.json();
    if (!response.ok || health.ok !== true || health.name !== "hostgate") {
      throw new Error("Unexpected health response.");
    }
    console.log(`Hostgate is responding at ${url}`);
  } catch {
    throw new Error(`Hostgate is not responding at ${url}. Run hostgate start in another terminal and inspect its output.`);
  }
}

try {
  const [command, ...args] = process.argv.slice(2);
  switch (command || "help") {
    case "onboard":
    case "setup":
      await onboard();
      break;
    case "start":
      await startForeground();
      break;
    case "service": {
      if (["plan", "prepare"].includes(args[0])) {
        // Route before importing the installer or calling any environment provider.
        const { servicePlanCli } = await import("../src/service-plan.js");
        process.exitCode = await servicePlanCli(args.slice(1), projectRoot);
        break;
      }
      const { serviceCli } = await import("../src/service-manager.js");
      await serviceCli(args, projectRoot, serverEnvironment);
      break;
    }
    case "update": {
      const { updateCli } = await import("../src/updates.js");
      await updateCli(args, projectRoot);
      break;
    }
    case "doctor": {
      const { collectDoctor, formatDoctor, parseDoctorArgs } = await import("../src/doctor.js");
      let options;
      try { options = parseDoctorArgs(args); }
      catch (error) {
        console.error(error.message);
        process.exitCode = 2;
        break;
      }
      const report = await collectDoctor({
        projectRoot, ...options,
        managed: isWindows ? await managedStatus() : null,
        readConfig: () => ({
          source: existsSync(envPath) ? "user" : existsSync(legacyEnvPath) ? "legacy" : "missing",
          values: Object.fromEntries(defaultEnvValues())
        })
      });
      console.log(options.json ? JSON.stringify(report, null, 2) : formatDoctor(report));
      process.exitCode = report.exitCode;
      break;
    }
    case "status":
      await status();
      break;
    case "logs":
      logs(args.includes("-f") || args.includes("--follow"));
      break;
    case "help":
    case "--help":
    case "-h":
      usage();
      break;
    default:
      console.error(`Unknown command: ${command}`);
      usage();
      process.exit(2);
  }
} catch (error) {
  console.error(error instanceof Error ? error.message : String(error));
  process.exit(1);
}
