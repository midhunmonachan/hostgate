#!/usr/bin/env node
import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import os from "node:os";
import path from "node:path";
import process from "node:process";
import readline from "node:readline/promises";
import { fileURLToPath } from "node:url";
import { spawnSync } from "node:child_process";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const projectRoot = path.resolve(__dirname, "..");
const serviceName = "hostgate.service";
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
  hostgate onboard      Configure, install, and start Hostgate
  hostgate status        Show service status
  hostgate logs [-f]     Show service logs, optionally follow
  hostgate help          Show this help
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
  return run("systemctl", ["--user", ...args], options);
}

function commandExists(command) {
  const result = run("sh", ["-lc", `command -v ${command}`], { capture: true, allowFailure: true });
  return result.status === 0;
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
  const result = systemctl(["is-active", "--quiet", serviceName], { capture: true, allowFailure: true });
  return result.status === 0;
}

function serviceStatusText(serviceOk) {
  return serviceOk ? `${serviceName} installed and running` : `${serviceName} installed but not running`;
}

function writeServiceFile() {
  mkdirSync(serviceDir, { recursive: true });
  writeFileSync(servicePath, serviceFile());
}

function installService() {
  writeServiceFile();
  systemctl(["daemon-reload"]);
  systemctl(["enable", serviceName]);
  systemctl(["restart", serviceName]);
}

function printOnboardSummary(values, exposure, serviceOk) {
  const connectorUrl = exposure?.ok && exposure.url ? exposure.url : "https://<your-domain>/hostgate/mcp";

  console.log("");
  console.log("Ready");
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
    console.log("Check logs: hostgate logs -f");
  }
}

async function onboard() {
  if (!process.stdin.isTTY || !process.stdout.isTTY) {
    throw new Error("hostgate onboard must be run in an interactive terminal.");
  }

  const values = defaultEnvValues();
  let exposeWithTailscale = false;
  const rl = readline.createInterface({ input: process.stdin, output: process.stdout });
  try {
    console.log("Hostgate onboarding");
    console.log("-------------------");
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
  run("journalctl", ["--user", "-u", serviceName, "-n", "100", "--no-pager", ...(follow ? ["-f"] : [])]);
}

try {
  const [command, ...args] = process.argv.slice(2);
  switch (command || "help") {
    case "onboard":
    case "setup":
      await onboard();
      break;
    case "status":
      systemctl(["status", serviceName, "--no-pager"]);
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
