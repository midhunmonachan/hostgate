// Read-only planner I/O. Deliberately independent of the installer, updater,
// doctor, savedEnvironment(), and the mutation-capable Windows adapter.
import fs from "node:fs";
import crypto from "node:crypto";
import os from "node:os";
import path from "node:path";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import { localWindowsPath } from "./service-plan.js";

const sha = (bytes) => crypto.createHash("sha256").update(bytes).digest("hex");
const privatePath = (file) => /(^|[\\/])(\.config|\.local|node_modules)([\\/]|$)/i.test(file) ||
  /(^|[\\/])(\.env(?:\..*)?|environment\.dpapi|oauth-state\.json|deployment\.json)$/i.test(file) && !/(^|[\\/])\.env\.example$/i.test(file);
export function planContext(repoRoot) {
  // OS-provided path/runtime metadata only; never enumerate/read launcher values.
  return { platform: process.platform, repoRoot, home: os.homedir(), nodePath: process.execPath, nodeVersion: process.versions.node };
}
export function metadataOnly(filename) {
  filename = localWindowsPath(filename);
  const root = path.win32.parse(filename).root;
  let current = root;
  const parts = filename.slice(root.length).split("\\").filter(Boolean);
  for (let i = -1; i < parts.length; i++) {
    if (i >= 0) current = path.win32.join(current, parts[i]);
    let stat;
    try { stat = fs.lstatSync(current); }
    catch (error) { return error.code === "ENOENT" ? "absent" : "inaccessible"; }
    if (stat.isSymbolicLink()) return "linked";
    if (i < parts.length - 1 && !stat.isDirectory()) return "invalid-ancestor";
    if (i === parts.length - 1) return stat.isDirectory() ? "directory" : stat.isFile() ? "file" : "other";
  }
  return "directory";
}
function publicBytes(filename, maximum) {
  // This reader is reachable only for code/executable/package metadata, not any
  // environment or deployment file. Presence probes never call it.
  if (/(^|[\\/])(\.env(?:\..*)?|environment\.dpapi|oauth-state\.json|deployment\.json)$/i.test(filename) ||
      metadataOnly(filename) !== "file" || fs.statSync(filename).size > maximum) throw new Error("Cannot read public planner input.");
  return fs.readFileSync(filename);
}

export function supportsNode(range, version) {
  if (typeof range !== "string" || typeof version !== "string" || !/^\d+\.\d+\.\d+$/.test(version)) return null;
  const v = version.split(".").map(Number);
  const cmp = (a, b) => a[0] - b[0] || a[1] - b[1] || a[2] - b[2];
  let unknown = false;
  for (const clause of range.split("||")) {
    const tokens = clause.trim().split(/\s+/);
    let ok = true;
    for (const token of tokens) {
      const match = /^(\^|>=|<=|>|<|=)?(\d+)\.(\d+)\.(\d+)$/.exec(token);
      if (!match) { unknown = true; ok = false; break; }
      const target = match.slice(2).map(Number);
      const d = cmp(v, target);
      const upper = target[0] ? [target[0] + 1, 0, 0] : target[1] ? [0, target[1] + 1, 0] : [0, 0, target[2] + 1];
      const satisfied = ({ ">=": d >= 0, ">": d > 0, "<=": d <= 0, "<": d < 0, "=": d === 0, "^": d >= 0 && cmp(v, upper) < 0 })[match[1] || "="];
      ok &&= satisfied;
    }
    if (ok) return true;
  }
  return unknown ? null : false;
}

export function plannerProcessEnvironment(home, systemRoot = "C:\\Windows") {
  // Fixed non-secret child environment. No spreading/enumeration of process.env,
  // no inherited NODE_OPTIONS, npm config, credential helper, or OAuth settings.
  const local = path.win32.join(home, "AppData", "Local");
  return { SystemRoot: systemRoot, WINDIR: systemRoot, HOME: home, USERPROFILE: home,
    APPDATA: path.win32.join(home, "AppData", "Roaming"), LOCALAPPDATA: local,
    TEMP: path.win32.join(local, "Temp"), TMP: path.win32.join(local, "Temp"),
    PATH: `${systemRoot}\\System32;${systemRoot}`, PATHEXT: ".COM;.EXE;.BAT;.CMD",
    GIT_CONFIG_NOSYSTEM: "1", GIT_CONFIG_GLOBAL: "NUL", GIT_TERMINAL_PROMPT: "0" };
}

export function createPlanProbes(context, options, io = {}) {
  const spawn = io.spawn || spawnSync;
  const gitPath = options.gitPath || "C:\\Program Files\\Git\\cmd\\git.exe";
  const cscriptPath = options.cscriptPath || "C:\\Windows\\System32\\cscript.exe";
  const script = fileURLToPath(new URL("./windows-plan.wsf", import.meta.url));
  const env = plannerProcessEnvironment(context.home);
  const run = (command, args, input, encoding = "utf8") => {
    const result = spawn(command, args, { env, input, encoding, shell: false, windowsHide: true,
      stdio: [input === undefined ? "ignore" : "pipe", "pipe", "pipe"], timeout: 15000, maxBuffer: 1048576 });
    if (result.error || result.status !== 0) throw new Error("Read-only planner probe failed.");
    return result.stdout.replace(/^\uFEFF/, "").trim();
  };
  const git = (root, args) => run(gitPath, ["--no-optional-locks", "--no-pager", "-c", "core.attributesFile=NUL", "-c", "core.fsmonitor=false", "-c", "core.untrackedCache=false", "-c", "core.quotepath=false", "-C", root, ...args]);
  const csv = (text) => text.split(/\r?\n/).filter(Boolean).map((line) => [...line.matchAll(/"((?:[^"]|"")*)"(?:,|$)/g)].map((match) => match[1].replaceAll('""', '"')));
  let currentIdentity;
  const identity = () => {
    if (currentIdentity) return currentIdentity;
    const whoami = "C:\\Windows\\System32\\whoami.exe";
    const user = csv(run(whoami, ["/user", "/fo", "csv", "/nh"]));
    const groups = csv(run(whoami, ["/groups", "/fo", "csv", "/nh"]));
    const sid = user[0]?.find((value) => /^S-1-(?:[0-9]+-)*[0-9]+$/.test(value));
    const label = groups.flat().filter((value) => /^S-1-16-[0-9]+$/.test(value));
    if (!sid || label.length !== 1) throw new Error("Current token identity is unavailable.");
    const integrityRid = Number(label[0].slice("S-1-16-".length));
    currentIdentity = { sid, integrityRid, elevated: integrityRid >= 12288 ? true : integrityRid === 8192 ? false : null,
      principals: groups.flatMap((row) => [row[0], row.find((value) => /^S-1-/.test(value))]).filter(Boolean) };
    return currentIdentity;
  };
  const escape = (value) => String(value).replaceAll("&", "&amp;").replaceAll("<", "&lt;").replaceAll(">", "&gt;").replaceAll('"', "&quot;");
  const windows = (mode, data) => {
    const request = { ...data, mode, sid: identity().sid };
    const xml = "<request>" + Object.entries(request).map(([key, value]) => "<" + key + ">" + (Array.isArray(value) ? value.map((item) => "<item>" + escape(item) + "</item>").join("") : escape(value)) + "</" + key + ">").join("") + "</request>";
    return JSON.parse(run(cscriptPath, ["//NoLogo", "//B", "//U", script], Buffer.from(xml, "utf16le"), "utf16le"));
  };
  return {
    presence: metadataOnly,
    repository(root) {
      if (metadataOnly(root) !== "directory") throw new Error("Unsafe repository path.");
      const commit = git(root, ["rev-parse", "HEAD"]);
      if (!/^[a-f0-9]{40}$/.test(commit)) throw new Error("Unsupported Git object ID.");
      const paths = git(root, ["ls-tree", "-r", "--name-only", "-z", commit]).split("\0").filter(Boolean);
      const indexed = git(root, ["ls-files", "--cached", "-z"]).split("\0").filter(Boolean);
      // Refuse before git status can hash a tracked private/state file.
      const unsafe = [...paths, ...indexed].some(privatePath);
      const configKeys = git(root, ["config", "--name-only", "--list"]).split(/\r?\n/);
      const externalFilters = configKeys.some((key) => /^filter\..*\.(clean|process)$/i.test(key));
      const status = unsafe || externalFilters ? "unsafe-tracked-path-or-external-filter" : git(root, ["status", "--porcelain=v1", "--untracked-files=all"]);
      const rawOrigin = git(root, ["remote", "get-url", "origin"]);
      const validOrigin = /^https:\/\/github\.com\/[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+$/.test(rawOrigin) || /^git@github\.com:[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+$/.test(rawOrigin);
      const manifest = JSON.parse(git(root, ["show", `${commit}:package.json`]));
      const required = ["package-lock.json", "bin/hostgate.js", "src/server.js", "src/service-manager.js", "src/managed-common.js", "src/supervisor.js", "src/managed-child.js", "src/windows-manager.ps1"];
      return { commit, branch: git(root, ["branch", "--show-current"]), origin: validOrigin ? rawOrigin : null,
        clean: status === "", statusFingerprint: sha(status), unsafeTrackedPaths: unsafe, externalFiltersConfigured: externalFilters,
        requiredFiles: required.every((file) => paths.includes(file)), compatible: manifest.name === "hostgate" && manifest.hostgateManagerApi === 1,
        remoteHeadChecked: false };
    },
    runtime(filename) {
      if (path.win32.basename(filename).toLowerCase() !== "node.exe") throw new Error("Unexpected runtime.");
      const state = metadataOnly(filename);
      return { state, ...(state === "file" ? { sha256: sha(publicBytes(filename, 268435456)) } : {}) };
    },
    npm(filename, nodeVersion) {
      if (path.win32.basename(filename).toLowerCase() !== "npm-cli.js" || path.win32.basename(path.win32.dirname(filename)).toLowerCase() !== "bin") throw new Error("Unexpected npm path.");
      const manifestPath = path.win32.join(path.win32.dirname(filename), "..", "package.json");
      const bytes = publicBytes(manifestPath, 1048576);
      const manifest = JSON.parse(bytes);
      const valid = manifest.name === "npm" && /^\d+\.\d+\.\d+(?:-[A-Za-z0-9.-]+)?$/.test(manifest.version || "");
      return { found: true, valid, version: valid ? manifest.version : null,
        runtimeCompatible: valid ? supportsNode(manifest.engines?.node, nodeVersion) : false,
        cliSha256: sha(publicBytes(filename, 1048576)), manifestSha256: sha(bytes), executed: false };
    },
    windowsInspect(directory) {
      let ancestor = directory;
      while (metadataOnly(ancestor) === "absent") {
        const parent = path.win32.dirname(ancestor);
        if (parent === ancestor) throw new Error("Directory ancestor unavailable.");
        ancestor = parent;
      }
      if (metadataOnly(ancestor) !== "directory") throw new Error("Unsafe directory ancestor.");
      const account = identity();
      const observed = windows("inspect", { ancestor, principals: account.principals });
      const { descriptorHex, ...acl } = observed.acl;
      return { ...observed, sid: account.sid, elevated: account.elevated, integrityRid: account.integrityRid,
        acl: { ...acl, ...(descriptorHex ? { descriptorSha256: sha(descriptorHex) } : {}) } };
    },
    validateTask(task) {
      if (task.sid !== identity().sid) throw new Error("Task account mismatch.");
      const { xml, ...fields } = task;
      return windows("validate", { ...fields, taskXml: xml });
    }
  };
}
