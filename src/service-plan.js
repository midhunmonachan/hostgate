// A plan is data, never an installer invocation. No environment reader or mutable
// manager module is imported here. The probe interface contains only observations.
import crypto from "node:crypto";
import path from "node:path";

export const PLAN_VERSION = 1;
export const PLAN_WARNING = "Hostgate is not a sandbox. The four tools retain full authorized OS-account capability. Shell and write remain potentially destructive; this plan does not suppress their warnings or override platform safeguards.";
const HELP = `Usage: hostgate service plan [--json] [--environment-source stdin|saved-file|launcher]
       [--npm-cli ABSOLUTE_PATH] [--expect FULL_COMMIT]
       [--git-path ABSOLUTE_PATH] [--cscript-path ABSOLUTE_PATH]

service prepare is an alias for the same READ-ONLY planner, not a release build.
No stdin/environment values, saved credentials, or OAuth state are read.
No files, ACLs, tasks, processes, or production configuration are changed.
The approval token fingerprints this non-secret plan; it cannot authorize activation.
Exit 0: observed checks pass (unverified items remain); 1: blockers; 2: bad arguments.`;

export function localWindowsPath(value) {
  if (typeof value !== "string" || !/^[A-Za-z]:[\\/]/.test(value) ||
      /[\u0000-\u001f\u007f"<>|?*%!]/.test(value) || value.slice(2).includes(":")) {
    throw new Error("Use an absolute local Windows path without control characters, wildcard, device, or expansion syntax.");
  }
  const result = path.win32.normalize(value);
  if (result.slice(3).split("\\").some((part) => /[ .]$/.test(part) || /^(con|prn|aux|nul|com[1-9]|lpt[1-9])(?:\.|$)/i.test(part))) {
    throw new Error("Unsupported Windows path component.");
  }
  return result;
}

export function parsePlanArgs(args) {
  const options = { json: false, help: false, environmentSource: "stdin", npmCli: null, expectedCommit: null, gitPath: null, cscriptPath: null };
  const seen = new Set();
  for (let i = 0; i < args.length; i++) {
    const flag = args[i];
    if (seen.has(flag)) throw new Error("Duplicate plan option.");
    seen.add(flag);
    if (flag === "--json") options.json = true;
    else if (flag === "--help" || flag === "-h") options.help = true;
    else if (flag === "--environment-source") {
      const value = args[++i];
      if (!["stdin", "saved-file", "launcher"].includes(value)) throw new Error("Choose environment source stdin, saved-file, or launcher. No values are inspected.");
      options.environmentSource = value;
    } else if (flag === "--expect") {
      const value = args[++i];
      if (typeof value !== "string" || !/^[a-f0-9]{40}$/.test(value)) throw new Error("--expect requires a full lowercase commit hash.");
      options.expectedCommit = value;
    } else if (["--npm-cli", "--git-path", "--cscript-path"].includes(flag)) {
      const value = localWindowsPath(args[++i]);
      const names = { "--npm-cli": ["npmCli", "npm-cli.js"], "--git-path": ["gitPath", "git.exe"], "--cscript-path": ["cscriptPath", "cscript.exe"] };
      const [key, basename] = names[flag];
      if (path.win32.basename(value).toLowerCase() !== basename) throw new Error("The specified planner executable/CLI filename is not supported.");
      options[key] = value;
    } else throw new Error("Unknown plan option. Use service plan --help. Installation, import, adoption, approval, and apply options are not accepted here.");
  }
  return options;
}

function canonical(value) {
  if (Array.isArray(value)) return value.map(canonical);
  if (value && typeof value === "object") return Object.fromEntries(Object.keys(value).sort().map((key) => [key, canonical(value[key])]));
  return value;
}
export function approvalToken(plan) {
  return "hostgate-plan-v1:" + crypto.createHash("sha256").update(JSON.stringify(canonical(plan))).digest("hex");
}
const xmlEscape = (value) => String(value).replaceAll("&", "&amp;").replaceAll("<", "&lt;").replaceAll(">", "&gt;").replaceAll('"', "&quot;").replaceAll("'", "&apos;");

export function taskSpecification(directory, commit, sid) {
  directory = localWindowsPath(directory);
  if (!/^[a-f0-9]{40}$/.test(commit) || !/^S-1-(?:[0-9]+-)*[0-9]+$/.test(sid)) throw new Error("Task planning requires a verified commit and Windows SID.");
  const runtime = path.win32.join(directory, "runtime", commit);
  const executable = path.win32.join(runtime, "node.exe");
  const supervisor = path.win32.join(runtime, "supervisor.js");
  const args = `"${supervisor}" "${directory}"`;
  const name = "Hostgate-" + crypto.createHash("sha256").update(sid).digest("hex").slice(0, 12);
  // This describes the existing installer, including its enabled logon trigger.
  // Validation-only MUST NOT be confused with creating a disabled/inert task.
  const xml = `<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <RegistrationInfo><Description>Hostgate user-logon supervisor; full authorized OS-account capability.</Description></RegistrationInfo>
  <Triggers><LogonTrigger><Enabled>true</Enabled><UserId>${xmlEscape(sid)}</UserId><Delay>PT5S</Delay></LogonTrigger></Triggers>
  <Principals><Principal id="HostgateUser"><UserId>${xmlEscape(sid)}</UserId><LogonType>InteractiveToken</LogonType><RunLevel>LeastPrivilege</RunLevel></Principal></Principals>
  <Settings><MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy><DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries><StopIfGoingOnBatteries>false</StopIfGoingOnBatteries><StartWhenAvailable>true</StartWhenAvailable><Enabled>true</Enabled><ExecutionTimeLimit>PT0S</ExecutionTimeLimit><RestartOnFailure><Interval>PT1M</Interval><Count>999</Count></RestartOnFailure></Settings>
  <Actions Context="HostgateUser"><Exec><Command>${xmlEscape(executable)}</Command><Arguments>${xmlEscape(args)}</Arguments><WorkingDirectory>${xmlEscape(directory)}</WorkingDirectory></Exec></Actions>
</Task>`;
  return { name, sid, executable, supervisor, arguments: args, directory, xml };
}

export function collectInstallPlan(options, context, probes) {
  const checks = [];
  const check = (id, status, message) => checks.push({ id, status, message });
  const plan = { schemaVersion: PLAN_VERSION, operation: "windows-service-install-plan", readOnly: true, warning: PLAN_WARNING,
    environmentSource: { selected: options.environmentSource, valuesRead: false, stdinConsumed: false, credentialValidity: "not-verified", provenance: "not-verified" },
    effectsPerformed: [], checks,
    futureEffectsRequiringSeparateApproval: ["Import the original launcher environment (including any other secrets it contains).", "Create private directories and change their ACLs; copy a Node runtime and manager files.", "Clone a release, install dependencies, and execute its tests.", "Save current-user DPAPI ciphertext, a deployment manifest, and launchers.", "Register an enabled user-logon task and start the supervisor.", "Verify and stop the selected original PID, launch production, and verify or recover it."],
    unresolved: ["Environment values, live-environment equality, and existing-token authentication are not checked.", "No PID is inspected/adopted and no port ownership or production binding is verified.", "ACL feasibility is advisory; no write or effective-access test is performed.", "DPAPI availability is not proof of encryption/decryption or reboot recovery.", "Task XML validation is not registration permission or proof of task execution.", "Initial-adoption rollback and partial-install recovery remain limitations of the existing installer."] };
  const finish = () => ({ plan, approvalToken: approvalToken(plan), tokenPurpose: "Stable non-secret review fingerprint only. Not human consent, an OAuth token, or platform approval. No installer consumes it; it cannot authorize or queue any action.", exitCode: checks.some((item) => item.status === "blocked") ? 1 : 0 });
  if (context.platform !== "win32") { check("platform", "blocked", "Service installation planning supports Windows. Linux startup is unchanged."); return finish(); }
  const root = localWindowsPath(context.repoRoot);
  const home = localWindowsPath(context.home);
  const nodePath = localWindowsPath(context.nodePath);
  const directory = path.win32.join(home, ".config", "hostgate", "managed");
  plan.paths = { repository: root, destination: directory };
  let repo;
  try { repo = probes.repository(root); plan.repository = repo; }
  catch { check("repository", "blocked", "Cannot verify local Git metadata; no Git changes or network fetch were attempted."); }
  if (repo) {
    check("repository", repo.branch === "main" && repo.clean && repo.requiredFiles && repo.compatible ? "ok" : "blocked", "Require main, a clean tracked/untracked tree, required source/lockfile, and manager API 1.");
    check("commit", !options.expectedCommit || options.expectedCommit === repo.commit ? "ok" : "blocked", "The selected commit must match --expect when supplied.");
    check("origin", repo.origin ? "ok" : "blocked", "Require a credential-free GitHub origin. Remote HEAD is deliberately not contacted.");
  }
  try {
    plan.runtime = { path: nodePath, version: context.nodeVersion, ...probes.runtime(nodePath) };
    check("runtime", Number(context.nodeVersion.split(".")[0]) >= 22 && plan.runtime.state === "file" ? "ok" : "blocked", "Check the current Node runtime (22+) without launching another executable.");
  } catch { check("runtime", "blocked", "The current runtime could not be inspected."); }
  const candidates = options.npmCli ? [options.npmCli] : [path.win32.join(path.win32.dirname(nodePath), "node_modules", "npm", "bin", "npm-cli.js"), path.win32.join(directory, "tools", "npm", "package", "bin", "npm-cli.js")];
  try {
    const selected = candidates.find((file) => probes.presence(file) === "file");
    plan.npm = selected ? { path: selected, ...probes.npm(selected, context.nodeVersion) } : { found: false };
    check("npm", plan.npm.valid && plan.npm.runtimeCompatible === true ? "ok" : "blocked", "Inspect npm CLI/package metadata and Node engine compatibility only. Supply --npm-cli if it is not beside Node; npm is never executed.");
  } catch { check("npm", "blocked", "npm metadata is unavailable or invalid; no package command was run."); }
  const observed = {};
  for (const [name, filename] of Object.entries({ directory, manifest: path.win32.join(directory, "deployment.json"), encryptedStore: path.win32.join(directory, "environment.dpapi"), launcher: path.win32.join(directory, "hostgate.cmd"), userEnv: path.win32.join(home, ".config", "hostgate", ".env"), repositoryEnv: path.win32.join(root, ".env") })) {
    try { observed[name] = probes.presence(filename); } catch { observed[name] = "inaccessible"; }
  }
  plan.pathStates = observed;
  check("destination", observed.directory === "absent" && [observed.manifest, observed.encryptedStore, observed.launcher].every((state) => state === "absent") ? "ok" : "blocked", "A fresh installation requires an absent managed destination. Existing, linked, partial, or inaccessible paths require review; nothing is overwritten.");
  const savedSource = observed.userEnv === "file" ? "user-file" : observed.userEnv === "absent" && observed.repositoryEnv === "file" ? "repository-file" : null;
  plan.environmentSource.availability = options.environmentSource === "saved-file" ? (savedSource || "not-found-or-unsafe") : "operator-input-not-inspected";
  check("environment-source", options.environmentSource === "saved-file" && !savedSource ? "blocked" : "unverified", options.environmentSource === "saved-file" ? "Only saved-file existence/type is inspected, never its contents or credentials." : "Input must later come from the original authorized launcher; stdin and launcher variables are not read or enumerated.");
  let platform;
  try { platform = probes.windowsInspect(directory); plan.windows = platform; }
  catch { check("windows", "blocked", "Read-only Windows metadata inspection was unavailable. No fallback to a mutable adapter was attempted."); }
  if (platform) {
    check("account", platform.elevated === false && /^S-1-(?:[0-9]+-)*[0-9]+$/.test(platform.sid || "") ? "ok" : "blocked", "The planned task retains the current, non-elevated Windows account.");
    check("encrypted-store", platform.dpapiAvailable === true ? "ok" : "blocked", "Check native DPAPI library presence only; encryption and decryption are never invoked.");
    check("acl", platform.acl?.readable && platform.acl.createChildIndicated ? "unverified" : "blocked", "Read the nearest existing directory ACL and assess indicative child-creation rights. Effective write/change-permission feasibility is not exercised.");
    if (repo?.commit && platform.sid) {
      try {
        const task = taskSpecification(directory, repo.commit, platform.sid);
        plan.task = { ...task, validation: probes.validateTask(task), commandExecuted: false, registered: false };
        check("task", plan.task.validation.xmlValid === true && plan.task.validation.commandMatches === true && plan.task.validation.existingTask === false ? "ok" : "blocked", "Validate exact task XML/command using TASK_VALIDATE_ONLY (1), and check name availability. Never register, update, disable, or run a task.");
      } catch { check("task", "blocked", "Task syntax/command validation was unavailable. No task registration was attempted."); }
    }
  }
  return finish();
}

export function formatInstallPlan(report) {
  const p = report.plan;
  return ["Hostgate Windows installation PLAN ONLY", p.warning, "", ...p.checks.map((c) => `${c.status.toUpperCase()}: ${c.id} - ${c.message}`), "",
    ...(p.repository ? [`Commit: ${p.repository.commit}`, `Source: ${p.paths.repository}`] : []), ...(p.paths ? [`Proposed destination: ${p.paths.destination}`] : []),
    ...(p.task ? [`Proposed task: ${p.task.name}`, `Executable (not run): ${p.task.executable}`, `Arguments: ${p.task.arguments}`, `Working directory: ${p.task.directory}`, "Proposed XML (validated only):", p.task.xml] : []),
    "", "Future effects, NOT performed or authorized by this token:", ...p.futureEffectsRequiringSeparateApproval.map((s) => `  ${s}`), "", ...p.unresolved,
    "", `Approval token: ${report.approvalToken}`, report.tokenPurpose, "No installation or activation ran. No values were imported and no files/tasks were created."].join("\n");
}

export async function servicePlanCli(args, repoRoot) {
  let options;
  try { options = parsePlanArgs(args); } catch (error) { console.error(error.message); return 2; }
  if (options.help) { console.log(HELP); return 0; }
  try {
    const { planContext, createPlanProbes } = await import("./plan-probes.js");
    const context = planContext(repoRoot);
    const report = collectInstallPlan(options, context, createPlanProbes(context, options));
    console.log(options.json ? JSON.stringify(report, null, 2) : formatInstallPlan(report));
    return report.exitCode;
  } catch { console.error("Installation plan could not be inspected. No installation was attempted; no private values are shown."); return 1; }
}
