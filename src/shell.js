import { statSync } from "node:fs";
import { spawn } from "node:child_process";
import os from "node:os";
import path from "node:path";
import process from "node:process";

function environmentValue(env, name, platform) {
  if (platform !== "win32") {
    return env[name];
  }
  const key = Object.keys(env).find((key) => key.toLowerCase() === name.toLowerCase());
  return key === undefined ? undefined : env[key];
}

export function shellEnvironment(platform = process.platform, env = process.env, home = os.homedir()) {
  const childEnv = {
    PATH: environmentValue(env, "PATH", platform) || (platform === "win32" ? "" : "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"),
    HOME: home,
    LANG: environmentValue(env, "LANG", platform) || "C.UTF-8"
  };

  if (platform === "win32") {
    // Keep Windows runtime essentials without inheriting OAuth credentials or arbitrary secrets.
    for (const key of [
      "SystemRoot", "WINDIR", "ComSpec", "PATHEXT", "TEMP", "TMP",
      "APPDATA", "LOCALAPPDATA", "HOMEDRIVE", "HOMEPATH", "USERNAME", "USERDOMAIN",
      "ProgramFiles", "ProgramFiles(x86)", "ProgramW6432", "ProgramData", "PSModulePath"
    ]) {
      const value = environmentValue(env, key, platform);
      if (value !== undefined) {
        childEnv[key] = value;
      }
    }
    childEnv.SystemRoot ||= childEnv.WINDIR || "C:\\Windows";
    childEnv.WINDIR ||= childEnv.SystemRoot;
    childEnv.USERPROFILE = home;
    childEnv.ComSpec ||= path.win32.join(childEnv.SystemRoot, "System32", "cmd.exe");
    childEnv.PATHEXT ||= ".COM;.EXE;.BAT;.CMD";
  }
  return childEnv;
}

export function shellCommand(command, platform = process.platform, env = process.env) {
  if (platform === "win32") {
    const systemRoot = environmentValue(env, "SystemRoot", platform) || environmentValue(env, "WINDIR", platform) || "C:\\Windows";
    // EncodedCommand preserves quotes, newlines and Unicode without a second cmd.exe parser.
    // Encoding is only argument transport; it is not encryption or a security boundary.
    const script = "[Console]::OutputEncoding = [System.Text.UTF8Encoding]::new($false);\n" +
      "$OutputEncoding = [Console]::OutputEncoding;\n" + command;
    return {
      cmd: path.win32.join(systemRoot, "System32", "WindowsPowerShell", "v1.0", "powershell.exe"),
      args: ["-NoLogo", "-NoProfile", "-NonInteractive", "-OutputFormat", "Text", "-EncodedCommand", Buffer.from(script, "utf16le").toString("base64")]
    };
  }
  return { cmd: "/bin/bash", args: ["-lc", command] };
}

export function runShell(command, options = {}) {
  const cwd = options.cwd === undefined ? os.homedir() : path.resolve(os.homedir(), options.cwd);
  if (!statSync(cwd).isDirectory()) throw new Error("Shell working directory must exist.");
  // Reassert an explicit cwd after Linux login profiles, without changing parent state.
  const script = options.cwd !== undefined && process.platform !== "win32" ? "cd -- '" + cwd.replaceAll("'", "'\"'\"'") + "' || exit;\n" + command : command;
  const spec = shellCommand(script);
  return new Promise((resolve) => {
    const child = spawn(spec.cmd, spec.args, {
      cwd,
      env: shellEnvironment(),
      shell: false,
      windowsHide: true,
      stdio: ["ignore", "pipe", "pipe"]
    });

    let stdout = "";
    let stderr = "";
    child.stdout.setEncoding("utf8");
    child.stderr.setEncoding("utf8");
    child.stdout.on("data", (chunk) => { stdout += chunk; });
    child.stderr.on("data", (chunk) => { stderr += chunk; });
    child.once("error", (error) => {
      resolve({ ...(options.cwd === undefined ? {} : { cwd, pid: child.pid ?? null }), exitCode: null, signal: null, stdout, stderr: `${stderr}\n${error.message}`.trim() });
    });
    child.once("close", (exitCode, signal) => {
      resolve({ ...(options.cwd === undefined ? {} : { cwd, pid: child.pid ?? null }), exitCode, signal, stdout, stderr });
    });
  });
}
