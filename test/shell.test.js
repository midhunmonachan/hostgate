import assert from "node:assert/strict";
import os from "node:os";
import test from "node:test";
import { runShell, shellCommand, shellEnvironment } from "../src/shell.js";

const isWindows = process.platform === "win32";

test("Linux retains /bin/bash -lc and the command unchanged", () => {
  const command = "printf '%s\\n' \"quotes & pipes |\"";
  assert.deepEqual(shellCommand(command, "linux", {}), { cmd: "/bin/bash", args: ["-lc", command] });
});

test("Windows launches PowerShell directly and preserves complex command text", () => {
  const command = "$value = 'caf\u00e9 & | \"quoted\"';\n$value | Write-Output";
  const spec = shellCommand(command, "win32", { systemroot: "D:\\Windows" });
  assert.equal(spec.cmd, "D:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe");
  assert.deepEqual(spec.args.slice(0, -1), ["-NoLogo", "-NoProfile", "-NonInteractive", "-OutputFormat", "Text", "-EncodedCommand"]);
  const script = Buffer.from(spec.args.at(-1), "base64").toString("utf16le");
  assert(script.endsWith(command));
  assert(script.includes("[Console]::OutputEncoding"));
  assert(!spec.args.includes("-ExecutionPolicy"));
});

test("Windows has a system PowerShell fallback without PATH or SystemRoot", () => {
  assert.equal(shellCommand("Get-Date", "win32", {}).cmd,
    "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe");
});

test("Linux keeps the original minimal environment and excludes credentials", () => {
  assert.deepEqual(shellEnvironment("linux", {
    PATH: "/tools/bin", LANG: "en_US.UTF-8", HOSTGATE_OAUTH_PASSWORD: "not-a-real-password"
  }, "/home/test"), { PATH: "/tools/bin", HOME: "/home/test", LANG: "en_US.UTF-8" });
  assert.equal(shellEnvironment("linux", {}, "/home/test").PATH,
    "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin");
});

test("Windows retains essential variables case-insensitively, but not arbitrary secrets", () => {
  const env = shellEnvironment("win32", {
    Path: "C:\\Tools", systemroot: "C:\\Windows", temp: "C:\\Temp",
    appdata: "C:\\Users\\Test\\AppData\\Roaming", psModulePath: "C:\\Modules",
    HOSTGATE_OAUTH_USERNAME: "smoke", HOSTGATE_OAUTH_PASSWORD: "not-a-real-password",
    GITHUB_TOKEN: "not-a-real-token", NODE_OPTIONS: "--inspect"
  }, "C:\\Users\\Test");
  assert.equal(env.PATH, "C:\\Tools");
  assert.equal(env.SystemRoot, "C:\\Windows");
  assert.equal(env.TEMP, "C:\\Temp");
  assert.equal(env.APPDATA, "C:\\Users\\Test\\AppData\\Roaming");
  assert.equal(env.PSModulePath, "C:\\Modules");
  assert.equal(env.USERPROFILE, "C:\\Users\\Test");
  assert.equal(env.HOME, env.USERPROFILE);
  assert.equal(env.ComSpec, "C:\\Windows\\System32\\cmd.exe");
  assert.equal(env.PATHEXT, ".COM;.EXE;.BAT;.CMD");
  for (const key of ["Path", "HOSTGATE_OAUTH_USERNAME", "HOSTGATE_OAUTH_PASSWORD", "GITHUB_TOKEN", "NODE_OPTIONS"]) {
    assert.equal(env[key], undefined);
  }
});

test("native shell runs a harmless command with pipes, quotes, and Unicode", { timeout: 15000 }, async () => {
  const expected = 'Hostgate caf\u00e9 \u2603 \ud83d\ude80 "quoted" & |';
  const command = isWindows
    ? `$value = '${expected}'; $value | ForEach-Object { $_ }`
    : `printf '%s\\n' '${expected}' | cat`;
  const result = await runShell(command);
  assert.equal(result.exitCode, 0, result.stderr);
  assert.equal(result.signal, null);
  assert.equal(result.stdout.trim(), expected);
  assert.equal(result.stderr, "");
});

test("native shell returns stderr and an explicit nonzero exit code", { timeout: 15000 }, async () => {
  const result = await runShell(isWindows
    ? "[Console]::Error.WriteLine('expected smoke error'); exit 7"
    : "printf 'expected smoke error\\n' >&2; exit 7");
  assert.equal(result.exitCode, 7);
  assert.match(result.stderr, /expected smoke error/);
});

test("native shell starts in the service user's home", { timeout: 15000 }, async () => {
  const result = await runShell(isWindows ? "(Get-Location).Path" : "pwd");
  assert.equal(result.exitCode, 0, result.stderr);
  assert.equal(result.stdout.trim(), os.homedir());
});
