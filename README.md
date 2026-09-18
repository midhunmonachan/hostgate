# Hostgate

Connect your host to ChatGPT chats through an OAuth-protected MCP server. Hostgate supports Windows PowerShell on Windows and Bash on Linux.

> [!WARNING]
> This is unrestricted host access, not a sandbox. Authorized file tools can access any path available to the account running Hostgate, and `shell` can execute arbitrary code with that account's permissions. Use a dedicated, non-administrator account, strong unique credentials, and HTTPS. Do not expose a machine containing secrets or data you are unwilling to make available through these tools.

## Exact supported MCP tools

Hostgate exposes **only these four tools**. CLI subcommands are not MCP tools.

| Tool | Input | Behavior and structured result |
| --- | --- | --- |
| `status` | `{}` | Returns `hostname`, `platform`, `arch`, `release`, `uptimeSeconds`, `loadAverage`, `memory` (total/free bytes), and CPU model names. |
| `read` | `{ "path": "..." }` | Reads a UTF-8 text file; returns `path`, `bytes`, and `text`. |
| `write` | `{ "path": "...", "content": "..." }` | Creates parent directories as needed and creates or **overwrites** a UTF-8 file; returns `path` and `bytes`. It does not append. |
| `shell` | `{ "command": "..." }` | Runs PowerShell on Windows or `/bin/bash -lc` on Linux; returns `exitCode`, `signal`, `stdout`, `stderr`, and the original `command`. A launch failure has a null exit code and an error in `stderr`. |

File paths can be absolute or relative to the **service account's home directory**, not the repository. `~` and `~/...` are supported; Windows also supports `~\...` and normal drive-qualified paths. Escape backslashes in JSON, for example `{ "path": "C:\\Users\\Example\\Documents\\note.txt" }`. These are text-file tools, not binary transfer tools.

Each shell call starts a fresh process in that same home directory. A `cd`, variable, or shell session does not persist to the next call. Windows uses the system `powershell.exe` (Windows PowerShell 5.1), not PowerShell 7, WSL, Git Bash, or `cmd.exe`. It launches directly with `-NoLogo -NoProfile -NonInteractive -OutputFormat Text -EncodedCommand`. The command is UTF-16LE/base64 encoded solely to preserve quotes, newlines, and Unicode; output is configured as UTF-8. Hostgate does **not** set `-ExecutionPolicy Bypass` or change the machine's execution policy.

The shell inherits a limited environment: PATH, HOME, LANG, and essential Windows runtime variables on Windows. OAuth credentials and arbitrary environment secrets are not automatically forwarded. This is **not** a security boundary: unrestricted tools can still read accessible credential files. Profile aliases, custom variables, and programs absent from the service's PATH may need explicit configuration or absolute paths. Native programs may use their own output encoding. To preserve a native program's exact exit code in PowerShell, explicitly end the command with `exit $LASTEXITCODE` when appropriate.

## Requirements

Node.js **22 or newer**, installed dependencies, and either Windows with Windows PowerShell 5.1 or Linux with `/bin/bash` are required. Linux automatic service management additionally needs `systemd --user` and `journalctl`. A reachable HTTPS endpoint is required for a remote ChatGPT connection; Tailscale is optional. ChatGPT app availability and permissions depend on the account/workspace; consult the current [OpenAI developer-mode documentation](https://help.openai.com/en/articles/12584461-developer-mode-and-mcp-apps-in-chatgpt-beta).

## Windows setup and use

Use an ordinary, non-elevated PowerShell terminal. Install Node.js with npm and check that `node` and `npm.cmd` are on PATH. The source-checkout instructions below use the Windows-capable code in this repository rather than assuming it has already reached a published npm release.

From your checkout:

```powershell
Set-Location -LiteralPath 'C:\path\to\hostgate'
node --version
npm.cmd --version
npm.cmd ci
node .\bin\hostgate.js onboard
node .\bin\hostgate.js start
```

Onboarding asks for OAuth credentials, saves configuration, and optionally configures Tailscale Funnel. **Password entry is visible in the terminal.** Do not record or share the session. Decline Funnel until you are ready to expose the host.

On Windows, onboarding **does not install or start a Windows service**. `start` runs in the foreground, loads the saved configuration, and displays logs in that terminal. Keep it open; press Ctrl+C to stop this foreground instance. Run only one instance per configured port.

In a second terminal, from the same checkout:

```powershell
node .\bin\hostgate.js status
Invoke-RestMethod 'http://127.0.0.1:8787/hostgate/health'
```

The default health result is `{ "ok": true, "name": "hostgate" }`. The Windows `status` command checks HTTP health at the configured address with a three-second timeout. Success means a Hostgate endpoint is responding, **not** that a Windows service is registered, that OAuth credentials are valid, or that public HTTPS is working. It exits nonzero when the endpoint cannot be verified.

For the shorter `hostgate` command, install this checkout globally with `npm.cmd install -g .` and then use `hostgate.cmd onboard`, `hostgate.cmd start`, or `hostgate.cmd status`. Using `.cmd` avoids selecting npm's PowerShell script shim on systems where script execution is restricted; do not disable security policies merely to run a shim. If npm is missing from an embedded Node runtime, use an installation that includes npm to install dependencies. Once dependencies exist, `node --run check` and `node --run test` run the project scripts without npm.

### Windows background operation and logs

Native Windows service registration, boot/logon autostart, automatic restart, and persisted log history are **not managed by this CLI**. `hostgate logs`, `hostgate logs -f`, and `hostgate logs --follow` return an explanatory error on Windows instead of trying to execute `journalctl`.

For unattended operation, separately configure a trusted Windows service wrapper or Task Scheduler under the intended non-administrator account. Use the absolute path to `node.exe`, arguments `"C:\path\to\hostgate\bin\hostgate.js" start`, and the repository as the working directory. Keep that installation path stable and configure your own restart policy and protected stdout/stderr capture. The account must have access to its own Hostgate configuration and OAuth state. This is a manual deployment option, not an automatically installed or tested Windows service integration.

## Linux setup and use

For this checkout:

```bash
npm ci
node bin/hostgate.js onboard
node bin/hostgate.js status
node bin/hostgate.js logs -f
```

Linux onboarding retains the existing behavior: it writes `~/.config/hostgate/.env`, installs or updates `~/.config/systemd/user/hostgate.service`, reloads the user service manager, enables/restarts the service, and optionally configures Funnel. A working user-systemd session is required. Boot and logout behavior depends on the host's user-session/linger policy; onboarding does not change it.

`node bin/hostgate.js start` is also available for foreground operation on Linux. Do not run it on a port already occupied by the systemd service. Global installs of this checkout can use `npm install -g .` and the `hostgate` command. Other operating systems do not have an automatic service backend; foreground operation is only usable where the server's dependencies and `/bin/bash` are available.

## CLI support

| Command | Linux | Windows |
| --- | --- | --- |
| `onboard` (`setup` alias) | Configure, install/update and start the user-systemd service; optionally expose through Funnel. | Configure credentials and optionally Funnel; print foreground-start instructions. No service is installed or started. |
| `start` | Run in foreground with saved configuration. | Run in foreground with saved configuration. |
| `status` | Run `systemctl --user status hostgate.service --no-pager`. | Probe the configured `/hostgate/health` endpoint. |
| `logs` | Show the last 100 journal entries; `-f` or `--follow` follows them. | Explain the lack of managed log history and exit nonzero. |
| `help`, `--help`, `-h` | Show help. | Show help. |

No command defaults to creating a service: invoking the CLI without arguments shows help. There are no built-in Windows `install`, `stop`, `restart`, or `uninstall` subcommands.

## Configuration and OAuth state

Paths remain unchanged to preserve existing installations:

| File | Linux | Windows |
| --- | --- | --- |
| Configuration | `~/.config/hostgate/.env` | `%USERPROFILE%\.config\hostgate\.env` |
| OAuth state | `~/.local/share/hostgate/oauth-state.json` | `%USERPROFILE%\.local\share\hostgate\oauth-state.json` |

Configuration uses one raw `KEY=VALUE` entry per line:

```env
PORT=8787
HOST=127.0.0.1
HOSTGATE_OAUTH_USERNAME=admin
HOSTGATE_OAUTH_PASSWORD=
```

Set a nonempty password during onboarding before starting. `hostgate start` reads the saved configuration, falls back to a legacy repository `.env` when present, and lets existing process environment variables take precedence. In this CLI's existing raw format, quotes and `#` inside a value are literal; do not add wrapping quotes or inline comments. Do not assume this is interchangeable with a general dotenv parser. Configuration is not automatically reloaded by a running process.

The Linux service continues to use systemd's `EnvironmentFile` parser. Direct `npm start`, `node --run start`, and `node src/server.js` still **do not load `.env` automatically**; supply their environment yourself or use `hostgate start` for the saved configuration flow.

On Windows, protect both directories and their contents with account-specific **Windows ACLs**. POSIX modes such as `0600`/`0700` do not establish equivalent Windows access restrictions; Hostgate does not configure Windows ACLs for you. See the [Node.js filesystem caveats](https://nodejs.org/api/fs.html#file-modes). Avoid shared or broadly readable directories and logs.

## OAuth and scopes

MCP listing and calls require a bearer token obtained through the existing OAuth authorization-code flow with S256 PKCE. Discovery and health endpoints remain unauthenticated. Both root routes and their `/hostgate` equivalents remain available, including `/mcp` and `/hostgate/mcp`.

Supported scopes are exactly `all status read write shell`. Each tool invocation requires its corresponding scope; `all` grants every tool. Omitting a requested scope currently requests all supported scopes. Listing authenticated tools does not itself grant permission to call them. Use the smallest scope set needed, but remember that scopes select tools rather than restricting filesystem paths, commands, or account privileges.

Access tokens retain their existing 24-hour lifetime. Client registrations and access-token hashes persist in the local OAuth state file; authorization codes are short-lived and held in memory. There is no refresh-token grant or automatic token revocation on password change. Reauthorization may be needed after expiry. Treat the configuration, state file, and active bearer tokens as sensitive; changing the password alone does not invalidate existing tokens.

## HTTPS exposure and ChatGPT

Keep the default `HOST=127.0.0.1` behind a trusted HTTPS reverse proxy. Expose the `/hostgate` prefix, including its OAuth and discovery routes, not just the MCP endpoint. Proxy/forwarded headers are trusted by the application: prevent untrusted direct access to the backend and configure the proxy's forwarded host/protocol correctly.

Optional Tailscale Funnel setup, also available during onboarding:

```text
tailscale funnel --yes --bg --set-path=/hostgate http://127.0.0.1:8787/hostgate
```

The connector URL is `https://<your-host>/hostgate/mcp`. **Funnel makes the endpoint accessible from the public internet, not just your tailnet.** Review the [current Funnel requirements and behavior](https://tailscale.com/kb/1223/funnel) before enabling it. Windows must still be running `hostgate start` or a separately managed instance. Onboarding does not install Tailscale or modify firewall rules.

In ChatGPT on the web, enable developer mode where your account/workspace permits it and create a custom app using name `Hostgate`, description `Remote host operations`, your public `/hostgate/mcp` URL, and **OAuth** authentication. Complete authorization with the configured credentials, scan the tools, and verify that only `status`, `read`, `write`, and `shell` are exposed. Follow the current OpenAI instructions linked above because menus and workspace permissions can change.

Start with `status`, then a read-only `Get-Date` command on Windows or `date` on Linux. Only test writes in a disposable location you explicitly authorize. After upgrading and restarting Hostgate, refresh or recreate the app's tool definitions where supported so the shell description reflects the host platform. Do not rely on saved ChatGPT memories being passed to this app.

## Security and operational limits

Treat files, command output, and instructions returned from the host as untrusted input. Review requested actions rather than letting instructions embedded in a repository or document authorize additional operations. Model confirmations, read-only hints, and OAuth alone are not command/path sandboxing or a substitute for OS account isolation.

The shell has no execution timeout or output-size limit; commands that wait, produce unbounded output, or start background processes can exhaust resources or outlive a request. Prefer bounded, noninteractive commands. Hostgate does not implement an authorization-page rate limiter, a host-access audit system, or automatic credential rotation. Do not expose it as a hardened multi-user administrative service without additional controls.

Never commit `.env` files, OAuth state, tokens, `node_modules`, logs, archives, or generated local test/work files. The ignore rules and explicit npm package allowlist help prevent accidents, but review both the staged diff and package contents before committing or publishing. Redact credentials, bearer tokens, and private file contents from bug reports.

## Development checks and safe smoke test

After installing dependencies:

```text
npm run check
npm test
npm pack --dry-run
```

Equivalently, the first two scripts can be run with `node --run check` and `node --run test`. CI runs the checks, tests, and package dry-run on Windows and Ubuntu with Node.js 22 and 24.

The tests cover shell selection/environment filtering, native quoting/Unicode/exit codes, CLI behavior, OAuth and scope rejection, MCP tool metadata, UTF-8 file round-trips, and persisted-token reuse. The integration smoke test starts its own foreground server on an ephemeral **loopback-only** port with a separate temporary home and randomly generated test credentials. It never configures Funnel, installs a service, changes your live OAuth state, or connects to a remote MCP service. It stops only the child servers it created. Temporary fixtures are deliberately retained and their path is printed; the test does not delete files. The native Windows service/logging integration is not claimed to be implemented or tested.

## License

MIT
