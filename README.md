# Hostgate

Give ChatGPT controlled access to your computer

[Overview](#overview) • [Install](#install) • [Connect](#connect) • [Tools](#tools) • [Security](#security) • [FAQ](#faq)

---

## Overview

Hostgate is an OAuth-protected MCP server that lets ChatGPT inspect your computer, read and write text files, and run commands locally.

Works on Windows and Linux.

## Install

Requirements: Node.js 22+, npm, and an HTTPS endpoint that ChatGPT can reach.

### Windows

Open a normal PowerShell window:

```powershell
git clone https://github.com/midhunmonachan/hostgate.git
cd hostgate
npm.cmd ci
node .\bin\hostgate.js onboard
node .\bin\hostgate.js service install --yes
```

The Windows installer validates a separate release, saves the existing configured environment with current-user DPAPI encryption, and registers a user-logon task. You can close the setup terminal after `service status` confirms it is running. For foreground-only operation instead, use `node .\bin\hostgate.js start` and keep that terminal open. Do not install over an unidentified running instance.

### Linux

```bash
git clone https://github.com/midhunmonachan/hostgate.git
cd hostgate
npm ci
node bin/hostgate.js onboard
```

Linux onboarding starts a user-level systemd service. Check it with:

```bash
node bin/hostgate.js status
node bin/hostgate.js logs -f
```

During onboarding, choose a Hostgate username and a strong password. Keep both private.

## Check my setup

From the checkout, run this in a second terminal on Windows or Linux:

```text
node bin/hostgate.js doctor
```

It reports **OK**, **NEEDS ATTENTION**, or **NOT VERIFIED**, with a next step for each issue. It checks Node.js, required package entry points, npm on PATH, the command shell, saved restart credentials, local health, and an existing matching Tailscale Funnel route. It never installs anything or applies fixes.

**Running is not the same as restart-ready.** A healthy server can still lack saved configuration. Do not stop a working server or replace its credentials just because this check finds missing restart settings. On Windows, foreground-only operation still needs its terminal; managed operation reports its encrypted settings, running process, verified launch, and logon task separately. On Linux, doctor also checks whether the user service is active, without changing it.

For another existing HTTPS deployment, supply its connection URL explicitly:

```text
node bin/hostgate.js doctor --url https://your-host/hostgate/mcp
node bin/hostgate.js doctor --json
```

The HTTPS check uses unauthenticated GET requests for health, OAuth discovery, and the MCP authentication challenge. It rejects redirects, credential-bearing URLs, and invalid certificates. Automatic discovery only recognizes a single public Funnel `/hostgate` mapping to the configured local backend; other arrangements need `--url`. Tailscale is optional. The public URL is contacted only when supplied explicitly or found in that existing mapping. It is never guessed from a hostname alone.

Doctor does not read OAuth state or another process's environment, create credentials, perform sign-in, issue tokens, call MCP tools, change tunneling, or start/stop Hostgate. Findings describe this terminal's configuration and connectivity, not proof of access from ChatGPT, credential validity, reboot recovery, or a completed security audit. Use the connection steps below and a read-only `status` request for the first authenticated test.

Diagnostics have a three-second timeout and a 64 KiB output/response limit per probe. These bounds apply **only to doctor**, not to authorized file or shell tools. Dependency checks establish entry-point availability, not version or integrity verification. JSON output includes a schema version and the same redacted findings; it may include your public connection URL, so review it before sharing.

Exit codes: **0** means no actionable problem was detected by the checks performed (some checks can remain unverified); **1** means a finding needs attention or a check failed; **2** means invalid arguments. Doctor requires Node.js to launch, but it can diagnose missing npm and missing Hostgate dependencies. It uses the same saved-configuration selection, raw values, and environment precedence as `start`, without modifying that startup behavior.

## Connect

ChatGPT connects to the server over HTTPS. Tailscale Funnel is one way to expose Hostgate:

```text
tailscale funnel --yes --bg --set-path=/hostgate http://127.0.0.1:8787/hostgate
```

Use this MCP URL:

```text
https://<your-tailscale-hostname>/hostgate/mcp
```

In ChatGPT on the web:

1. Open **Settings → Apps** and choose **Create**, or open [ChatGPT Plugins](https://chatgpt.com/plugins) if that is the interface shown for your account.
2. Choose **Server URL** and enter your `/hostgate/mcp` URL.
3. Choose **OAuth**.
4. Scan the tools, then create the app.
5. Open the app’s connection settings and choose **Connect another account**.
6. Enter the Hostgate username and password from onboarding.
7. Refresh the app details so the actions appear.
8. Enable **Allow all actions** only if you accept full access for the Hostgate account.

Start with safe prompts:

```text
Use Hostgate status to show the operating system and hostname.
```

```text
Use Hostgate shell to run Get-Date on Windows, or date on Linux.
```

OpenAI’s current custom MCP app instructions are in the [Developer mode and MCP apps guide](https://help.openai.com/en/articles/12584461-developer-mode-and-mcp-apps-in-chatgpt).

## Tools

| Tool | Does |
| --- | --- |
| `status` | Shows basic system information. |
| `read` | Reads a UTF-8 text file. |
| `write` | Creates or overwrites a UTF-8 text file. |
| `shell` | Runs PowerShell on Windows or Bash on Linux. |

Hostgate exposes exactly these four MCP tools.

## Security

Hostgate is not a sandbox. `write` can overwrite files and `shell` can run commands with the permissions of the account running Hostgate.

- Use a dedicated, non-administrator account when possible.
- Use a strong, unique Hostgate password.
- Review every action before allowing it.
- Use HTTPS for remote access.
- Treat credentials, OAuth state, tokens, files, and command output as sensitive.
- Never commit `.env`, OAuth state, tokens, or `node_modules`.

Tailscale Funnel makes the endpoint reachable from the public internet. Read the [Tailscale Funnel documentation](https://tailscale.com/kb/1223/funnel) before enabling it.

### OAuth validation and upgrades

Authorization now requires a registered client and an exact match to its registered callback URL. An invalid client or callback receives an error without a password form or redirect. The login page shows the callback and the application's **self-reported** name; that name alone does not establish that the requester is ChatGPT. Continue only for a connection you initiated.

Dynamic client registration remains available. Callbacks must be absolute HTTPS URLs, without user information or fragments. Literal loopback HTTP callbacks (`127.0.0.1` or `[::1]`) remain supported for local clients and tests; their ports must also match exactly. HTTP hostname callbacks such as `localhost`, custom URI schemes, and callback wildcards are not supported. Registration rejects empty/invalid callback lists, invalid display names, unsupported client-authentication methods, and incompatible flow metadata. Unknown metadata is ignored. The response still selects the existing public-client `none` / `authorization_code` / `code` combination, even if the request includes additional grants such as `refresh_token`; refresh tokens are not issued.

S256 is required. Its challenge must be 43 base64url characters; the verifier must be 43–128 unreserved ASCII characters. Malformed scalar parameters and repeated form-encoded OAuth scalar fields are rejected. A failed exchange for a parsed authorization code retains the existing single-use behavior; obtain a new code rather than retry that code. These are authentication checks, not limits on authorized filesystem or shell access. Both root and `/hostgate` routes, all existing scopes, the default full-access grant, and exactly four MCP tools remain unchanged.

**Upgrade compatibility:** no state-file migration, credential rotation, client-ID replacement, or automatic token revocation occurs. Existing valid registrations and unexpired bearer tokens remain usable, including tokens loaded from the existing version-1 state format. Malformed legacy registrations are retained on disk but cannot obtain new authorization codes. Already-issued tokens are not retroactively revoked. If a connection has missing or invalid callback metadata, register a new OAuth client using the app connection setup and the exact callback shown for that connection. Recreating the affected MCP connection may be necessary because clients can reuse their original registration. Do not delete OAuth state or replace Hostgate credentials to repair callback metadata.

A normal server restart is required to load updated validation code; editing the checkout does not update an already-running process. Before restarting an environment-only deployment, preserve its original launcher configuration. Browser-bound approval transactions, token revocation, resource/audience binding, and stronger proof of ChatGPT client identity remain separate perimeter-security work. Public-request protections and their compatibility effects are described below.

Implementation references: [OpenAI authentication and callback requirements](https://developers.openai.com/plugins/build/auth), [RFC 7591 registration](https://www.rfc-editor.org/rfc/rfc7591.html), [RFC 9700 exact redirect matching](https://www.rfc-editor.org/rfc/rfc9700.html#section-2.1), and [RFC 7636 PKCE](https://www.rfc-editor.org/rfc/rfc7636.html). OpenAI guidance was checked on September 18, 2026. Hostgate continues to advertise DCR, not Client ID Metadata Documents; this update does not change issuer discovery or add `iss` support.

### If sign-in asks you to wait

Hostgate now slows repeated public OAuth requests. HTTP **429** means wait for the number of seconds in the `Retry-After` response header, then retry; it does not necessarily mean your password is wrong. Do not repeatedly click Authorize or retry in a tight loop. If the authorization code expired, restart the connection's sign-in flow rather than reusing that code. Existing authenticated MCP connections are not subject to these OAuth rate limits.

HTTP **503** can mean too many unfinished OAuth uploads or that new-registration/issuance capacity is full. A temporary upload overload includes `Retry-After: 1`; issuance capacity suggests retrying after 60 seconds, although a grant may not expire that soon. A registration-capacity response needs the host owner's review, not password rotation or repeated registration. Do not delete OAuth state, replace working credentials, or restart a healthy server merely to clear an admission error.

<details>
<summary>Public endpoint limits, deployment notes, and compatibility</summary>

Limits are per running server process, shared across root and `/hostgate` route aliases, regardless of supplied usernames, client IDs, IP addresses, or forwarded headers. Fixed-size token buckets refill gradually rather than extending a ban every time a denied request arrives.

| OAuth budget | Initial burst | Refill |
| --- | --- | --- |
| Registration requests | 30 | One request every 2 seconds |
| Authorization GET/HEAD/POST requests (combined) | 120 | One request every 0.5 seconds |
| Token endpoint requests | 60 | One request every second |
| Failed password checks after valid client/callback validation | 5 | One failure allowance every 12 seconds |

Successful password checks do not spend or reset the failed-password budget. When that budget is exhausted, even a correct login waits until an allowance refills. Valid and invalid endpoint requests both spend their endpoint's request budget. An attacker can temporarily delay legitimate new sign-ins by consuming shared allowances; these safeguards are not a denial-of-service guarantee. Counters are in memory and reset on a normal process restart. Multiple instances need separate deployment coordination; no distributed rate store is implemented.

Public OAuth POST bodies accept JSON or URL-encoded parameters, up to **64 KiB**, with a **10-second total upload deadline** and at most **16 pending OAuth body readers**. Declared and chunked oversized bodies receive **413**; incomplete uploads receive **408**; unsupported media types or compressed bodies receive **415**. OAuth GET/HEAD requests must not carry bodies, and unsupported OAuth methods receive **405**. Slots are released on completion, rejection, timeout, or disconnection. Responses to rejected incomplete uploads close that HTTP connection after the response is flushed. Unknown routes return a small JSON **404** immediately rather than waiting for a body.

MCP bearer authentication runs **before** request-body decoding. An unauthenticated or invalid-token MCP request receives **401** without waiting for the upload. Authenticated MCP requests retain the existing decoding and full authority: this change adds no body-size, output-size, duration, path, or command restrictions to MCP tools. Health and discovery remain public and are not assigned these OAuth endpoint budgets. Transport-level header/socket controls, reverse-proxy filtering, and volumetric attack protection remain separate deployment concerns; this patch does not change Node's transport defaults.

New registrations stop at **256 stored clients** by default. An operator can explicitly set `HOSTGATE_OAUTH_MAX_CLIENTS` in the launcher's environment to an integer from 1 through 100000; invalid values stop startup without echoing the supplied value. Investigate unexpected registration growth before raising this ceiling. No automatic registration deletion or eviction occurs. Existing registrations above a new ceiling are loaded and remain usable if valid, but no additional registrations are admitted until capacity is available or deliberately increased. A future owner-authorized connection-management operation is still needed for convenient cleanup; do not hand-edit or delete state while the server runs.

Issuance is bounded at **256 outstanding authorization codes** and **4096 active access-token records**. Expired entries are removed opportunistically before new issuance; expired tokens are also omitted from subsequent normal state saves. Existing unexpired tokens are not evicted, including legacy state above the ceiling. Startup does not migrate or rewrite the version-1 state file. Rate, body, and token-capacity admission failures occur before authorization-code consumption; normal parsed exchange failures still consume the code as documented above. Capacity reclamation changes only already-expired records, not scopes, token lifetimes, credentials, or grants that are still valid.

OAuth responses include `Cache-Control: no-store` and `Pragma: no-cache`. New rejection messages are fixed strings: no request bodies, passwords, codes, tokens, or raw exceptions are logged or reflected by these guards. This is not an audit-log implementation; proxy access logs still need independent redaction and protection.

These budgets intentionally do not derive identity from `X-Forwarded-For`: the existing proxy trust/issuer behavior is unchanged and still needs its own migration. Keep the backend behind the intended HTTPS proxy. A restart is required to activate these protections, using the original launcher environment; no service, tunnel, configuration, or credential change is performed by installing this code. Windows PowerShell and Linux Bash behavior, both route families, all scopes, and exactly four MCP tools are preserved.

References: [OAuth credential-guessing defenses](https://www.rfc-editor.org/rfc/rfc6749.html#section-10.10), [HTTP 429 and Retry-After](https://www.rfc-editor.org/rfc/rfc6585.html#section-4), [Express proxy trust](https://expressjs.com/en/guide/behind-proxies.html), and [Node HTTP transport defaults](https://nodejs.org/api/http.html). Operator guidance checked September 18, 2026.

</details>

## FAQ

### ChatGPT does not show any actions

Confirm that Hostgate is running, the `/hostgate/mcp` URL is reachable over HTTPS, OAuth is selected, and the account is connected. Then refresh the app details.

### Check my setup without changing anything

Run `node bin/hostgate.js doctor`. See [Check my setup](#check-my-setup) for options and what each result means.

### Check whether Hostgate is running

Open this URL on the computer running Hostgate:

```text
http://127.0.0.1:8787/hostgate/health
```

The expected response is:

```json
{"ok":true,"name":"hostgate"}
```

### Why does a command behave differently through ChatGPT?

Hostgate runs as the account that started it. That account may have a different home directory, PATH, or permissions.

### Does Windows install a background service?

Windows managed startup uses a current-user Task Scheduler logon task and a supervisor, not a pre-login Windows service. It recovers after this user logs in following reboot; it does not run while the user is logged out. Foreground `start` remains available. Linux onboarding still uses the existing user-level systemd service.

## Windows managed startup and recovery

### Preview installation without changing this computer

From the checkout on Windows:

```powershell
node .\bin\hostgate.js service plan
node .\bin\hostgate.js service prepare --json --environment-source stdin
node .\bin\hostgate.js service plan --npm-cli "C:\path\to\npm\bin\npm-cli.js"
```

**Both commands are the same read-only planner.** `prepare` does not build a release, install dependencies, import credentials, or activate anything. `--help` lists options; `--expect FULL_COMMIT` pins the expected local commit. The plan shows checks, proposed paths and task XML/command, and every future installation effect requiring separate authorization.

It checks local Git metadata, committed `main`, tracked/untracked cleanliness, a credential-free GitHub origin, the current Node executable, and npm metadata/Node compatibility without executing npm. It does not fetch remote HEAD. Existing or linked managed paths and configured external Git filters are blockers; nothing is removed, stashed, or ignored to clear them.

`--environment-source stdin|saved-file|launcher` declares the intended input method. Saved-file checks inspect only existence/type; stdin and launcher values are **never read or enumerated**, and no saved environment or OAuth state is opened/decrypted. Input availability, validity, provenance, and equality with a live launcher remain unverified where they cannot be established without reading values.

Windows checks inspect the current token identity, the nearest existing directory ACL, native DPAPI-library presence, and Task Scheduler XML using **TASK_VALIDATE_ONLY (1)**. They do not test encryption, create directories, change ACLs, register/run tasks, inspect/adopt a PID, open a test listener, or restart. ACL feasibility is advisory, and XML validity does not prove registration permission, runtime binding, or reboot recovery. Native `whoami`/`cscript` probes avoid PowerShell startup-cache writes. Disabled/unavailable native scripting or COM checks fail without a mutation or policy-change fallback. Defaults assume Windows under `C:\Windows` and Git under `C:\Program Files\Git`; explicit `--git-path` and `--cscript-path` select alternate trusted executables, not policy overrides.

The stable `hostgate-plan-v1:...` **approval token is a non-secret review fingerprint**, not proof of human consent, an OAuth credential, or platform approval. Identical observed plans yield the same token; relevant observations change it. No installer consumes it, and it cannot queue or authorize activation. Rerun planning before any separately approved installation. Shell/write warnings and all four full-authority MCP tools are unchanged; a planner invocation does not turn the shell tool into a read-only tool.

Exit codes: `0` means observed checks passed (unverified items can remain), `1` means blockers, and `2` means invalid arguments. Reports can disclose local paths, account identifiers, and repository URLs; review before sharing. This addition does not fix the existing installer's initial-adoption rollback or partial-install recovery limitations.

References: [Task Scheduler validation-only flag](https://learn.microsoft.com/en-us/windows/win32/taskschd/taskfolder-registertask), [read-only ACL retrieval](https://learn.microsoft.com/en-us/windows/win32/api/iads/nf-iads-iadssecurityutility-getsecuritydescriptor). Checked September 18, 2026.

### Install or operate the managed service

After onboarding, run `node bin/hostgate.js service install --yes`. It requires committed `main` source, a credential-free GitHub `origin`, and npm. Dependencies are installed and checks/tests pass in a new release directory **before** the supervisor starts. Existing untracked developer files are not copied. Installation does not change the Hostgate password or OAuth state.

The installation creates `%USERPROFILE%\.config\hostgate\managed`, restricts its ACL to the current user and SYSTEM, saves the environment as current-user DPAPI ciphertext, and copies the existing Node executable into a private stable runtime. The task runs non-elevated as that same account with no Windows password stored. A logon trigger starts it after sign-in; Task Scheduler retries supervisor failures, and the supervisor restarts crashed server children with backoff. It runs on battery without a scheduled execution-time limit. This is **post-logon recovery**, not a boot-before-login service. Do not use installation to silently change an elevated server's account or token privileges.

Use these from the checkout:

```text
node bin/hostgate.js service status
node bin/hostgate.js service start
node bin/hostgate.js service restart --yes
node bin/hostgate.js service result REQUEST_ID
node bin/hostgate.js logs
node bin/hostgate.js doctor
```

A restart returns a request ID. Its receipt reports completion or failure. It validates a loopback-only candidate before stopping the managed child, then launches the saved environment on the original address. Explicit restarts drain existing HTTP connections for up to ten seconds; they can interrupt longer calls. This lifecycle drain is not a new normal-operation shell timeout. If activation fails, the previous release is restarted; the receipt distinguishes a successful rollback from recovery that needs attention. No process tree or unrelated process is terminated.

From a **fresh PowerShell terminal**, even without Node or npm on PATH:

```powershell
& "$HOME\.config\hostgate\managed\hostgate.cmd" service status
& "$HOME\.config\hostgate\managed\hostgate.cmd" service restart --yes
& "$HOME\.config\hostgate\managed\hostgate.cmd" doctor
```

`configured` means the managed manifest exists. `running` requires a recent supervisor heartbeat, live supervisor/child PIDs, matching deployed release, and HTTP health. `restartReady` additionally requires a decryptable saved environment, present runtime files, a matching logon task, and a successful actual start with the same environment/release. None of these claims an actual reboot was tested. Doctor no longer treats a foreground configuration file alone as a verified restart.

A missing task can be recreated with `service repair --yes`; a task with conflicting ownership/arguments is never overwritten. `logs` displays the latest lifecycle events; `-f` currently returns a snapshot, not continuous tailing. Raw shell output, environment values, OAuth credentials, and token bodies are not written to manager logs. Keep the managed directory protected and backed up appropriately: DPAPI data is tied to the Windows user context and is not a portable plaintext configuration.

The saved environment is authoritative for managed launches and is not automatically replaced by a new terminal's variables or by the updater. Ordinary foreground configuration selection still prefers the user/legacy `.env` and falls back to the encrypted environment when no such file exists. Preserve original launcher settings during migration. An environment-only live server requires an explicit verified import: `service install --yes --import-stdin --adopt-pid PID` accepts environment JSON through stdin, never command-line credential values. `--adopt-from PATH` supports migration from another checkout of the same trusted origin. This is an operator migration interface, not permission to read arbitrary processes. Installation validates the selected same-user Node identity before stopping it, only after candidate checks. The CLI itself does not extract process memory.

### Safe GitHub updates

```text
node bin/hostgate.js update check
node bin/hostgate.js update apply --yes --expect FULL_40_CHARACTER_COMMIT
node bin/hostgate.js update status JOB_ID
node bin/hostgate.js update rollback --yes
```

`check` reads `origin/main` without checking out files. Applying requires explicit consent and the **full commit returned by check**. A changed remote, changed origin, non-main source branch, dirty tracked files, or **any untracked files** blocks application. Nothing is stashed, reset, force-pushed, or deleted to make the check pass. An existing untracked lockfile is still a reason to stop; review it rather than weakening the safety check.

The worker fetches without force, requires forward ancestry, creates a separate retained Git release, runs `npm ci --ignore-scripts`, then syntax checks and tests with a separate build home and no production OAuth environment. npm must be available; `service install --npm-cli PATH --yes` can explicitly record a private npm CLI installation. Missing npm or failing checks leave the active server unchanged. Package installation, tests, and update code are trusted code from the explicitly approved repository commit; this is not a sandbox or a substitute for source review.

After preparation, the worker rechecks source/deployment stability and asks the supervisor to activate. A failed live activation triggers rollback to the old release. Candidate directories, build fixtures, and receipts remain for diagnosis; automatic cleanup is deliberately not implemented. Updates switch a managed release pointer rather than modifying the developer checkout, its local dependencies, credentials, or OAuth state. The checkout's branch can therefore lag the deployed commit; `update check` reports checkout, deployed, and remote commits separately. Future code must declare `hostgateManagerApi: 1`; the stable supervisor is not silently self-replaced.

Only one apply worker owns the exclusive lock. If a worker crashes, inspect its receipt and service status; `update recover-lock --yes` retains and clears a stale lock only when its owner PID is no longer present. `update rollback --yes` activates the retained previous release without rewriting Git history or credentials. A queued request is not a completed update: inspect the job receipt and `service status`.

This milestone supports managed install/restart/apply/rollback on **Windows**. `update check` works on Linux, while Linux apply continues to require the existing manual/systemd deployment procedure; unsupported managed operations fail without changing it. Existing root and `/hostgate` routes, OAuth/PKCE, scopes, and exactly four full-authority MCP tools are unchanged. No HTTP management endpoint or fifth MCP tool is added.

Platform references: [Task Scheduler logon triggers](https://learn.microsoft.com/en-us/powershell/module/scheduledtasks/new-scheduledtasktrigger), [task recovery settings](https://learn.microsoft.com/en-us/powershell/module/scheduledtasks/new-scheduledtasksettingsset), [current-user DPAPI](https://learn.microsoft.com/en-us/dotnet/api/system.security.cryptography.protecteddata), and [Node child-process lifecycle](https://nodejs.org/api/child_process.html). Checked September 18, 2026.

## More than one computer: named host profiles

Use **one independent Hostgate server and ChatGPT connection per computer**, not a central shell proxy. Existing unprofiled operation is unchanged and never migrates its credentials/state automatically. Creating profiles does not activate or restart any server.

On the first computer, create its own local identity; on the second, repeat with a different name and HTTPS origin:

```powershell
node .\bin\hostgate.js host add "Primary laptop" --local --endpoint https://primary.example/hostgate/mcp --cwd "C:\Work" --yes
node .\bin\hostgate.js host add "Second laptop" --local --endpoint https://second.example/hostgate/mcp --cwd "C:\Work" --yes
```

Run each command **on the named computer**, with its real existing working directory and verified HTTPS proxy URL. Local IDs are generated UUIDs, not aliases or machine names. Profiles are also bound to the local platform/hostname to catch accidental catalog copies; that is not hardware attestation. Names (case-insensitively), IDs and HTTPS origins must be distinct within a catalog, including retired records. The endpoint is immutable in this first version. No network request is made by add/list/inspect/select/rename/remove.

Configure each host separately with `host configure NAME --import-stdin --yes`. Supply local JSON containing exactly `HOST` (loopback), `PORT` (a fixed port as a string), `HOSTGATE_OAUTH_USERNAME`, and `HOSTGATE_OAUTH_PASSWORD`. It never inherits the legacy server's or another profile's credentials, prints their values, or overwrites an existing credential store. Use different credentials per computer; keep input files out of source control and chat. Windows stores current-user DPAPI ciphertext; Linux stores a private mode-0600 file. Host ID and endpoint are bound inside the protected configuration. Start only when separately authorized with `host start NAME`; this is foreground operation.

A catalog can also describe another computer without storing its credentials or executing anything there:

```text
node bin/hostgate.js host add "Second laptop" --remote --id UUID_FROM_SECOND_LAPTOP --platform win32 --endpoint https://second.example/hostgate/mcp --cwd "C:\Work" --yes
node bin/hostgate.js host list
node bin/hostgate.js host inspect "Primary laptop"
node bin/hostgate.js host rename "Primary laptop" "Main laptop" --yes
node bin/hostgate.js host select "Main laptop" --context ProjectA/chat1 --cwd "C:\Work\ProjectA" --yes
node bin/hostgate.js host inspect --context ProjectA/chat1
node bin/hostgate.js host route "Second laptop" --context ProjectB/chat2
node bin/hostgate.js host remove "Second laptop" --yes
```

For a remote record, copy the **non-secret ID, canonical host name and endpoint** from that computer's inspection. Linux remote profiles use `--platform linux` and an absolute Linux cwd. A local catalog label that does not match the target server's name will be rejected at execution; it is not permission to rewrite the routing card. Remote start/configure/service/update/log commands are refused rather than accidentally operating on the current laptop.

**Select stores only a project/chat-specific routing card, never a global execution default.** All runtime/lifecycle commands still require an explicit name/ID. Registry mutations use an exclusive lock and atomic replacement; competing writers fail without losing selections. An interrupted edit can leave a lock that needs local inspection. Removal retires the entry and its selections, reserves its identity/origin, and retains all credentials, OAuth state, deployments and logs. It does not revoke a remote connection. A running local process or configured manager blocks removal. Renaming a running local profile makes further requests fail closed until an explicit restart; IDs and state paths do not change.

### ChatGPT connection and project routing

Create separately named connections, for example **Hostgate - Primary laptop** and **Hostgate - Second laptop**, each using that host's exact endpoint and its own OAuth sign-in. Current official developer-mode instructions use **Settings → Security and login → Developer mode**, then **Plugins → plus → name/description → connection URL**; availability depends on workspace policy. After deployment, refresh that connection's tools and start a new conversation. Use the official guide when your UI differs. No ChatGPT settings are changed by this CLI.

Put the output of `host route NAME --context PROJECT/CHAT [--cwd ABSOLUTE_PATH]` in that project's instructions or the chat. It supplies a `target` object containing the immutable host ID, canonical name, and endpoint, plus an explicit context and working directory. Instruct ChatGPT to use **only that named connection**, preserve the target exactly, and stop on mismatch—never substitute another connection or modify the target to make a call pass.

In profiled mode, **all four tools require the exact target and contextId**. Shell also requires a per-call cwd; relative file paths require cwd. The server compares ID, name and endpoint **before** invoking a handler. Missing/mismatched targets fail without the requested side effect; explicitly targeted calls reaching a legacy server fail too. Tool descriptions, initialization, health and results identify the host. Shell/write retain their destructive warnings and unrestricted OS-account capability.

Each call gets server-generated request/execution IDs, a host-scoped OAuth connection ID, and a context key. An optional OpenAI conversation identifier is hashed for correlation; it is not authentication. No shared current directory, shell session, or current project is mutated between requests. Native children run concurrently; logs contain completion metadata, not commands, output, file contents, paths, passwords or tokens.

**Boundary:** Hostgate cannot read the user's natural-language intention or independently establish a ChatGPT project-to-host binding. It rejects a misaddressed structured request, but cannot detect a caller that supplies an entirely different, internally consistent routing card. Context labels/optional conversation metadata are not authorization. Full authorized shell access is deliberately not a filesystem/process sandbox: two commands intentionally editing the same files can conflict, and an authorized account can deliberately access its other profiles. Use distinct directories or Git worktrees for independent work.

### Per-host state and operations

Host catalog: `~/.config/hostgate/hosts.json`. Each ID has its own `~/.config/hostgate/hosts/ID/` credential and managed-deployment directory, and `~/.local/share/hostgate/hosts/ID/` OAuth state, runtime status and execution logs. Relative paths above follow the OS account's home. Do not copy private stores between computers. OAuth client registrations, codes and tokens are independent; profiled state and opaque token records are bound to ID/resource. Cross-host credentials/state copies fail closed. Profile OAuth requires the canonical endpoint in the `resource` parameter; root and `/hostgate` route aliases advertise that same resource. Existing unprofiled tokens/routes keep their old behavior.

`host status NAME`, `host doctor NAME`, and `host logs NAME` inspect only that local profile. Status requires identity-matched health; a remote record is not treated as a locally running host. Windows `host service NAME plan|prepare` retains the read-only/no-secret contract and uses distinct profile paths/task names. `host service NAME install --yes` uses only that profile's separately configured environment; legacy PID adoption is not performed. Other service/update operations use the same explicit-host prefix and require their existing confirmations. Per-host launchers remain pinned to their profile; an update cannot drop named-host support silently.

Linux named-host foreground operation is supported; automatic per-profile systemd installation and managed update application remain unsupported, and the legacy systemd service is never implicitly reused. Initial-adoption/partial-install recovery limitations remain as documented above. No real two-computer ChatGPT UI test or production activation is implied by isolated automated tests.

Official references, checked September 18, 2026: [connect/refresh MCP connections](https://developers.openai.com/plugins/deploy/connect-chatgpt), [conversation metadata](https://developers.openai.com/plugins/reference#_meta-fields-the-client-provides), [MCP resource/audience binding](https://modelcontextprotocol.io/specification/2025-11-25/basic/authorization).

## Development

```bash
npm run check
npm test
npm pack --dry-run
```

## License

MIT
