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
node .\bin\hostgate.js start
```

Keep this terminal open. Press `Ctrl+C` to stop Hostgate.

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

**Running is not the same as restart-ready.** A healthy server can still lack saved configuration. Do not stop a working server or replace its credentials just because this check finds missing restart settings. On Windows, keep the foreground terminal open; this CLI does not manage Windows services or autostart. On Linux, doctor also checks whether the user service is active, without changing it.

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

A normal server restart is required to load updated validation code; editing the checkout does not update an already-running process. Before restarting an environment-only deployment, preserve its original launcher configuration. This validation slice does not add brute-force protection, request-size limits, browser-bound approval transactions, token revocation, resource/audience binding, or stronger proof of ChatGPT client identity; those remain separate perimeter-security work.

Implementation references: [OpenAI authentication and callback requirements](https://developers.openai.com/plugins/build/auth), [RFC 7591 registration](https://www.rfc-editor.org/rfc/rfc7591.html), [RFC 9700 exact redirect matching](https://www.rfc-editor.org/rfc/rfc9700.html#section-2.1), and [RFC 7636 PKCE](https://www.rfc-editor.org/rfc/rfc7636.html). OpenAI guidance was checked on September 18, 2026. Hostgate continues to advertise DCR, not Client ID Metadata Documents; this update does not change issuer discovery or add `iss` support.

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

No. Windows runs Hostgate in the foreground with `node .\bin\hostgate.js start`. Linux onboarding uses a user-level systemd service.

## Development

```bash
npm run check
npm test
npm pack --dry-run
```

## License

MIT
