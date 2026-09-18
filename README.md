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

No. Windows runs Hostgate in the foreground with `node .\bin\hostgate.js start`. Linux onboarding uses a user-level systemd service.

## Development

```bash
npm run check
npm test
npm pack --dry-run
```

## License

MIT
