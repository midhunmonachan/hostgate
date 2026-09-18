# Hostgate

Connect ChatGPT to your own computer through an OAuth-protected MCP server.

[Overview](#overview) • [Install](#install) • [Connect to ChatGPT](#connect-to-chatgpt) • [Tools](#tools) • [Security](#security) • [Troubleshooting](#troubleshooting)

---

## Overview

Hostgate lets ChatGPT read files, write files, run commands, and inspect the computer where Hostgate is running.

It supports:

- Windows with PowerShell
- Linux with Bash
- ChatGPT custom apps using MCP and OAuth
- Local use or remote access through an HTTPS endpoint such as Tailscale Funnel

Hostgate is not a sandbox. It can use the permissions of the account running it.

## Requirements

- Node.js 22 or newer
- npm
- Windows PowerShell 5.1 or Linux Bash
- An HTTPS endpoint reachable by ChatGPT
- A ChatGPT account/workspace that can use custom MCP apps

## Install

Clone the repository and install its dependencies.

### Windows

Open a normal, non-administrator PowerShell window:

```powershell
git clone https://github.com/midhunmonachan/hostgate.git
Set-Location .\hostgate
npm.cmd ci
node .\bin\hostgate.js onboard
```

### Linux

```bash
git clone https://github.com/midhunmonachan/hostgate.git
cd hostgate
npm ci
node bin/hostgate.js onboard
```

During onboarding, choose a username and a strong password for Hostgate. Do not share these credentials.

On Windows, start Hostgate in the foreground:

```powershell
node .\bin\hostgate.js start
```

Keep this terminal open. Press `Ctrl+C` to stop it.

On Linux, onboarding configures a user-level systemd service. Check it with:

```bash
node bin/hostgate.js status
node bin/hostgate.js logs -f
```

You can also run Linux in the foreground with `node bin/hostgate.js start`.

## Connect to ChatGPT

ChatGPT needs a public HTTPS MCP URL. Tailscale Funnel is one option:

```text
tailscale funnel --yes --bg --set-path=/hostgate http://127.0.0.1:8787/hostgate
```

Your MCP URL will be:

```text
https://<your-hostname>/hostgate/mcp
```

In ChatGPT on the web:

1. Open [ChatGPT Plugins](https://chatgpt.com/plugins).
2. Select **Create app**.
3. Choose **Server URL**.
4. Enter your `/hostgate/mcp` URL.
5. Choose **OAuth** and create the app.
6. Select **Connect another account**.
7. Enter the Hostgate username and password you chose during onboarding.
8. Refresh the app details so the actions appear.
9. Enable **Allow all actions** only if you accept full access for the Hostgate account.

Start with a harmless test such as:

```text
Use Hostgate status to report the operating system and hostname.
```

Then test a read-only command:

```text
Use Hostgate shell to run Get-Date on Windows, or date on Linux.
```

## Tools

Hostgate exposes exactly four MCP tools:

| Tool | Purpose |
| --- | --- |
| `status` | Reports basic system information. |
| `read` | Reads a UTF-8 text file. |
| `write` | Creates or overwrites a UTF-8 text file. |
| `shell` | Runs a PowerShell or Bash command. |

`write` overwrites files and `shell` can run arbitrary commands. Use disposable files and harmless commands while testing.

## Security

Hostgate provides access to the machine, not an isolated environment.

- Run it under a dedicated, non-administrator account when possible.
- Use a strong, unique Hostgate password.
- Keep the default local bind address unless you need another one.
- Use HTTPS for remote connections.
- Treat the `.env` file, OAuth state, tokens, command output, and files as sensitive.
- Never commit credentials, tokens, `.env` files, OAuth state, or `node_modules`.
- Review every action before allowing it to run.

Tailscale Funnel makes the endpoint reachable from the public internet. Read the [Tailscale Funnel documentation](https://tailscale.com/kb/1223/funnel) before enabling it.

## Troubleshooting

Check the local health endpoint:

```text
http://127.0.0.1:8787/hostgate/health
```

It should return:

```json
{"ok":true,"name":"hostgate"}
```

If ChatGPT does not show actions:

1. Confirm Hostgate is running.
2. Confirm the public `/hostgate/mcp` URL is reachable over HTTPS.
3. Reconnect the account using **Connect another account**.
4. Refresh the app details.
5. Check that OAuth is selected and the credentials are correct.

If a command works locally but not through ChatGPT, remember that Hostgate runs commands as the account that started the server. That account may have a different home directory, PATH, or permissions.

## Development

Run the project checks before submitting changes:

```bash
npm run check
npm test
npm pack --dry-run
```

## License

MIT
