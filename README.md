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

## FAQ

### ChatGPT does not show any actions

Confirm that Hostgate is running, the `/hostgate/mcp` URL is reachable over HTTPS, OAuth is selected, and the account is connected. Then refresh the app details.

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
