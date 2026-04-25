# Hostgate

Connect your server to ChatGPT chats.

Hostgate runs an OAuth-protected MCP server on your machine. After adding it as a ChatGPT developer-mode app, you can select Hostgate in a chat and ask it to inspect the host, read or write files, and run shell commands.

> [!WARNING]
> Hostgate provides host-level access. Treat it like exposing SSH through ChatGPT: use strong credentials, HTTPS, and only run it on machines you intend to operate this way.

## Capabilities

| Tool | What it does |
| --- | --- |
| `status` | Returns hostname, OS, uptime, load, CPU, and memory details. |
| `read` | Reads a UTF-8 text file by absolute path, or relative to the service user's home directory. |
| `write` | Writes a UTF-8 text file by absolute path, or relative to the service user's home directory. |
| `shell` | Runs a Bash command with `/bin/bash -lc`. |

> [!IMPORTANT]
> File tools are size-limited, but paths are not sandboxed after OAuth authorization.

## Requirements

- Node.js `22` or newer
- Linux with `systemd --user`
- Public HTTPS access for ChatGPT
- Tailscale CLI, optional, for automatic Funnel setup during onboarding

## Install

```bash
npm install -g hostgate
hostgate onboard
```

`hostgate onboard` is the main setup flow. It:

- writes configuration to `~/.config/hostgate/.env`
- installs or updates `~/.config/systemd/user/hostgate.service`
- enables and restarts the service
- optionally exposes Hostgate through Tailscale Funnel at `/hostgate`
- prints the ChatGPT app setup guide

When Tailscale Funnel is enabled, Hostgate is exposed as:

```text
https://your-host.example/hostgate/mcp
```

Internally, this maps to:

```text
/hostgate -> http://127.0.0.1:8787/hostgate
```

## Connect To ChatGPT

After onboarding:

1. Open the ChatGPT website.
2. Go to `Settings` -> `Apps` -> `Advanced settings`.
3. Enable `Developer Mode`.
4. Create an app.
5. Enter the app details:
   - `Name`: `Hostgate`
   - `Description`: `Remote host operations`
   - `MCP Server URL`: the `/hostgate/mcp` URL printed by onboarding
   - `Authentication`: `OAuth`
6. Open `Advanced OAuth settings` only if you need to choose scopes.
7. Check `I understand and want to continue`.
8. Click `Create`.
9. Complete the OAuth flow with the username and password from onboarding.
10. Start a new chat, press `+`, select `Hostgate`, and ask it to run a task.

> [!NOTE]
> ChatGPT memory is not available to developer-mode apps. Do not rely on saved memories being provided to Hostgate during testing.

## CLI

```bash
hostgate onboard      # configure, install, start, and optionally expose Hostgate
hostgate status       # show systemd service status
hostgate logs -f      # follow service logs
hostgate help         # show help
```

## OAuth And Scopes

Hostgate requires OAuth before MCP tools can be listed or called.

OAuth client registrations and access tokens are stored locally:

```text
~/.local/share/hostgate/oauth-state.json
```

Supported scopes:

```text
all status read write shell
```

Each tool requires its matching scope. `all` grants every tool.

## Configuration

Onboarding manages `~/.config/hostgate/.env`:

```env
PORT=8787
HOST=127.0.0.1
HOSTGATE_OAUTH_USERNAME=
HOSTGATE_OAUTH_PASSWORD=
```

The systemd service loads this file through `EnvironmentFile`. Direct `npm start` does not load `.env` automatically.

## Feedback

Ideas, bugs, and setup issues are welcome. Open a GitHub issue with what you tried, what happened, and any relevant `hostgate logs -f` output.

## License

MIT
