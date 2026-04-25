import express from "express";
import { spawn } from "node:child_process";
import crypto from "node:crypto";
import { mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { mkdir, readFile, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import process from "node:process";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";
import { z } from "zod";

const PORT = Number(process.env.PORT || 8787);
const HOST = process.env.HOST || "127.0.0.1";
const MAX_OUTPUT = 20_000;
const MAX_FILE_BYTES = 200_000;
const OAUTH_USERNAME = process.env.HOSTGATE_OAUTH_USERNAME || "admin";
const OAUTH_PASSWORD = process.env.HOSTGATE_OAUTH_PASSWORD || "";
const ALL_SCOPE = "all";
const TOOL_SCOPES = {
  status: "status",
  read: "read",
  write: "write",
  shell: "shell"
};
const SUPPORTED_SCOPES = [ALL_SCOPE, ...Object.values(TOOL_SCOPES)];
const TOKEN_TTL_SECONDS = 86_400;
const STATE_PATH = path.join(os.homedir(), ".local/share/hostgate/oauth-state.json");
const PREFIX = "/hostgate";

const clients = new Map();
const authorizationCodes = new Map();
const accessTokens = new Map();

function randomToken(bytes = 32) {
  return crypto.randomBytes(bytes).toString("base64url");
}

function tokenHash(token) {
  return crypto.createHash("sha256").update(token).digest("base64url");
}

function loadOAuthState() {
  try {
    const state = JSON.parse(readFileSync(STATE_PATH, "utf8"));
    for (const client of state.clients || []) {
      if (client?.clientId) {
        clients.set(client.clientId, client);
      }
    }
    for (const token of state.accessTokens || []) {
      if (token?.hash && token.expiresAt > Date.now()) {
        accessTokens.set(token.hash, {
          clientId: token.clientId,
          scope: token.scope,
          expiresAt: token.expiresAt
        });
      }
    }
  } catch (error) {
    if (error.code !== "ENOENT") {
      console.warn(`Failed to load OAuth state from ${STATE_PATH}: ${error.message}`);
    }
  }
}

function saveOAuthState() {
  try {
    mkdirSync(path.dirname(STATE_PATH), { recursive: true, mode: 0o700 });
    const state = {
      version: 1,
      clients: Array.from(clients.values()),
      accessTokens: Array.from(accessTokens.entries()).map(([hash, token]) => ({
        hash,
        clientId: token.clientId,
        scope: token.scope,
        expiresAt: token.expiresAt
      }))
    };
    writeFileSync(STATE_PATH, `${JSON.stringify(state, null, 2)}\n`, { mode: 0o600 });
  } catch (error) {
    console.warn(`Failed to save OAuth state to ${STATE_PATH}: ${error.message}`);
  }
}

loadOAuthState();

function timingSafeEqualString(left, right) {
  const leftBuffer = Buffer.from(left);
  const rightBuffer = Buffer.from(right);
  return leftBuffer.length === rightBuffer.length && crypto.timingSafeEqual(leftBuffer, rightBuffer);
}

function requestBasePath(req) {
  return req.originalUrl === PREFIX || req.originalUrl.startsWith(`${PREFIX}/`) ? PREFIX : "";
}

function requestBaseUrl(req) {
  return `${req.protocol}://${req.get("host")}${requestBasePath(req)}`;
}

function parseScopes(scopeText) {
  return new Set(
    String(scopeText || "")
      .split(/[,\s]+/)
      .map((scope) => scope.trim())
      .filter(Boolean)
  );
}

function normalizeRequestedScopes(scopeText) {
  const requested = parseScopes(scopeText);
  const selected = requested.size > 0 ? requested : new Set(SUPPORTED_SCOPES);
  const normalized = new Set();

  for (const scope of selected) {
    if (!SUPPORTED_SCOPES.includes(scope)) {
      throw new Error(`Unsupported OAuth scope: ${scope}`);
    }
    normalized.add(scope);
  }

  if (normalized.has(ALL_SCOPE)) {
    for (const scope of Object.values(TOOL_SCOPES)) {
      normalized.add(scope);
    }
  }
  return normalized;
}

function hasScope(scopeText, requiredScope) {
  const scopes = parseScopes(scopeText);
  return scopes.has(ALL_SCOPE) || scopes.has(requiredScope);
}

function oauthMetadata(baseUrl) {
  return {
    issuer: baseUrl,
    authorization_endpoint: `${baseUrl}/oauth/authorize`,
    token_endpoint: `${baseUrl}/oauth/token`,
    registration_endpoint: `${baseUrl}/oauth/register`,
    response_types_supported: ["code"],
    grant_types_supported: ["authorization_code"],
    token_endpoint_auth_methods_supported: ["none"],
    code_challenge_methods_supported: ["S256"],
    scopes_supported: SUPPORTED_SCOPES
  };
}

function protectedResourceMetadata(baseUrl) {
  return {
    resource: `${baseUrl}/mcp`,
    authorization_servers: [baseUrl],
    scopes_supported: SUPPORTED_SCOPES,
    bearer_methods_supported: ["header"]
  };
}

function verifyBearerToken(req) {
  const header = req.get("authorization") || "";
  if (!header.startsWith("Bearer ")) {
    return false;
  }

  const token = header.slice("Bearer ".length);
  const record = accessTokens.get(tokenHash(token));
  if (!record) {
    return false;
  }
  if (record.expiresAt < Date.now()) {
    accessTokens.delete(tokenHash(token));
    saveOAuthState();
    return false;
  }
  req.hostgateToken = record;
  return true;
}

function requireScope(req, scope) {
  if (!scope) {
    return;
  }
  if (!hasScope(req.hostgateToken?.scope, scope)) {
    throw new Error(`OAuth token is missing required scope: ${scope}`);
  }
}

function requireAuth(req, res, next) {
  if (verifyBearerToken(req)) {
    next();
    return;
  }

  res
    .status(401)
    .set("WWW-Authenticate", `Bearer resource_metadata="${requestBaseUrl(req)}/.well-known/oauth-protected-resource"`)
    .json({ error: "authorization_required" });
}

function resolveHostPath(requestedPath) {
  if (!requestedPath || requestedPath.includes("\0")) {
    throw new Error("Path is required.");
  }
  return path.isAbsolute(requestedPath) ? path.normalize(requestedPath) : path.resolve(os.homedir(), requestedPath);
}

function collectSystemStatus() {
  return {
    hostname: os.hostname(),
    platform: os.platform(),
    arch: os.arch(),
    release: os.release(),
    uptimeSeconds: os.uptime(),
    loadAverage: os.loadavg(),
    memory: {
      totalBytes: os.totalmem(),
      freeBytes: os.freemem()
    },
    cpus: os.cpus().map((cpu) => cpu.model)
  };
}

function runCommand(commandSpec, timeoutMs) {
  return new Promise((resolve) => {
    const child = spawn(commandSpec.cmd, commandSpec.args, {
      cwd: os.homedir(),
      env: {
        PATH: process.env.PATH || "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
        HOME: os.homedir(),
        LANG: process.env.LANG || "C.UTF-8"
      },
      shell: false,
      windowsHide: true
    });

    let stdout = "";
    let stderr = "";
    let truncated = false;
    const timer = setTimeout(() => child.kill("SIGTERM"), timeoutMs);

    const append = (chunk, target) => {
      const next = target + chunk.toString("utf8");
      if (next.length > MAX_OUTPUT) {
        truncated = true;
        return next.slice(0, MAX_OUTPUT);
      }
      return next;
    };

    child.stdout.on("data", (chunk) => {
      stdout = append(chunk, stdout);
    });
    child.stderr.on("data", (chunk) => {
      stderr = append(chunk, stderr);
    });
    child.on("error", (error) => {
      clearTimeout(timer);
      resolve({ exitCode: null, stdout, stderr: `${stderr}\n${error.message}`.trim(), timedOut: false, truncated });
    });
    child.on("close", (code, signal) => {
      clearTimeout(timer);
      resolve({ exitCode: code, signal, stdout, stderr, timedOut: signal === "SIGTERM", truncated });
    });
  });
}

function runShell(command, timeoutMs) {
  return runCommand({ cmd: "/bin/bash", args: ["-lc", command] }, timeoutMs);
}

function buildMcpServer(req) {
const server = new McpServer({
  name: "hostgate",
  version: "0.1.0"
});

server.registerTool(
  "status",
  {
    title: "Status",
    description: "Use this to inspect this server's OS, uptime, load, CPU, and memory.",
    inputSchema: {},
    annotations: {
      readOnlyHint: true,
      destructiveHint: false,
      openWorldHint: false
    }
  },
  async () => {
    requireScope(req, TOOL_SCOPES.status);
    const status = collectSystemStatus();
    return {
      content: [{ type: "text", text: JSON.stringify(status, null, 2) }],
      structuredContent: status
    };
  }
);

server.registerTool(
  "read",
  {
    title: "Read text file",
    description: "Use this to read a UTF-8 text file by absolute path or by path relative to the service user's home directory.",
    inputSchema: {
      path: z.string().min(1).describe("Absolute path, or a path relative to the service user's home directory.")
    },
    annotations: {
      readOnlyHint: true,
      destructiveHint: false,
      openWorldHint: false
    }
  },
  async ({ path: requestedPath }) => {
    requireScope(req, TOOL_SCOPES.read);
    const resolved = resolveHostPath(requestedPath);
    const file = await readFile(resolved);
    if (file.byteLength > MAX_FILE_BYTES) {
      throw new Error(`File is too large: ${file.byteLength} bytes > ${MAX_FILE_BYTES} bytes.`);
    }

    const text = file.toString("utf8");
    return {
      content: [{ type: "text", text }],
      structuredContent: { path: requestedPath, bytes: file.byteLength, text }
    };
  }
);

server.registerTool(
  "write",
  {
    title: "Write text file",
    description: "Use this to write a UTF-8 text file by absolute path or by path relative to the service user's home directory. This overwrites the file.",
    inputSchema: {
      path: z.string().min(1).describe("Absolute path, or a path relative to the service user's home directory."),
      content: z.string().max(MAX_FILE_BYTES).describe("UTF-8 text content to write.")
    },
    annotations: {
      readOnlyHint: false,
      destructiveHint: true,
      openWorldHint: false
    }
  },
  async ({ path: requestedPath, content }) => {
    requireScope(req, TOOL_SCOPES.write);
    const resolved = resolveHostPath(requestedPath);
    await mkdir(path.dirname(resolved), { recursive: true });
    await writeFile(resolved, content, "utf8");
    return {
      content: [{ type: "text", text: `Wrote ${Buffer.byteLength(content, "utf8")} bytes to ${requestedPath}.` }],
      structuredContent: { path: requestedPath, bytes: Buffer.byteLength(content, "utf8") }
    };
  }
);

server.registerTool(
  "shell",
  {
    title: "Shell",
    description: "Run an unrestricted Bash command on this server. This is OAuth-protected and intentionally dangerous.",
    inputSchema: {
      command: z.string().min(1).max(8000).describe("Bash command to run with /bin/bash -lc."),
      timeoutMs: z.number().int().min(1000).max(120000).default(30000).describe("Maximum runtime in milliseconds.")
    },
    annotations: {
      readOnlyHint: false,
      destructiveHint: true,
      openWorldHint: true
    }
  },
  async ({ command, timeoutMs }) => {
    requireScope(req, TOOL_SCOPES.shell);
    const result = await runShell(command, timeoutMs);
    const structuredContent = { ...result, command };
    const parts = [
      `$ ${command}`,
      result.stdout,
      result.stderr ? `[stderr]\n${result.stderr}` : "",
      `exit ${result.exitCode ?? "none"}${result.signal ? ` signal ${result.signal}` : ""}${result.timedOut ? " timed out" : ""}${result.truncated ? " truncated" : ""}`
    ].filter(Boolean);
    return {
      content: [
        {
          type: "text",
          text: parts.join("\n")
        }
      ],
      structuredContent
    };
  }
);

return server;
}

const app = express();
app.set("trust proxy", true);
app.use(express.json({ limit: "1mb" }));
app.use(express.urlencoded({ extended: false }));
app.get(["/health", `${PREFIX}/health`], (_req, res) => {
  res.json({ ok: true, name: "hostgate" });
});

app.get([
  "/.well-known/oauth-authorization-server",
  "/.well-known/openid-configuration",
  `${PREFIX}/.well-known/oauth-authorization-server`,
  `${PREFIX}/.well-known/openid-configuration`
], (req, res) => {
  res.json(oauthMetadata(requestBaseUrl(req)));
});

app.get([
  "/.well-known/oauth-protected-resource",
  "/.well-known/oauth-protected-resource/mcp",
  `${PREFIX}/.well-known/oauth-protected-resource`,
  `${PREFIX}/.well-known/oauth-protected-resource/mcp`
], (req, res) => {
  res.json(protectedResourceMetadata(requestBaseUrl(req)));
});

app.post(["/oauth/register", `${PREFIX}/oauth/register`], (req, res) => {
  const clientId = randomToken(18);
  const client = {
    clientId,
    clientName: req.body.client_name || "ChatGPT",
    redirectUris: Array.isArray(req.body.redirect_uris) ? req.body.redirect_uris : [],
    createdAt: Date.now()
  };
  clients.set(clientId, client);
  saveOAuthState();

  res.status(201).json({
    client_id: clientId,
    client_name: client.clientName,
    redirect_uris: client.redirectUris,
    grant_types: ["authorization_code"],
    response_types: ["code"],
    token_endpoint_auth_method: "none"
  });
});

function htmlEscape(value) {
  return String(value)
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;");
}

function renderLoginForm(params, basePath, error = "") {
  const hiddenInputs = Object.entries(params)
    .map(([key, value]) => `<input type="hidden" name="${htmlEscape(key)}" value="${htmlEscape(value || "")}">`)
    .join("\n");

  return `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Authorize Hostgate</title>
  <style>
    body { font-family: ui-sans-serif, system-ui, sans-serif; background: #111827; color: #f9fafb; display: grid; min-height: 100vh; place-items: center; margin: 0; }
    main { width: min(92vw, 420px); background: #1f2937; border: 1px solid #374151; border-radius: 18px; padding: 28px; box-shadow: 0 20px 60px rgb(0 0 0 / 0.35); }
    label { display: block; margin-top: 14px; color: #d1d5db; font-size: 14px; }
    input { box-sizing: border-box; width: 100%; margin-top: 6px; border: 1px solid #4b5563; border-radius: 10px; padding: 12px; background: #111827; color: #f9fafb; }
    button { width: 100%; margin-top: 20px; border: 0; border-radius: 10px; padding: 12px; background: #f59e0b; color: #111827; font-weight: 700; cursor: pointer; }
    p { color: #9ca3af; line-height: 1.5; }
    .error { color: #fecaca; background: #7f1d1d; border: 1px solid #991b1b; border-radius: 10px; padding: 10px; }
  </style>
</head>
<body>
  <main>
    <h1>Authorize Hostgate</h1>
    <p>This grants ChatGPT access to the OAuth-protected MCP tools on this server.</p>
    ${error ? `<p class="error">${htmlEscape(error)}</p>` : ""}
    <form method="post" action="${basePath}/oauth/authorize">
      ${hiddenInputs}
      <label>Username<input name="username" autocomplete="username" required autofocus></label>
      <label>Password<input name="password" type="password" autocomplete="current-password" required></label>
      <button type="submit">Authorize</button>
    </form>
  </main>
</body>
</html>`;
}

function validateAuthorizeParams(params) {
  if (params.response_type !== "code") {
    return "Unsupported response_type.";
  }
  if (!params.client_id || !params.redirect_uri || !params.code_challenge || params.code_challenge_method !== "S256") {
    return "Missing required OAuth parameters.";
  }
  try {
    normalizeRequestedScopes(params.scope);
  } catch (error) {
    return error.message;
  }

  const client = clients.get(params.client_id);
  if (client && client.redirectUris.length > 0 && !client.redirectUris.includes(params.redirect_uri)) {
    return "Redirect URI is not registered for this client.";
  }
  return "";
}

app.get(["/oauth/authorize", `${PREFIX}/oauth/authorize`], (req, res) => {
  const params = {
    response_type: req.query.response_type,
    client_id: req.query.client_id,
    redirect_uri: req.query.redirect_uri,
    code_challenge: req.query.code_challenge,
    code_challenge_method: req.query.code_challenge_method,
    state: req.query.state,
    scope: req.query.scope
  };
  const error = validateAuthorizeParams(params);
  res.status(error ? 400 : 200).type("html").send(renderLoginForm(params, requestBasePath(req), error));
});

app.post(["/oauth/authorize", `${PREFIX}/oauth/authorize`], (req, res) => {
  const params = {
    response_type: req.body.response_type,
    client_id: req.body.client_id,
    redirect_uri: req.body.redirect_uri,
    code_challenge: req.body.code_challenge,
    code_challenge_method: req.body.code_challenge_method,
    state: req.body.state,
    scope: req.body.scope
  };

  const error = validateAuthorizeParams(params);
  if (error) {
    res.status(400).type("html").send(renderLoginForm(params, requestBasePath(req), error));
    return;
  }

  if (!OAUTH_PASSWORD || req.body.username !== OAUTH_USERNAME || !timingSafeEqualString(req.body.password || "", OAUTH_PASSWORD)) {
    res.status(401).type("html").send(renderLoginForm(params, requestBasePath(req), "Invalid username or password."));
    return;
  }

  const code = randomToken(24);
  authorizationCodes.set(code, {
    clientId: params.client_id,
    redirectUri: params.redirect_uri,
    codeChallenge: params.code_challenge,
    scope: Array.from(normalizeRequestedScopes(params.scope)).join(" "),
    expiresAt: Date.now() + 5 * 60 * 1000
  });

  const redirectUrl = new URL(params.redirect_uri);
  redirectUrl.searchParams.set("code", code);
  if (params.state) {
    redirectUrl.searchParams.set("state", params.state);
  }
  res.redirect(302, redirectUrl.toString());
});

app.post(["/oauth/token", `${PREFIX}/oauth/token`], (req, res) => {
  if (req.body.grant_type !== "authorization_code") {
    res.status(400).json({ error: "unsupported_grant_type" });
    return;
  }

  const record = authorizationCodes.get(req.body.code);
  authorizationCodes.delete(req.body.code);
  if (!record || record.expiresAt < Date.now()) {
    res.status(400).json({ error: "invalid_grant" });
    return;
  }
  if (record.clientId !== req.body.client_id || record.redirectUri !== req.body.redirect_uri) {
    res.status(400).json({ error: "invalid_grant" });
    return;
  }

  const verifier = req.body.code_verifier || "";
  const challenge = crypto.createHash("sha256").update(verifier).digest("base64url");
  if (!timingSafeEqualString(challenge, record.codeChallenge)) {
    res.status(400).json({ error: "invalid_grant" });
    return;
  }

  const accessToken = randomToken(32);
  accessTokens.set(tokenHash(accessToken), {
    clientId: record.clientId,
    scope: record.scope,
    expiresAt: Date.now() + TOKEN_TTL_SECONDS * 1000
  });
  saveOAuthState();

  res.json({
    access_token: accessToken,
    token_type: "Bearer",
    expires_in: TOKEN_TTL_SECONDS,
    scope: record.scope
  });
});

app.use(["/mcp", `${PREFIX}/mcp`], requireAuth);

app.all(["/mcp", `${PREFIX}/mcp`], async (req, res) => {
  if (req.method === "GET" || req.method === "DELETE") {
    res.status(405).json({
      jsonrpc: "2.0",
      error: {
        code: -32000,
        message: "Method not allowed."
      },
      id: null
    });
    return;
  }

  const server = buildMcpServer(req);
  try {
    const transport = new StreamableHTTPServerTransport({
      sessionIdGenerator: undefined
    });

    res.on("close", () => {
      transport.close();
      server.close();
    });

    await server.connect(transport);
    await transport.handleRequest(req, res, req.body);
  } catch (error) {
    if (!res.headersSent) {
      res.status(500).json({ error: error instanceof Error ? error.message : String(error) });
    }
  }
});

app.listen(PORT, HOST, () => {
  console.log(`Hostgate listening at http://${HOST}:${PORT}/mcp`);
  console.log("OAuth: enabled");
  console.log(`OAuth state: ${STATE_PATH}`);
});
