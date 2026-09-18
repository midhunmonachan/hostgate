import { performance } from "node:perf_hooks";

// Public OAuth admission only. These limits never apply to authenticated MCP tools.
export const LIMITS = Object.freeze({
  bodyBytes: 64 * 1024,
  bodyTimeoutMs: 10000,
  pendingBodies: 16,
  clients: 256,
  codes: 256,
  tokens: 4096
});
export const RATES = Object.freeze({
  register: Object.freeze({ capacity: 30, refillMs: 2000 }),
  authorize: Object.freeze({ capacity: 120, refillMs: 500 }),
  token: Object.freeze({ capacity: 60, refillMs: 1000 }),
  password: Object.freeze({ capacity: 5, refillMs: 12000 })
});
const SCALAR_FIELDS = ["resource", "response_type", "client_id", "redirect_uri", "code_challenge",
  "code_challenge_method", "state", "scope", "username", "password", "grant_type", "code", "code_verifier"];

export function configuredClientLimit(env = process.env) {
  const text = env.HOSTGATE_OAUTH_MAX_CLIENTS;
  if (text === undefined) return LIMITS.clients;
  if (typeof text !== "string" || /[^0-9]/.test(text) || !/^[1-9][0-9]*$/.test(text) || !Number.isSafeInteger(Number(text)) || Number(text) > 100000) {
    throw new Error("HOSTGATE_OAUTH_MAX_CLIENTS must be an integer from 1 to 100000.");
  }
  return Number(text);
}

// Constant memory: no attacker-controlled client ID, username, or IP-address map.
// A denied request never spends a token or extends a lockout. Time is monotonic.
export function createBucket({ capacity, refillMs }, now = () => performance.now()) {
  if (!Number.isInteger(capacity) || capacity < 1 || !Number.isFinite(refillMs) || refillMs <= 0) {
    throw new Error("Invalid OAuth rate configuration.");
  }
  let tokens = capacity;
  let last = now();
  function retryAfter() {
    const current = Math.max(last, now());
    tokens = Math.min(capacity, tokens + (current - last) / refillMs);
    last = current;
    return tokens >= 1 ? 0 : Math.max(1, Math.ceil((1 - tokens) * refillMs / 1000));
  }
  return {
    retryAfter,
    take() {
      const delay = retryAfter();
      if (!delay) tokens -= 1;
      return delay;
    }
  };
}

export function closeUnreadRequest(req, res) {
  if (!req.complete) {
    // Let Node flush the response and close HTTP/1.x without awaiting the upload.
    res.shouldKeepAlive = false;
    res.set("Connection", "close");
  }
}

export function publicError(req, res, status, error, description, retryAfter) {
  closeUnreadRequest(req, res);
  res.set("Cache-Control", "no-store").set("Pragma", "no-cache");
  if (retryAfter !== undefined) res.set("Retry-After", String(retryAfter));
  res.status(status).json({ error, error_description: description });
}

// The same decoding is used for MCP and OAuth. Only OAuth enables admission bounds.
export function createBodyParser({ oauth = false, maxBytes = LIMITS.bodyBytes,
  timeoutMs = LIMITS.bodyTimeoutMs, maxPending = LIMITS.pendingBodies } = {}) {
  let pending = 0;
  return function parseBody(req, res, next) {
    if (!["POST", "PUT", "PATCH"].includes(req.method)) {
      if (oauth && (req.headers["transfer-encoding"] || (req.headers["content-length"] && req.headers["content-length"] !== "0"))) {
        publicError(req, res, 400, "invalid_request", "OAuth GET and HEAD requests must not carry a body.");
        return;
      }
      req.body = {};
      next();
      return;
    }
    const reject = (status, error, description, retryAfter) => publicError(req, res, status, error, description, retryAfter);
    if (oauth) {
      if (pending >= maxPending) {
        reject(503, "temporarily_unavailable", "Too many pending OAuth requests. Retry shortly.", 1);
        return;
      }
      const length = req.headers["content-length"];
      if (length !== undefined && (!/^[0-9]+$/.test(length) || !Number.isSafeInteger(Number(length)))) {
        reject(400, "invalid_request", "Invalid request length.");
        return;
      }
      if (length !== undefined && Number(length) > maxBytes) {
        reject(413, "invalid_request", "OAuth request body exceeds the supported size.");
        return;
      }
      const encoding = (req.headers["content-encoding"] || "identity").toLowerCase();
      if (encoding !== "identity") {
        reject(415, "invalid_request", "Compressed OAuth request bodies are not supported.");
        return;
      }
      const type = (req.headers["content-type"] || "").split(";", 1)[0].trim().toLowerCase();
      if (!["application/json", "application/x-www-form-urlencoded"].includes(type)) {
        reject(415, "invalid_request", "Send JSON or URL-encoded OAuth parameters.");
        return;
      }
    }
    let chunks = [];
    let size = 0;
    let settled = false;
    let timer;
    if (oauth) pending++;
    function cleanup() {
      if (settled) return false;
      settled = true;
      clearTimeout(timer);
      if (oauth) pending--;
      req.removeListener("data", onData);
      req.removeListener("end", onEnd);
      req.removeListener("aborted", onAbort);
      res.removeListener("close", onAbort);
      // Keep the guarded error listener: aborting a stream can emit error later.
      return true;
    }
    function fail(status, error, description) {
      if (!cleanup()) return;
      chunks = [];
      req.pause();
      reject(status, error, description);
    }
    function onAbort() {
      if (cleanup()) chunks = [];
    }
    function onError() {
      if (req.aborted || res.destroyed) onAbort();
      else fail(400, "invalid_request_body", "Request body could not be read.");
    }
    function onData(chunk) {
      size += chunk.length;
      if (oauth && size > maxBytes) {
        fail(413, "invalid_request", "OAuth request body exceeds the supported size.");
        return;
      }
      chunks.push(chunk);
    }
    function onEnd() {
      if (!cleanup()) return;
      const text = Buffer.concat(chunks).toString("utf8");
      chunks = [];
      const contentType = (req.headers["content-type"] || "").toLowerCase();
      try {
        if (!text) req.body = {};
        else if (contentType.includes("application/json")) req.body = JSON.parse(text);
        else if (contentType.includes("application/x-www-form-urlencoded")) {
          const form = new URLSearchParams(text);
          if (oauth && SCALAR_FIELDS.some((key) => form.getAll(key).length > 1)) {
            reject(400, "invalid_request", "Repeated OAuth parameters are not supported.");
            return;
          }
          req.body = Object.fromEntries(form);
        } else req.body = {};
      } catch {
        reject(400, "invalid_request_body", "Request body could not be parsed.");
        return;
      }
      next();
    }
    req.on("error", onError);
    req.once("aborted", onAbort);
    res.once("close", onAbort);
    req.on("end", onEnd);
    req.on("data", onData);
    if (oauth) {
      timer = setTimeout(() => fail(408, "invalid_request", "OAuth body upload timed out. Retry the request."), timeoutMs);
      timer.unref?.();
    }
  };
}

export function pruneExpired(records, now = Date.now()) {
  for (const [key, record] of records) {
    if (typeof record?.expiresAt === "number" && record.expiresAt <= now) records.delete(key);
  }
}

export function createPerimeter({ now, rates = RATES, bodyOptions, maxClients = configuredClientLimit() } = {}) {
  const buckets = Object.fromEntries(Object.entries(rates).map(([key, rate]) => [key, createBucket(rate, now)]));
  const body = createBodyParser({ ...bodyOptions, oauth: true });
  const throttle = (req, res, seconds) => publicError(req, res, 429, "temporarily_unavailable",
    "Too many OAuth attempts. Wait for Retry-After before trying again.", seconds);
  return {
    middleware(req, res, next) {
      // Mounted on /oauth and /hostgate/oauth; Express already strips that prefix.
      const endpoint = /^\/(register|authorize|token)\/?$/i.exec(req.path)?.[1].toLowerCase();
      if (!endpoint) { next(); return; } // Unknown routes never buffer a body.
      res.set("Cache-Control", "no-store").set("Pragma", "no-cache");
      const methods = endpoint === "authorize" ? ["GET", "HEAD", "POST"] : ["POST"];
      if (!methods.includes(req.method)) {
        res.set("Allow", methods.join(", "));
        publicError(req, res, 405, "invalid_request", "Method not allowed.");
        return;
      }
      const retry = buckets[endpoint].take();
      if (retry) { throttle(req, res, retry); return; }
      body(req, res, next);
    },
    allowPassword(req, res) {
      const retry = buckets.password.retryAfter();
      if (retry) { throttle(req, res, retry); return false; }
      return true;
    },
    failedPassword() { buckets.password.take(); },
    allowClient(req, res, clients) {
      if (clients.size < maxClients) return true;
      publicError(req, res, 503, "temporarily_unavailable",
        "OAuth registration capacity reached. The host owner must review deployment capacity.");
      return false;
    },
    allowExpiring(req, res, records, kind) {
      pruneExpired(records);
      const limit = kind === "code" ? LIMITS.codes : LIMITS.tokens;
      if (records.size < limit) return true;
      publicError(req, res, 503, "temporarily_unavailable",
        "OAuth issuance capacity reached. Retry after existing grants expire.", 60);
      return false;
    }
  };
}
