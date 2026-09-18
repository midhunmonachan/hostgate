import assert from "node:assert/strict";
import { EventEmitter } from "node:events";
import test from "node:test";
import { LIMITS, RATES, configuredClientLimit, createBucket, createBodyParser, createPerimeter, pruneExpired } from "../src/perimeter.js";

function request(path = "/register", method = "POST", headers = {}) {
  const req = new EventEmitter();
  Object.assign(req, { path, method, headers: { "content-type": "application/json", ...headers }, complete: false, pause() {} });
  return req;
}
function response() {
  const res = new EventEmitter();
  Object.assign(res, { headers: {}, set(key, value) { this.headers[key.toLowerCase()] = value; return this; },
    status(code) { this.statusCode = code; return this; }, json(value) { this.body = value; this.emit("finish"); return this; } });
  return res;
}
function finish(req, body) {
  req.emit("data", Buffer.from(body));
  req.complete = true;
  req.emit("end");
}

test("token bucket bounds bursts, refills monotonically, and never extends denial", () => {
  let clock = 0;
  const bucket = createBucket({ capacity: 2, refillMs: 10000 }, () => clock);
  assert.equal(bucket.take(), 0);
  assert.equal(bucket.take(), 0);
  for (let n = 0; n < 100; n++) assert.equal(bucket.take(), 10);
  clock = 5500;
  assert.equal(bucket.take(), 5);
  clock = 10000;
  assert.equal(bucket.take(), 0);
  assert.equal(bucket.take(), 10);
  clock = 5000;
  assert.equal(bucket.take(), 10, "Backwards clocks cannot add tokens");
  clock = 100000;
  assert.equal(bucket.take(), 0);
  assert.equal(bucket.take(), 0);
  assert.equal(bucket.take(), 10, "Idle time never adds more than the burst capacity");
});

test("all bucket capacities and default storage limits are explicit", () => {
  for (const rate of Object.values(RATES)) {
    const bucket = createBucket(rate, () => 0);
    for (let i = 0; i < rate.capacity; i++) assert.equal(bucket.take(), 0);
    assert(bucket.take() > 0);
  }
  assert.equal(LIMITS.bodyBytes, 65536);
  assert.equal(LIMITS.pendingBodies, 16);
  assert.equal(LIMITS.bodyTimeoutMs, 10000);
  assert.throws(() => createBucket({ capacity: 0, refillMs: 1 }));
  assert.throws(() => createBucket({ capacity: 1, refillMs: 0 }));
});

test("client-capacity configuration fails safely without printing values", () => {
  assert.equal(configuredClientLimit({}), 256);
  assert.equal(configuredClientLimit({ HOSTGATE_OAUTH_MAX_CLIENTS: "1024" }), 1024);
  for (const value of ["0", "-1", "1.5", "secret-value", "100001", "", "Infinity"]) {
    assert.throws(() => configuredClientLimit({ HOSTGATE_OAUTH_MAX_CLIENTS: value }), /must be an integer/);
  }
});

test("rate admission ignores forged IP/client headers, path case, trailing slash, and query identity", () => {
  let clock = 0;
  const p = createPerimeter({ now: () => clock });
  for (let i = 0; i < RATES.register.capacity; i++) {
    const req = request(i % 2 ? "/REGISTER/" : "/register", "POST", { "x-forwarded-for": `192.0.2.${i}`, "x-client-id": String(i) });
    const res = response();
    let next = false;
    p.middleware(req, res, () => { next = true; });
    finish(req, "{}");
    assert(next);
    assert.equal(res.headers["cache-control"], "no-store");
  }
  const res = response();
  p.middleware(request("/register"), res, () => assert.fail("Throttled request reached parsing"));
  assert.equal(res.statusCode, 429);
  assert.equal(res.headers["retry-after"], "2");
  assert.equal(res.headers.connection, "close");
  clock = 2000;
  let resumed = false;
  const req = request();
  p.middleware(req, response(), () => { resumed = true; });
  finish(req, "{}");
  assert(resumed);
});

test("password failures have a separate recovering budget and successes do not refill it", () => {
  let clock = 0;
  const p = createPerimeter({ now: () => clock });
  for (let i = 0; i < 20; i++) assert(p.allowPassword(request(), response()));
  for (let i = 0; i < 5; i++) {
    assert(p.allowPassword(request(), response()));
    p.failedPassword();
  }
  for (let i = 0; i < 20; i++) {
    const res = response();
    assert.equal(p.allowPassword(request(), res), false);
    assert.equal(res.statusCode, 429);
    assert.equal(res.headers["retry-after"], "12");
  }
  clock = 12000;
  assert(p.allowPassword(request(), response()));
  p.failedPassword();
  assert.equal(p.allowPassword(request(), response()), false);
});

test("OAuth body bounds count bytes, accept exact limit, and release pending slots", () => {
  const parser = createBodyParser({ oauth: true, maxBytes: 8, maxPending: 1 });
  const req = request();
  let count = 0;
  parser(req, response(), () => { count++; });
  finish(req, '"ééé"'); // 8 bytes, not 5 JavaScript characters.
  assert.equal(count, 1);
  const bad = request();
  const res = response();
  parser(bad, res, () => assert.fail("Oversized body accepted"));
  bad.emit("data", Buffer.from('"éééé"'));
  bad.emit("end");
  bad.emit("error", new Error("private stream detail"));
  assert.equal(res.statusCode, 413);
  assert(!JSON.stringify(res.body).includes("private"));
  const after = request();
  parser(after, response(), () => { count++; });
  finish(after, "{}");
  assert.equal(count, 2);
});

test("OAuth body concurrency slots recover after abort, errors, and response close", () => {
  for (const event of ["aborted", "error", "response-close"]) {
    const parser = createBodyParser({ oauth: true, maxPending: 1 });
    const first = request();
    const firstRes = response();
    parser(first, firstRes, () => assert.fail("Incomplete request accepted"));
    const blocked = response();
    parser(request(), blocked, () => assert.fail("Pending body cap bypassed"));
    assert.equal(blocked.statusCode, 503);
    if (event === "response-close") firstRes.emit("close");
    else first.emit(event, new Error("do not log"));
    first.emit("error", new Error("late error"));
    const after = request();
    let accepted = false;
    parser(after, response(), () => { accepted = true; });
    finish(after, "{}");
    assert(accepted, event);
  }
});

test("public OAuth deadline frees retained data and does not extend on dribbled input", async () => {
  const parser = createBodyParser({ oauth: true, timeoutMs: 25, maxPending: 1 });
  const req = request();
  const res = response();
  parser(req, res, () => assert.fail("Slow upload reached handler"));
  req.emit("data", Buffer.from("{"));
  await new Promise((resolve) => setTimeout(resolve, 60));
  assert.equal(res.statusCode, 408);
  req.emit("data", Buffer.from("}"));
  req.emit("end");
  const after = request();
  let accepted = false;
  parser(after, response(), () => { accepted = true; });
  finish(after, "{}");
  assert(accepted);
});

test("declared oversized, unsupported, and malformed bodies fail without reaching handlers", () => {
  const parser = createBodyParser({ oauth: true });
  for (const [headers, status] of [[{ "content-length": "65537" }, 413], [{ "content-length": "bad" }, 400],
    [{ "content-encoding": "gzip" }, 415], [{ "content-type": "text/plain" }, 415]]) {
    const req = request("/token", "POST", headers);
    const res = response();
    parser(req, res, () => assert.fail("Invalid request accepted"));
    assert.equal(res.statusCode, status);
    assert.equal(req.listenerCount("data"), 0);
  }
  const req = request();
  const res = response();
  parser(req, res, () => assert.fail("Malformed JSON accepted"));
  finish(req, '{"secret":');
  assert.equal(res.statusCode, 400);
  assert(!JSON.stringify(res.body).includes("secret"));
});

test("public repeated OAuth fields remain invalid, while MCP decoding stays unbounded", () => {
  const form = request("/token", "POST", { "content-type": "application/x-www-form-urlencoded" });
  const res = response();
  createBodyParser({ oauth: true })(form, res, () => assert.fail("Duplicate OAuth field accepted"));
  finish(form, "code=one&code=two");
  assert.equal(res.statusCode, 400);
  const parser = createBodyParser({ maxBytes: 1, timeoutMs: 1, maxPending: 0 });
  const req = request("/mcp");
  let accepted = false;
  parser(req, response(), () => { accepted = true; });
  finish(req, JSON.stringify({ content: "X".repeat(131072) }));
  assert(accepted);
  assert.equal(req.body.content.length, 131072);
});

test("unknown routes and unsupported methods never install upload readers", () => {
  const p = createPerimeter();
  const unknown = request("/unknown");
  let next = false;
  p.middleware(unknown, response(), () => { next = true; });
  assert(next);
  assert.equal(unknown.listenerCount("data"), 0);
  const req = request("/token", "PUT");
  const res = response();
  p.middleware(req, res, () => assert.fail("Unsupported method reached handler"));
  assert.equal(res.statusCode, 405);
  assert.equal(res.headers.allow, "POST");
  assert.equal(req.listenerCount("data"), 0);
});

test("client cap rejects new admissions without evicting existing records, including legacy excess", () => {
  const clients = new Map([["old-1", { clientId: "old-1" }], ["old-2", { clientId: "old-2" }]]);
  const before = [...clients];
  const res = response();
  assert.equal(createPerimeter({ maxClients: 1 }).allowClient(request(), res, clients), false);
  assert.equal(res.statusCode, 503);
  assert.deepEqual([...clients], before);
  assert(createPerimeter({ maxClients: 3 }).allowClient(request(), response(), clients));
});

test("expired state is pruned without revoking active tokens or altering legacy records", () => {
  const active = { expiresAt: 2000, scope: "all", clientId: "old" };
  const records = new Map([["expired", { expiresAt: 1000 }], ["active", active], ["legacy", {}]]);
  pruneExpired(records, 1000);
  assert.deepEqual([...records.keys()], ["active", "legacy"]);
  assert.equal(records.get("active"), active);
  for (const [kind, cap] of [["code", LIMITS.codes], ["token", LIMITS.tokens]]) {
    const full = new Map(Array.from({ length: cap }, (_, i) => [i, { expiresAt: Date.now() + 60000 }]));
    const res = response();
    const p = createPerimeter();
    assert.equal(p.allowExpiring(request(), res, full, kind), false);
    assert.equal(res.statusCode, 503);
    assert.equal(full.size, cap);
    full.set(0, { expiresAt: Date.now() - 1 });
    assert(p.allowExpiring(request(), response(), full, kind));
    assert.equal(full.size, cap - 1);
  }
});


test("OAuth GET/HEAD payloads cannot hold upload slots or reach the login page", () => {
  const p = createPerimeter();
  for (const method of ["GET", "HEAD"]) {
    const req = request("/authorize", method, { "content-length": "100" });
    const res = response();
    p.middleware(req, res, () => assert.fail("Unexpected body accepted"));
    assert.equal(res.statusCode, 400);
    assert.equal(req.listenerCount("data"), 0);
  }
});
