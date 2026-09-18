import assert from "node:assert/strict";
import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { executionContext, runTool, resolveExecutionDirectory, resolveFilePath, executionLogPath } from "../src/execution.js";
import { configuredResource, validResource, tokenResourceMatches, validateStateBinding, assertSingleInstanceEnvironment } from "../src/endpoint-binding.js";

const endpoint = "https://single.example.test/hostgate/mcp";
test("correlation is independent of host profiles and distinguishes requests, instances, connections and conversations", () => {
  const req = { hostgateRequestId: crypto.randomUUID(), hostgateToken: { clientId: "client-a" } };
  const args = { contextId: "project/chat" }, extra = { _meta: { "openai/session": "private-session" } };
  const a = executionContext("instance-a", req, args, extra), b = executionContext("instance-a", req, args, extra);
  assert.equal(a.requestId, req.hostgateRequestId); assert.notEqual(a.executionId, b.executionId); assert.equal(a.contextKey, b.contextKey);
  for (const alternative of [
    executionContext("instance-b", req, args, extra),
    executionContext("instance-a", { hostgateToken: { clientId: "client-b" } }, args, extra),
    executionContext("instance-a", req, { contextId: "another/chat" }, extra),
    executionContext("instance-a", req, args, { _meta: { "openai/session": "other-session" } })
  ]) assert.notEqual(a.contextKey, alternative.contextKey);
  assert(!JSON.stringify(a).includes("private-session")); assert(!JSON.stringify(a).includes("client-a"));
  assert.equal(a.host, undefined); assert.equal(a.hostId, undefined);
  const unnamed = executionContext("instance", {}, {}); assert.equal(unnamed.contextId, null); assert.equal(unnamed.conversationId, null);
});
test("successful and failed tools expose correlation and log only completion metadata", async () => {
  const events = [], audit = event => events.push(event);
  const args = { command: "private-command", path: "private-path", contextId: "private-context" };
  const req = { hostgateToken: { clientId: "private-client", password: "private-password" } };
  const result = await runTool("instance", req, "shell", args, {}, async () => ({ content: [{ type: "text", text: "output" }], structuredContent: { exitCode: 0, command: args.command } }), audit);
  assert.equal(result.structuredContent.command, args.command); assert(result.structuredContent.execution.auditRecorded);
  assert.match(result.content.at(-1).text, /Execution:/); assert(events[0].success);
  const failure = await runTool("instance", req, "read", args, {}, async () => { throw new Error("expected test error"); }, audit);
  assert.equal(failure.isError, true); assert.equal(events[1].success, false);
  assert(failure.structuredContent.execution.executionId); assert.equal(failure.content[0].text, "expected test error");
  const serialized = JSON.stringify(events);
  for (const value of ["private-command", "private-path", "private-context", "private-client", "private-password", "expected test error"]) assert(!serialized.includes(value));
});
test("logging failure is reported without rerunning a command", async () => {
  let invocations = 0;
  const result = await runTool("instance", {}, "write", {}, {}, async () => { invocations++; return { content: [] }; }, () => { throw new Error("unavailable log"); });
  assert.equal(invocations, 1); assert.equal(result.structuredContent.execution.auditRecorded, false); assert.equal(result.isError, undefined);
});
test("nonzero shell exits and failed spawns are unsuccessful audit outcomes", async () => {
  for (const exitCode of [7, null]) {
    let event;
    await runTool("instance", {}, "shell", {}, {}, async () => ({ structuredContent: { exitCode } }), value => { event = value; });
    assert.equal(event.success, false);
  }
});
test("explicit cwd is validated per call without changing the parent directory or restricting absolute file access", () => {
  const home = fs.mkdtempSync(path.join(os.tmpdir(), "hostgate-cwd-unit-"));
  const a = path.join(home, "project A"), b = path.join(home, "other ' project"); fs.mkdirSync(a); fs.mkdirSync(b);
  const before = process.cwd();
  assert.equal(resolveExecutionDirectory(undefined, home), home); assert.equal(resolveExecutionDirectory("~/project A", home), a);
  assert.equal(resolveFilePath("same.txt", a, home), path.join(a, "same.txt"));
  assert.equal(resolveFilePath("same.txt", b, home), path.join(b, "same.txt"));
  assert.equal(resolveFilePath(path.join(b, "outside.txt"), a, home), path.join(b, "outside.txt"));
  assert.equal(resolveFilePath("~/same.txt", a, home), path.join(home, "same.txt"));
  for (const invalid of ["", "relative", "C:relative", "bad\0cwd", path.join(home, "missing")]) assert.throws(() => resolveExecutionDirectory(invalid, home));
  const file = path.join(home, "file"); fs.writeFileSync(file, "fixture"); assert.throws(() => resolveExecutionDirectory(file, home));
  assert.equal(process.cwd(), before); assert.equal(executionLogPath(home), path.join(home, ".local/share/hostgate/executions.jsonl"));
});
test("configured endpoint validation is strict and never echoes credential-bearing input", () => {
  assert.equal(configuredResource(undefined), null); assert.equal(configuredResource(""), null);
  assert.equal(configuredResource(endpoint), endpoint);
  assert.equal(configuredResource("https://SINGLE.example.test:443/mcp"), "https://single.example.test/mcp");
  for (const value of ["http://example.test/mcp", "https://user:secret@example.test/mcp", endpoint + "?token=secret", endpoint + "#secret", "https://example.test/wrong", " https://example.test/mcp", "https://example.test\\mcp"]) {
    assert.throws(() => configuredResource(value), error => !error.message.includes("secret"));
  }
});
test("resource matching preserves unbound legacy tokens only outside strict endpoint mode", () => {
  assert(validResource(undefined, endpoint)); assert(!validResource(undefined, endpoint, true));
  assert(validResource(endpoint, endpoint, true)); assert(!validResource([endpoint, endpoint], endpoint));
  assert(!validResource("https://other.test/mcp", endpoint)); assert(!validResource("", endpoint));
  assert(tokenResourceMatches({}, endpoint)); assert(!tokenResourceMatches({}, endpoint, true));
  assert(tokenResourceMatches({ resource: endpoint }, endpoint, true));
  assert(!tokenResourceMatches({ resource: "https://other.test/mcp" }, endpoint));
});
test("bound state cannot be moved to another endpoint or downgraded; retired profile state fails closed", () => {
  const records = { clients: [], accessTokens: [] };
  assert.doesNotThrow(() => validateStateBinding({ ...records, version: 1 }, null));
  assert.doesNotThrow(() => validateStateBinding({ ...records, version: 1 }, endpoint));
  assert.doesNotThrow(() => validateStateBinding({ ...records, version: 3, resource: endpoint }, endpoint));
  for (const state of [{ ...records, version: 2, hostId: crypto.randomUUID() }, { ...records, version: 3, resource: "https://other.test/mcp" }, { ...records, version: 999 }]) {
    assert.throws(() => validateStateBinding(state, endpoint));
  }
  assert.throws(() => validateStateBinding({ ...records, version: 3, resource: endpoint }, null));
});
test("retired runtime selectors fail without reading a catalog or replacing credentials", () => {
  assert.doesNotThrow(() => assertSingleInstanceEnvironment({ HOST: "127.0.0.1" }));
  assert.throws(() => assertSingleInstanceEnvironment({ HOSTGATE_PROFILE_ID: "old" }), /explicit migration/);
  assert.throws(() => assertSingleInstanceEnvironment({ hostgate_profile_staging: "1" }), /explicit migration/);
});
