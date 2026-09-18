import assert from "node:assert/strict";
import crypto from "node:crypto";
import test from "node:test";
import { isObject, validRedirectUri, validateRegistration, validateClientRedirect, validateAuthorization, validCodeVerifier } from "../src/oauth-validation.js";

const redirect = "https://chatgpt.com/connector/oauth/example-callback";
const client = Object.freeze({ clientId: "registered-client", clientName: "Example", redirectUris: Object.freeze([redirect]) });
const verifier = "A".repeat(43);
const params = Object.freeze({ response_type: "code", client_id: client.clientId, redirect_uri: redirect,
  code_challenge: crypto.createHash("sha256").update(verifier).digest("base64url"), code_challenge_method: "S256" });

test("OAuth object validation rejects null, arrays, and primitives", () => {
  for (const value of [null, undefined, [], "text", 42, true]) assert.equal(isObject(value), false);
  assert.equal(isObject({}), true);
});

test("callback validation accepts current ChatGPT URLs, HTTPS queries, and literal loopback HTTP", () => {
  for (const value of [redirect, "https://chatgpt.com/connector_platform_oauth_redirect", "https://example.test/callback?tenant=a%20b",
    "https://localhost/callback", "http://127.0.0.1/callback", "http://127.0.0.1:12345/callback", "http://[::1]:12345/callback"]) {
    assert.equal(validRedirectUri(value), true, value);
  }
});

test("callbacks reject insecure, malformed, credential-bearing, and fragment URLs", () => {
  for (const value of [null, 1, [], {}, "", "/callback", "javascript:alert(1)", "file:///callback", "ftp://example.test/callback",
    "http://example.test/callback", "http://localhost/callback", "http://127.0.0.1.evil.test/callback", "http://2130706433/callback",
    "https:///example.test/callback", "https://example.test/callback#", "https://example.test/callback#fragment",
    "https://user:password@example.test/callback", "https://@example.test/callback", "https://*.example.test/callback",
    " https://example.test/callback", "https://example.test/callback\n", "https://example.test/ca llback",
    "https://example.test\\evil/callback", "https://example.test/%ZZ", "https://example.test:99999/callback"]) {
    assert.equal(validRedirectUri(value), false, JSON.stringify(value));
  }
});

test("registration requires nonempty valid redirect metadata before persistence", () => {
  for (const value of [null, [], "body"]) assert.equal(validateRegistration(value), "invalid_client_metadata");
  for (const redirect_uris of [undefined, null, [], "https://example.test/callback", [null], [redirect, "http://example.test/callback"]]) {
    assert.equal(validateRegistration({ redirect_uris }), "invalid_redirect_uri");
  }
});

test("registration accepts public-client defaults and ignores extension metadata", () => {
  const body = Object.freeze({ redirect_uris: Object.freeze([redirect]), client_name: "Example",
    token_endpoint_auth_method: "none", grant_types: ["authorization_code", "refresh_token"], response_types: ["code"],
    extension_metadata: { ignored: true } });
  const before = JSON.stringify(body);
  assert.equal(validateRegistration(body), "");
  assert.equal(validateRegistration({ redirect_uris: [redirect] }), "");
  assert.equal(JSON.stringify(body), before);
});

test("invalid name, authentication method, and flow metadata are rejected without echoing values", () => {
  for (const extra of [{ client_name: null }, { client_name: [] }, { client_name: "" }, { client_name: "\nsecret" },
    { client_name: "x".repeat(257) }, { token_endpoint_auth_method: "client_secret_basic" }, { token_endpoint_auth_method: null },
    { grant_types: "authorization_code" }, { grant_types: [] }, { grant_types: [null] }, { grant_types: ["implicit"] },
    { response_types: ["token"] }, { response_types: null }]) {
    assert.equal(validateRegistration({ redirect_uris: [redirect], ...extra }), "invalid_client_metadata");
  }
});

test("authorization rejects unknown clients and malformed legacy redirect lists", () => {
  for (const legacy of [undefined, null, {}, { ...client, clientId: "other" }, { ...client, redirectUris: [] },
    { ...client, redirectUris: "not-an-array" }, { ...client, redirectUris: [null] }]) {
    assert.notEqual(validateAuthorization(params, legacy), "");
  }
});

test("callback comparison is exact: no normalization, wildcard, query, prefix, or port matching", () => {
  const exact = { clientId: "exact", redirectUris: ["https://Example.test:443/Callback?tenant=1"] };
  assert.equal(validateClientRedirect("exact", exact.redirectUris[0], exact), "");
  for (const uri of ["https://example.test/Callback?tenant=1", "https://Example.test:443/callback?tenant=1",
    "https://Example.test:443/Callback?tenant=2", "https://Example.test:443/Callback?tenant=1&extra=yes",
    "https://Example.test:443/Callback/extra?tenant=1"]) assert.notEqual(validateClientRedirect("exact", uri, exact), "");
  const loopback = { clientId: "loopback", redirectUris: ["http://127.0.0.1:1234/callback"] };
  assert.notEqual(validateClientRedirect("loopback", "http://127.0.0.1:5678/callback", loopback), "");
});

test("S256 challenge validation rejects malformed types, lengths, alphabets, and downgrades", () => {
  assert.equal(validateAuthorization(params, client), "");
  for (const code_challenge of [undefined, null, [], {}, "", "A".repeat(42), "A".repeat(44), "A".repeat(43) + "\n",
    "A".repeat(42) + "=", "A".repeat(42) + "+", "A".repeat(42) + "."]) {
    assert.notEqual(validateAuthorization({ ...params, code_challenge }, client), "");
  }
  for (const code_challenge_method of [undefined, null, "plain", "s256", ["S256"]]) {
    assert.notEqual(validateAuthorization({ ...params, code_challenge_method }, client), "");
  }
});

test("authorization optional fields stay optional but must be strings when supplied", () => {
  assert.equal(validateAuthorization({ ...params, scope: "", state: "" }, client), "");
  for (const value of [null, 1, [], {}]) {
    for (const key of ["scope", "state", "client_id", "redirect_uri", "response_type"]) {
      assert.notEqual(validateAuthorization({ ...params, [key]: value }, client), "");
    }
  }
});

test("RFC 7636 verifier uses 43 through 128 unreserved ASCII characters", () => {
  for (const value of ["A".repeat(43), "z".repeat(128), "Ab09-._~".repeat(8)]) assert.equal(validCodeVerifier(value), true);
  for (const value of [undefined, null, [], {}, "A".repeat(42), "A".repeat(129), "A".repeat(43) + "\n",
    "A".repeat(43) + "\r", "A".repeat(42) + "=", "A".repeat(42) + "é", "A".repeat(42) + "+"]) {
    assert.equal(validCodeVerifier(value), false, JSON.stringify(value));
  }
});
