// One OAuth resource per configured endpoint; no host IDs, catalog or routing state.
export function assertSingleInstanceEnvironment(env) {
  if (Object.keys(env).some(key => /^(HOSTGATE_PROFILE_ID|HOSTGATE_PROFILE_STAGING)$/i.test(key))) {
    throw new Error("Retired profile configuration requires explicit migration to a single instance. No state was imported or replaced.");
  }
}
export function configuredResource(value) {
  if (value === undefined || value === "") return null;
  if (typeof value !== "string" || /[\s\\#?]/.test(value) || !value.startsWith("https://")) throw new Error("HOSTGATE_PUBLIC_URL must be an HTTPS MCP URL without credentials, query or fragment.");
  let url;
  try { url = new URL(value); } catch { throw new Error("Invalid HOSTGATE_PUBLIC_URL."); }
  if (url.username || url.password || !url.hostname || !["/mcp", "/hostgate/mcp"].includes(url.pathname)) {
    throw new Error("HOSTGATE_PUBLIC_URL must end in /mcp or /hostgate/mcp and contain no credentials.");
  }
  return url.href;
}
export function validResource(value, expected, required = false) {
  return value === undefined ? !required : typeof value === "string" && value === expected;
}
export function tokenResourceMatches(record, expected, required = false) {
  return !!record && validResource(record.resource, expected, required);
}
export function validateStateBinding(state, resource) {
  if (!state || typeof state !== "object" || Array.isArray(state) || state.hostId !== undefined || state.version === 2) {
    throw new Error("Retired profile OAuth state cannot be used implicitly by a single instance.");
  }
  if (state.version === 3) {
    if (!resource || state.resource !== resource) throw new Error("OAuth state belongs to a different endpoint, or endpoint binding was disabled.");
  } else if (state.version !== 1 || state.resource !== undefined) {
    throw new Error("Unsupported OAuth state version or binding.");
  }
  if (!Array.isArray(state.clients) || !Array.isArray(state.accessTokens)) throw new Error("Invalid OAuth state records.");
}
