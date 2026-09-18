// OAuth perimeter validation only; this module does not restrict authorized MCP tools.
// RFC 7591 (registration), RFC 9700 section 2.1 (exact redirects), RFC 7636 (S256).
export function isObject(value) {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

export function validRedirectUri(value) {
  if (typeof value !== "string" || !/^https?:\/\//i.test(value) ||
      /[\u0000-\u0020\u007f\\#]/.test(value) || /%(?![\da-f]{2})/i.test(value)) return false;
  try {
    const url = new URL(value);
    const authority = value.match(/^https?:\/\/([^/?#]*)/i)[1];
    if (!authority || !url.hostname || authority.includes("@") || url.username || url.password || url.hostname.includes("*")) return false;
    // HTTP is only for literal loopback callbacks used by local clients/tests.
    // Never resolve arbitrary hostnames to decide whether a callback is loopback.
    return url.protocol === "https:" || (url.protocol === "http:" &&
      /^(127\.0\.0\.1|\[::1\])(?::[0-9]+)?$/.test(authority));
  } catch {
    return false;
  }
}

export function validateRegistration(body) {
  if (!isObject(body)) return "invalid_client_metadata";
  if (!Array.isArray(body.redirect_uris) || body.redirect_uris.length === 0 ||
      !body.redirect_uris.every(validRedirectUri)) return "invalid_redirect_uri";
  if (body.client_name !== undefined && (typeof body.client_name !== "string" ||
      !body.client_name.trim() || body.client_name.length > 256 || /[\u0000-\u001f\u007f]/.test(body.client_name))) {
    return "invalid_client_metadata";
  }
  if (body.token_endpoint_auth_method !== undefined && body.token_endpoint_auth_method !== "none") {
    return "invalid_client_metadata";
  }
  for (const [field, supported] of [["grant_types", "authorization_code"], ["response_types", "code"]]) {
    const requested = body[field];
    if (requested !== undefined && (!Array.isArray(requested) ||
        !requested.every((value) => typeof value === "string" && value.length > 0) || !requested.includes(supported))) {
      return "invalid_client_metadata";
    }
  }
  // Keep the existing response's supported subset (code/authorization_code/none).
  // Unknown extension metadata is ignored, not fetched or treated as verified identity.
  return "";
}

export function validateClientRedirect(clientId, redirectUri, client) {
  if (typeof clientId !== "string" || !clientId || !isObject(client) || client.clientId !== clientId) {
    return "OAuth client is not registered. Reconnect using a registered client.";
  }
  if (!validRedirectUri(redirectUri) || !Array.isArray(client.redirectUris) ||
      client.redirectUris.length === 0 || !client.redirectUris.every(validRedirectUri) ||
      !client.redirectUris.includes(redirectUri)) {
    return "Redirect URI is not registered for this client.";
  }
  // Compare the original strings, never their normalized URL representations.
  // Ports are exact too: native clients must register the actual loopback callback.
  return "";
}

export function validateAuthorization(params, client) {
  if (!isObject(params)) return "Invalid OAuth parameters.";
  if (params.response_type !== "code") return "Unsupported response_type.";
  const callbackError = validateClientRedirect(params.client_id, params.redirect_uri, client);
  if (callbackError) return callbackError;
  if (params.code_challenge_method !== "S256" || typeof params.code_challenge !== "string" ||
      (params.code_challenge.length !== 43 || /[^A-Za-z0-9_-]/.test(params.code_challenge))) return "A valid S256 PKCE challenge is required.";
  for (const key of ["state", "scope"]) {
    if (params[key] !== undefined && typeof params[key] !== "string") return "Invalid OAuth parameters.";
  }
  return "";
}

export function validCodeVerifier(value) {
  return typeof value === "string" && value.length >= 43 && value.length <= 128 && !/[^A-Za-z0-9._~-]/.test(value);
}
