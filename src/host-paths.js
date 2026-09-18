// Profile identifiers are routing/storage namespaces, never OS capability restrictions.
import os from "node:os";
import path from "node:path";
export function hostId(value) {
  if (typeof value !== "string" || !/^[a-f0-9]{8}-[a-f0-9]{4}-4[a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/.test(value)) throw new Error("A canonical Hostgate UUID is required.");
  return value;
}
export function activeHostId() {
  const value = process.env.HOSTGATE_PROFILE_ID;
  return value === undefined ? null : hostId(value);
}
export function hostPaths(id, home = os.homedir()) {
  id = hostId(id);
  const config = path.join(home, ".config", "hostgate", "hosts", id);
  const data = path.join(home, ".local", "share", "hostgate", "hosts", id);
  return { config, data, managed: path.join(config, "managed"), credentials: path.join(config, process.platform === "win32" ? "credentials.dpapi" : "credentials.json"),
    oauth: path.join(data, "oauth-state.json"), status: path.join(data, "status.json"), logs: path.join(data, "executions.jsonl") };
}
