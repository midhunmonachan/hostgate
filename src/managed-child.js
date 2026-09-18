// Local supervisor protocol only. Public MCP routes and tool authority are unchanged.
import net from "node:net";
import path from "node:path";
import { pathToFileURL } from "node:url";

if (!process.send || !process.argv[2]) throw new Error("Launch this entry point through the Hostgate manager.");
let listener;
const originalListen = net.Server.prototype.listen;
net.Server.prototype.listen = function (...args) {
  // A profile takes a named-pipe lease before its TCP HTTP listener.
  if (typeof args[0] !== "number" && !(args[0] && typeof args[0] === "object" && "port" in args[0])) return originalListen.apply(this, args);
  net.Server.prototype.listen = originalListen;
  listener = this;
  this.once("listening", () => {
    const address = this.address();
    process.send?.({ type: "ready", pid: process.pid, port: address.port, address: address.address });
  });
  return originalListen.apply(this, args);
};
function shutdown() {
  const deadline = setTimeout(() => process.exit(0), 10000);
  deadline.unref();
  if (!listener) process.exit(0);
  listener.close(() => process.exit(0));
  listener.closeIdleConnections?.();
}
process.on("message", (message) => { if (message?.operation === "shutdown") shutdown(); });
process.on("disconnect", () => process.exit(1));
try { await import(pathToFileURL(path.resolve(process.argv[2], "src", "server.js")).href); }
catch { process.send?.({ type: "failed" }); process.exitCode = 1; process.disconnect(); }
