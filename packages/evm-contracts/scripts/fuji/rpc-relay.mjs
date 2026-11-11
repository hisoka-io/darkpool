// A local JSON-RPC relay for the Fuji test build: forwards each POST to one upstream over a small pool of kept-alive
// connections, and retries only failures where the request cannot have reached the upstream (connect errors), with
// backoff. A burst of short-lived connections from one deploy got this machine's connections refused for minutes.
//
// Usage: node scripts/fuji/rpc-relay.mjs <port> <upstream https url>
import http from "node:http";
import https from "node:https";

const [portArg, upstreamArg] = process.argv.slice(2);
if (!portArg || !upstreamArg) {
  console.error("usage: rpc-relay.mjs <port> <upstream https url>");
  process.exit(2);
}
const upstream = new URL(upstreamArg);
const agent = new https.Agent({ keepAlive: true, maxSockets: 4 });
const CONNECT_ERRORS = new Set([
  "ECONNREFUSED",
  "ETIMEDOUT",
  "ENETUNREACH",
  "EHOSTUNREACH",
  "EAI_AGAIN",
]);
const MAX_ATTEMPTS = 12;

function forward(body) {
  return new Promise((resolve, reject) => {
    const req = https.request(
      upstream,
      {
        method: "POST",
        agent,
        headers: {
          "content-type": "application/json",
          "content-length": Buffer.byteLength(body),
        },
        timeout: 120000,
      },
      (res) => {
        const chunks = [];
        res.on("data", (c) => chunks.push(c));
        res.on("end", () =>
          resolve({
            status: res.statusCode ?? 502,
            body: Buffer.concat(chunks),
          }),
        );
        res.on("error", reject);
      },
    );
    req.on("timeout", () =>
      req.destroy(
        Object.assign(new Error("upstream response timeout"), {
          code: "RESPONSE_TIMEOUT",
        }),
      ),
    );
    req.on("error", reject);
    req.end(body);
  });
}

function connectError(err) {
  if (CONNECT_ERRORS.has(err.code)) return true;
  return (
    Array.isArray(err.errors) &&
    err.errors.every((e) => CONNECT_ERRORS.has(e.code))
  );
}

const server = http.createServer((req, res) => {
  const chunks = [];
  req.on("data", (c) => chunks.push(c));
  req.on("end", async () => {
    const body = Buffer.concat(chunks).toString("utf8");
    for (let attempt = 1; ; attempt++) {
      try {
        const out = await forward(body);
        if (out.status === 429 && attempt < MAX_ATTEMPTS)
          throw Object.assign(new Error("HTTP 429"), { code: "ETIMEDOUT" });
        res.writeHead(out.status, { "content-type": "application/json" });
        res.end(out.body);
        return;
      } catch (err) {
        if (!connectError(err) || attempt >= MAX_ATTEMPTS) {
          console.error(
            `relay: giving up after ${attempt} attempt(s): ${err.code ?? err.message}`,
          );
          res.writeHead(502, { "content-type": "application/json" });
          res.end(
            JSON.stringify({
              jsonrpc: "2.0",
              id: null,
              error: {
                code: -32603,
                message: `relay: ${err.code ?? err.message}`,
              },
            }),
          );
          return;
        }
        const wait = Math.min(30000, 2000 * attempt);
        console.error(
          `relay: ${err.code ?? "connect error"} on attempt ${attempt}; retrying in ${wait} ms`,
        );
        await new Promise((r) => setTimeout(r, wait));
      }
    }
  });
});
server.listen(Number(portArg), "127.0.0.1", () =>
  console.error(`relay: 127.0.0.1:${portArg} -> ${upstream.origin}`),
);
