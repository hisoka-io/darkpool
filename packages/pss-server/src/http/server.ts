import {
  createServer,
  type IncomingMessage,
  type Server,
  type ServerResponse,
} from "node:http";
import {
  type Collection,
  type GetBlobResponse,
  PSS_STATUS,
  PssProtocolError,
  decodeAccountIdPath,
  decodeCollectionPath,
  deletePreimage,
  encodeGetBlobResponse,
  parseDeleteAccountRequest,
  parsePutBlobRequest,
  putPreimage,
  toHexRaw,
} from "@hisoka/pss-client/wire";
import type { ServerConfig } from "../config.js";
import { today } from "../db/migrate.js";
import type { InviteGate, SlotStore } from "../db/slotStore.js";
import { ownsAccount, sha256, verifyEd25519, withinSkew } from "../auth.js";
import type { RequestCounters, RouteName } from "../metrics.js";
import type { RateLimiter } from "../rateLimit.js";
import type { ReplayGuard } from "../replayGuard.js";
import { decodeJson, readBody } from "./body.js";
import {
  MAX_DELETE_BODY_BYTES,
  base64Bytes,
  maxPutBodyBytes,
} from "./limits.js";

const METHOD_NOT_ALLOWED = 405;
const INTERNAL_ERROR = 500;
const MS_PER_SECOND = 1000;
const PATH_ROOT = "v1";
const PATH_RESOURCE = "blob";
const ACCOUNT_SEGMENTS = 3;
const BLOB_SEGMENTS = 4;

export interface ServerDeps {
  readonly config: ServerConfig;
  readonly store: SlotStore;
  readonly limiter: RateLimiter;
  readonly replay: ReplayGuard;
  readonly counters: RequestCounters;
  readonly now: () => number;
}

type Route =
  | {
      readonly kind: "blob";
      readonly accountId: Uint8Array;
      readonly collection: Collection;
    }
  | { readonly kind: "account"; readonly accountId: Uint8Array }
  | { readonly kind: "none" };

interface Reply {
  readonly status: number;
  readonly body: GetBlobResponse | null;
  readonly allow?: string;
}

function bare(status: number): Reply {
  return { status, body: null };
}

function notAllowed(allow: string): Reply {
  return { status: METHOD_NOT_ALLOWED, body: null, allow };
}

function parseRoute(target: string): Route {
  const query = target.indexOf("?");
  const path = query === -1 ? target : target.slice(0, query);
  const segments = path.split("/").filter((segment) => segment.length > 0);
  if (segments[0] !== PATH_ROOT || segments[1] !== PATH_RESOURCE) {
    return { kind: "none" };
  }
  if (segments.length === ACCOUNT_SEGMENTS) {
    return { kind: "account", accountId: decodeAccountIdPath(segments[2]) };
  }
  if (segments.length === BLOB_SEGMENTS) {
    return {
      kind: "blob",
      accountId: decodeAccountIdPath(segments[2]),
      collection: decodeCollectionPath(segments[3]),
    };
  }
  return { kind: "none" };
}

function routeName(route: Route, method: string | undefined): RouteName {
  if (route.kind === "blob" && method === "GET") return "blob_get";
  if (route.kind === "blob" && method === "PUT") return "blob_put";
  if (route.kind === "account" && method === "DELETE") return "account_delete";
  return "other";
}

function seconds(deps: ServerDeps): number {
  return Math.floor(deps.now() / MS_PER_SECOND);
}

function inviteGate(config: ServerConfig, code: string | null): InviteGate {
  return config.inviteRequired ? { required: true, code } : { required: false };
}

function oversizedCiphertext(payload: unknown, cap: number): boolean {
  if (typeof payload !== "object" || payload === null) return false;
  const field = (payload as Record<string, unknown>).ciphertext;
  if (typeof field !== "string") return false;
  const size = base64Bytes(field);
  return size !== null && size > cap;
}

function handleGet(
  route: Extract<Route, { kind: "blob" }>,
  deps: ServerDeps,
): Reply {
  const slot = deps.store.get(route.accountId, route.collection);
  if (slot === null) return bare(PSS_STATUS.not_found);
  return {
    status: PSS_STATUS.ok,
    body: encodeGetBlobResponse({
      version: slot.version,
      prevVersion: slot.prevVersion,
      nonce: slot.nonce,
      ciphertext: slot.ciphertext,
      serverTime: seconds(deps),
    }),
  };
}

async function handlePut(
  req: IncomingMessage,
  route: Extract<Route, { kind: "blob" }>,
  deps: ServerDeps,
): Promise<Reply> {
  const read = await readBody(
    req,
    maxPutBodyBytes(
      deps.config.maxCiphertextBytes,
      deps.config.bodyHeadroomBytes,
    ),
  );
  if (!read.ok) {
    return bare(
      read.failure === "too_large"
        ? PSS_STATUS.payload_too_large
        : PSS_STATUS.bad_request,
    );
  }

  let payload: unknown;
  try {
    payload = decodeJson(read.bytes);
  } catch {
    return bare(PSS_STATUS.bad_request);
  }
  if (oversizedCiphertext(payload, deps.config.maxCiphertextBytes)) {
    return bare(PSS_STATUS.payload_too_large);
  }
  const put = parsePutBlobRequest(payload);

  if (!ownsAccount(put.authPk, route.accountId)) {
    return bare(PSS_STATUS.unauthorized);
  }
  const preimage = putPreimage({
    accountId: route.accountId,
    collection: route.collection,
    version: put.version,
    prevVersion: put.prevVersion,
    ciphertextDigest: sha256(put.ciphertext),
    timestamp: put.timestamp,
  });
  if (!verifyEd25519(preimage, put.sig, put.authPk)) {
    return bare(PSS_STATUS.unauthorized);
  }
  if (
    !withinSkew(put.timestamp, seconds(deps), deps.config.timestampSkewSeconds)
  ) {
    return bare(PSS_STATUS.unauthorized);
  }

  const stored = deps.store.get(route.accountId, route.collection);
  const storedVersion = stored?.version ?? 0;
  if (put.prevVersion !== storedVersion || put.version <= storedVersion) {
    return bare(PSS_STATUS.version_conflict);
  }
  const putSignature = toHexRaw(put.sig);
  if (deps.replay.seen(putSignature)) {
    return bare(PSS_STATUS.version_conflict);
  }
  if (!deps.limiter.take(toHexRaw(route.accountId))) {
    return bare(PSS_STATUS.rate_limited);
  }

  const outcome = deps.store.upsert(
    {
      accountId: route.accountId,
      collection: route.collection,
      version: put.version,
      prevVersion: put.prevVersion,
      nonce: put.nonce,
      ciphertext: put.ciphertext,
      updatedOn: today(new Date(deps.now())),
    },
    inviteGate(deps.config, put.invite),
  );
  if (outcome === "invite_rejected") return bare(PSS_STATUS.unauthorized);
  if (outcome === "conflict") return bare(PSS_STATUS.version_conflict);
  deps.replay.record(putSignature, seconds(deps));
  return bare(PSS_STATUS.ok);
}

async function handleDelete(
  req: IncomingMessage,
  route: Extract<Route, { kind: "account" }>,
  deps: ServerDeps,
): Promise<Reply> {
  const read = await readBody(req, MAX_DELETE_BODY_BYTES);
  if (!read.ok) {
    return bare(
      read.failure === "too_large"
        ? PSS_STATUS.payload_too_large
        : PSS_STATUS.bad_request,
    );
  }

  let payload: unknown;
  try {
    payload = decodeJson(read.bytes);
  } catch {
    return bare(PSS_STATUS.bad_request);
  }
  const request = parseDeleteAccountRequest(payload);

  if (!ownsAccount(request.authPk, route.accountId)) {
    return bare(PSS_STATUS.unauthorized);
  }
  const preimage = deletePreimage({
    accountId: route.accountId,
    nonce: request.nonce,
    timestamp: request.timestamp,
  });
  if (!verifyEd25519(preimage, request.sig, request.authPk)) {
    return bare(PSS_STATUS.unauthorized);
  }
  if (
    !withinSkew(
      request.timestamp,
      seconds(deps),
      deps.config.timestampSkewSeconds,
    )
  ) {
    return bare(PSS_STATUS.unauthorized);
  }
  const deleteSignature = toHexRaw(request.sig);
  if (deps.replay.seen(deleteSignature)) {
    return bare(PSS_STATUS.unauthorized);
  }
  if (!deps.limiter.take(toHexRaw(route.accountId))) {
    return bare(PSS_STATUS.rate_limited);
  }

  // Recorded only when rows actually went away. A self-signed delete for an invented account erases
  // nothing, so it must not spend a guard slot; the reply stays a bare 200 either way, so declining to
  // record does not turn into an account-existence oracle.
  if (deps.store.deleteAccount(route.accountId) > 0) {
    deps.replay.record(deleteSignature, seconds(deps));
  }
  return bare(PSS_STATUS.ok);
}

function route(
  req: IncomingMessage,
  target: Route,
  deps: ServerDeps,
): Promise<Reply> | Reply {
  if (target.kind === "blob") {
    if (req.method === "GET") return handleGet(target, deps);
    if (req.method === "PUT") return handlePut(req, target, deps);
    return notAllowed("GET, PUT");
  }
  if (target.kind === "account") {
    if (req.method === "DELETE") return handleDelete(req, target, deps);
    return notAllowed("DELETE");
  }
  return bare(PSS_STATUS.not_found);
}

// Every failure is a bare status. An error string that separated "no such account" from "bad signature"
// would answer, to anyone who asks, whether an account exists.
function send(req: IncomingMessage, res: ServerResponse, reply: Reply): void {
  const payload = reply.body === null ? "" : JSON.stringify(reply.body);
  const closing = reply.status === PSS_STATUS.payload_too_large;
  res.writeHead(reply.status, {
    "content-length": Buffer.byteLength(payload),
    "cache-control": "no-store",
    ...(reply.body === null ? {} : { "content-type": "application/json" }),
    ...(closing ? { connection: "close" } : {}),
    ...(reply.allow === undefined ? {} : { allow: reply.allow }),
  });
  res.end(payload, () => {
    if (closing) req.destroy();
  });
}

async function dispatch(
  req: IncomingMessage,
  res: ServerResponse,
  deps: ServerDeps,
): Promise<void> {
  let target: Route = { kind: "none" };
  let reply: Reply;
  try {
    target = parseRoute(req.url ?? "");
    reply = await route(req, target, deps);
  } catch (error) {
    reply = bare(
      error instanceof PssProtocolError
        ? PSS_STATUS.bad_request
        : INTERNAL_ERROR,
    );
  }
  deps.counters.record(routeName(target, req.method), reply.status);
  send(req, res, reply);
}

export function createPssServer(deps: ServerDeps): Server {
  // Node enforces requestTimeout and headersTimeout from a sweep whose interval defaults to 30 s, so
  // without this a 30 s budget is only noticed up to 30 s late. Tying the sweep to the headers timeout
  // bounds the overshoot to the tightest budget the server sets.
  const server = createServer(
    { connectionsCheckingInterval: deps.config.headersTimeoutMs },
    (req, res) => {
      dispatch(req, res, deps).catch(() => {
        if (!res.headersSent) {
          res.writeHead(INTERNAL_ERROR, { "content-length": 0 });
        }
        res.end();
      });
    },
  );
  // The body is read before the signature can be checked, because the signature covers a digest of it,
  // so these bound what an unauthenticated caller can hold. Node's defaults are a 300 s request timeout
  // and no connection cap, which leaves retained buffers per half-open upload times unbounded sockets.
  server.requestTimeout = deps.config.requestTimeoutMs;
  server.headersTimeout = deps.config.headersTimeoutMs;
  server.maxConnections = deps.config.maxConnections;
  return server;
}
