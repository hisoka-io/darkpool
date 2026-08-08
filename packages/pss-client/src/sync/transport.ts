import { Collection } from "../wire/collection.js";
import {
  DeleteAccountRequest,
  GetBlobResponse,
  PutBlobRequest,
  parseGetBlobResponse,
} from "../wire/types.js";
import { PSS_STATUS, PssError, PssFailure } from "../wire/errors.js";

// A 404 is an outcome, not a failure: an account that has never been written has no blob. Every other
// non-200 is a typed PssError carrying the wire failure code.
export interface PssTransport {
  getBlob(
    accountPath: string,
    collection: Collection,
  ): Promise<GetBlobResponse | null>;
  putBlob(
    accountPath: string,
    collection: Collection,
    body: PutBlobRequest,
  ): Promise<void>;
  deleteAccount(accountPath: string, body: DeleteAccountRequest): Promise<void>;
}

export interface HttpResponse {
  readonly status: number;
  json(): Promise<unknown>;
}

export interface HttpRequest {
  readonly method: string;
  readonly headers: Readonly<Record<string, string>>;
  readonly body?: string;
  readonly signal?: AbortSignal;
}

// Injected rather than reaching for globalThis.fetch, so a test can serve a response no honest server
// would produce. Typed structurally to keep this package off the DOM lib.
export type HttpFetch = (
  url: string,
  request: HttpRequest,
) => Promise<HttpResponse>;

export interface HttpTransportOptions {
  readonly baseUrl: string;
  readonly fetch: HttpFetch;
  readonly timeoutMs: number;
}

const JSON_HEADERS: Readonly<Record<string, string>> = {
  "content-type": "application/json",
};

const FAILURE_BY_STATUS: ReadonlyMap<number, PssFailure> = new Map([
  [PSS_STATUS.unauthorized, { code: "unauthorized" } as PssFailure],
  [PSS_STATUS.version_conflict, { code: "version_conflict" } as PssFailure],
  [PSS_STATUS.rate_limited, { code: "rate_limited" } as PssFailure],
]);

function failureFor(status: number, limit: number): PssFailure {
  const known = FAILURE_BY_STATUS.get(status);
  if (known !== undefined) return known;
  if (status === PSS_STATUS.payload_too_large) {
    return { code: "payload_too_large", limit };
  }
  return { code: "bad_request", field: `status ${status}` };
}

function blobUrl(
  baseUrl: string,
  accountPath: string,
  collection: Collection,
): string {
  return `${baseUrl}/v1/blob/${accountPath}/${collection}`;
}

export function createHttpTransport(
  options: HttpTransportOptions,
): PssTransport {
  async function send(
    url: string,
    method: string,
    body?: unknown,
  ): Promise<HttpResponse> {
    const controller = new AbortController();
    const timer = setTimeout(() => {
      controller.abort();
    }, options.timeoutMs);
    try {
      return await options.fetch(url, {
        method,
        headers: JSON_HEADERS,
        // Compact on purpose. The server's body cap carries headroom, but a client that pretty-prints
        // spends it for nothing, and a maximal create has the least room of any request.
        ...(body === undefined ? {} : { body: JSON.stringify(body) }),
        signal: controller.signal,
      });
    } catch (error) {
      throw new PssError(
        { code: "bad_request", field: "transport" },
        `${method} ${url} did not complete: ${
          error instanceof Error ? error.message : String(error)
        }`,
      );
    } finally {
      clearTimeout(timer);
    }
  }

  function refuse(response: HttpResponse, what: string): never {
    const failure = failureFor(response.status, 0);
    throw new PssError(failure, `${what} answered ${response.status}`);
  }

  return {
    async getBlob(accountPath, collection) {
      const url = blobUrl(options.baseUrl, accountPath, collection);
      const response = await send(url, "GET");
      if (response.status === PSS_STATUS.not_found) return null;
      if (response.status !== PSS_STATUS.ok) {
        refuse(response, `GET ${collection}`);
      }
      return parseGetBlobResponse(await response.json());
    },

    async putBlob(accountPath, collection, body) {
      const url = blobUrl(options.baseUrl, accountPath, collection);
      const response = await send(url, "PUT", body);
      if (response.status !== PSS_STATUS.ok) {
        refuse(response, `PUT ${collection} version ${body.version}`);
      }
    },

    async deleteAccount(accountPath, body) {
      const url = `${options.baseUrl}/v1/blob/${accountPath}`;
      const response = await send(url, "DELETE", body);
      if (response.status !== PSS_STATUS.ok) refuse(response, "DELETE account");
    },
  };
}
