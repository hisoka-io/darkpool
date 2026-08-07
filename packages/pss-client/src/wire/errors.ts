export type PssFailure =
  | { readonly code: "bad_request"; readonly field: string }
  | { readonly code: "unauthorized" }
  | { readonly code: "not_found" }
  | { readonly code: "version_conflict" }
  | { readonly code: "payload_too_large"; readonly limit: number }
  | { readonly code: "rate_limited" };

export type PssFailureCode = PssFailure["code"];

export const PSS_STATUS: Readonly<Record<PssFailureCode | "ok", number>> = {
  ok: 200,
  bad_request: 400,
  unauthorized: 401,
  not_found: 404,
  version_conflict: 409,
  payload_too_large: 413,
  rate_limited: 429,
};

export function statusOf(failure: PssFailure): number {
  return PSS_STATUS[failure.code];
}

export class PssError extends Error {
  public readonly failure: PssFailure;

  constructor(failure: PssFailure, detail: string) {
    super(`PSS ${failure.code}: ${detail}`);
    this.name = "PssError";
    this.failure = failure;
  }
}

export class PssProtocolError extends Error {
  constructor(detail: string) {
    super(`PSS protocol: ${detail}`);
    this.name = "PssProtocolError";
  }
}
