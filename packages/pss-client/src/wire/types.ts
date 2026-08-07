import { Collection, isCollection } from "./collection.js";
import {
  assertCount,
  assertLength,
  fromBase64,
  fromHexRaw,
  toBase64,
  toHexRaw,
} from "./codec.js";
import {
  ACCOUNT_ID_BYTES,
  ED25519_PUBLIC_KEY_BYTES,
  ED25519_SIGNATURE_BYTES,
  GCM_NONCE_BYTES,
  INVITE_CODE_MAX_CHARS,
  MAX_CIPHERTEXT_BYTES,
} from "./constants.js";
import { PssProtocolError } from "./errors.js";

const INVITE_SHAPE = /^[A-Za-z0-9_-]+$/;

export interface BlobSlotWire {
  readonly version: number;
  readonly prevVersion: number;
  readonly nonce: string;
  readonly ciphertext: string;
}

export interface GetBlobResponse extends BlobSlotWire {
  readonly serverTime: number;
}

export interface PutBlobRequest extends BlobSlotWire {
  readonly authPk: string;
  readonly sig: string;
  readonly timestamp: number;
  readonly invite?: string;
}

export interface DeleteAccountRequest {
  readonly authPk: string;
  readonly sig: string;
  readonly timestamp: number;
  readonly nonce: string;
}

export interface DecodedPutBlobRequest {
  readonly version: number;
  readonly prevVersion: number;
  readonly nonce: Uint8Array;
  readonly ciphertext: Uint8Array;
  readonly authPk: Uint8Array;
  readonly sig: Uint8Array;
  readonly timestamp: number;
  readonly invite: string | null;
}

export interface DecodedDeleteAccountRequest {
  readonly authPk: Uint8Array;
  readonly sig: Uint8Array;
  readonly timestamp: number;
  readonly nonce: Uint8Array;
}

export function encodeAccountIdPath(accountId: Uint8Array): string {
  return toHexRaw(assertLength(accountId, ACCOUNT_ID_BYTES, "accountId"));
}

export function decodeAccountIdPath(segment: string): Uint8Array {
  return assertLength(
    fromHexRaw(segment, "accountId"),
    ACCOUNT_ID_BYTES,
    "accountId",
  );
}

export function decodeCollectionPath(segment: string): Collection {
  if (!isCollection(segment)) {
    throw new PssProtocolError(`unknown collection: ${segment}`);
  }
  return segment;
}

function record(value: unknown, label: string): Record<string, unknown> {
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    throw new PssProtocolError(`${label} must be a JSON object`);
  }
  return value as Record<string, unknown>;
}

function text(value: unknown, label: string): string {
  if (typeof value !== "string") {
    throw new PssProtocolError(`${label} must be a string`);
  }
  return value;
}

function bytesField(
  value: unknown,
  expected: number,
  label: string,
): Uint8Array {
  return assertLength(fromBase64(text(value, label), label), expected, label);
}

function inviteField(value: unknown): string | null {
  if (value === undefined || value === null) return null;
  const code = text(value, "invite");
  if (code.length > INVITE_CODE_MAX_CHARS || !INVITE_SHAPE.test(code)) {
    throw new PssProtocolError("invite is not a valid code");
  }
  return code;
}

export function parsePutBlobRequest(body: unknown): DecodedPutBlobRequest {
  const raw = record(body, "put body");
  const ciphertext = fromBase64(
    text(raw.ciphertext, "ciphertext"),
    "ciphertext",
  );
  if (ciphertext.length === 0 || ciphertext.length > MAX_CIPHERTEXT_BYTES) {
    throw new PssProtocolError(
      `ciphertext must be 1..${MAX_CIPHERTEXT_BYTES} bytes, got ${ciphertext.length}`,
    );
  }
  return {
    version: assertCount(raw.version, "version"),
    prevVersion: assertCount(raw.prevVersion, "prevVersion"),
    nonce: bytesField(raw.nonce, GCM_NONCE_BYTES, "nonce"),
    ciphertext,
    authPk: bytesField(raw.authPk, ED25519_PUBLIC_KEY_BYTES, "authPk"),
    sig: bytesField(raw.sig, ED25519_SIGNATURE_BYTES, "sig"),
    timestamp: assertCount(raw.timestamp, "timestamp"),
    invite: inviteField(raw.invite),
  };
}

export function parseDeleteAccountRequest(
  body: unknown,
): DecodedDeleteAccountRequest {
  const raw = record(body, "delete body");
  return {
    authPk: bytesField(raw.authPk, ED25519_PUBLIC_KEY_BYTES, "authPk"),
    sig: bytesField(raw.sig, ED25519_SIGNATURE_BYTES, "sig"),
    timestamp: assertCount(raw.timestamp, "timestamp"),
    nonce: bytesField(raw.nonce, GCM_NONCE_BYTES, "nonce"),
  };
}

export function parseGetBlobResponse(body: unknown): GetBlobResponse {
  const raw = record(body, "get response");
  const response: GetBlobResponse = {
    version: assertCount(raw.version, "version"),
    prevVersion: assertCount(raw.prevVersion, "prevVersion"),
    nonce: text(raw.nonce, "nonce"),
    ciphertext: text(raw.ciphertext, "ciphertext"),
    serverTime: assertCount(raw.serverTime, "serverTime"),
  };
  assertLength(fromBase64(response.nonce, "nonce"), GCM_NONCE_BYTES, "nonce");
  const ciphertext = fromBase64(response.ciphertext, "ciphertext");
  if (ciphertext.length === 0 || ciphertext.length > MAX_CIPHERTEXT_BYTES) {
    throw new PssProtocolError(
      `ciphertext must be 1..${MAX_CIPHERTEXT_BYTES} bytes, got ${ciphertext.length}`,
    );
  }
  return response;
}

export function encodeGetBlobResponse(slot: {
  readonly version: number;
  readonly prevVersion: number;
  readonly nonce: Uint8Array;
  readonly ciphertext: Uint8Array;
  readonly serverTime: number;
}): GetBlobResponse {
  return {
    version: slot.version,
    prevVersion: slot.prevVersion,
    nonce: toBase64(slot.nonce),
    ciphertext: toBase64(slot.ciphertext),
    serverTime: slot.serverTime,
  };
}
