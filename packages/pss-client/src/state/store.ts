import { Collection } from "../wire/collection.js";

// Injected and async on purpose. A browser extension service worker has no localStorage, React Native
// has none, and every viable substrate (chrome.storage.local, AsyncStorage) is promise-based.
export interface PssStore {
  get(key: string): Promise<string | null>;
  set(key: string, value: string): Promise<void>;
  remove(key: string): Promise<void>;
}

const NAMESPACE = "hisoka.pss.v1";

export function floorKey(accountId: string, collection: Collection): string {
  return `${NAMESPACE}.floor.${accountId}.${collection}`;
}

export function payloadKey(accountId: string, collection: Collection): string {
  return `${NAMESPACE}.payload.${accountId}.${collection}`;
}

export function installKey(accountId: string): string {
  return `${NAMESPACE}.install.${accountId}`;
}
