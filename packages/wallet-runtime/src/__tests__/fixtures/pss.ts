import {
  decodeStatePayload,
  emptyStatePayload,
  serializeStatePayload,
  type ParsedStatePayload,
} from "@hisoka/pss-client";
import type { PssStatePort } from "../../pss/noteMirror.js";

export const INSTALL = "0x11111111111111111111111111111111";

/** A PSS port over an in-memory payload that round-trips every write through the real schema parser. */
export class FakePss implements PssStatePort {
  payload: ParsedStatePayload = emptyStatePayload(INSTALL, "web", 1);
  state: PssStatePort["state"] = { mode: "writer", heldBy: null };
  current(): ParsedStatePayload {
    return decodeStatePayload(serializeStatePayload(this.payload));
  }
  async update(
    change: (current: ParsedStatePayload) => ParsedStatePayload,
  ): Promise<void> {
    this.payload = decodeStatePayload(
      serializeStatePayload(change(this.current())),
    );
  }
  async mutateAsWriterDurably<T>(
    change: (current: ParsedStatePayload) => {
      readonly payload: ParsedStatePayload;
      readonly value: T;
    },
  ): Promise<T> {
    const out = change(this.current());
    await this.update(() => out.payload);
    return out.value;
  }
}
