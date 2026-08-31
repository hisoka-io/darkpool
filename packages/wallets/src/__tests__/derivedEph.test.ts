import { describe, it, expect } from "vitest";
import { Fr } from "@aztec/foundation/fields";
import { randScalar, scalarBaseMul } from "../tss/bjj.js";
import { DarkAccount } from "../keys/DarkAccount.js";
import { KeyRepository } from "../state/KeyRepository.js";
import { InMemoryEphemeralCounterStore } from "../state/EphemeralCounterStore.js";
import { deriveSelfEphemeral } from "../note/keys.js";
import { deriveCek } from "../crypto/kem.js";
import type { DerivedEph } from "../types/ephemeral.js";
import type { SelfEphemeral } from "../repositories.js";

const MNEMONIC = "test test test test test test test test test test test junk";

// These pins are checked by `pnpm --filter @hisoka/wallets run typecheck`, which is the only gate that
// typechecks this package's tests: tsconfig.json excludes them and vitest strips types with esbuild.
// If a directive below ever becomes unused, the brand has been widened and the gate says so.
describe("the derived-ephemeral brand", () => {
  it("rejects a sampled scalar at every self-family surface", () => {
    const sampled = new Fr(randScalar());

    // @ts-expect-error a sampled Fr is not a DerivedEph
    const asEph: DerivedEph = sampled;
    expect(asEph).toBeDefined();

    const witness: SelfEphemeral = {
      // @ts-expect-error SelfEphemeral.eph carries the brand
      eph: sampled,
      ephPub: scalarBaseMul(sampled.toBigInt()),
      index: 0,
    };
    expect(witness).toBeDefined();
  });

  it("stays additive, so a derived value flows into any Fr sink", async () => {
    const account = await DarkAccount.fromMnemonic(MNEMONIC);
    const eph = await account.getSelfEphemeral(0n);
    // deriveCek takes a bare Fr and is legitimately called with random memo ephemerals too. The brand
    // must not obstruct that direction.
    expect(deriveCek(eph, scalarBaseMul(randScalar()))).toBeDefined();
  });

  it("derives, rather than samples, at the standard-path source", async () => {
    const account = await DarkAccount.fromMnemonic(MNEMONIC);
    const view = await account.getViewKey();
    const a = await deriveSelfEphemeral(view, 3n);
    const b = await deriveSelfEphemeral(view, 3n);
    expect(a.equals(b)).toBe(true);
  });

  // The wallet's tag map recognizes derived self ephemerals only.
  it("a sampled ephemeral is not recognised by the wallet's own tag map", async () => {
    const account = await DarkAccount.fromMnemonic(MNEMONIC);
    const repo = new KeyRepository(
      account,
      new InMemoryEphemeralCounterStore(),
    );
    const minted = await repo.nextSelfEphemeral();

    expect(repo.matchSelfTag(minted.ephPub[0])).not.toBeNull();

    const sampled = new Fr(randScalar());
    const sampledPub = scalarBaseMul(sampled.toBigInt());
    expect(repo.matchSelfTag(sampledPub[0])).toBeNull();
  });
});
