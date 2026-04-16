import { NotePlaintext, toFr, addressToFr, Poseidon } from "../src";
import { Base8, mulPointEscalar } from "@zk-kit/baby-jubjub";
import { ethers } from "ethers";
import { packToNoir, fmt } from "./lib/helpers.js";

async function main() {
  console.log("--- PUBLIC CLAIM VECTORS ---");
  const COMPLIANCE_PK = mulPointEscalar(Base8, 987654321n);

  const val = toFr(100n);
  const assetId = addressToFr("0x1234567890123456789012345678901234567890");
  const timelock = toFr(0n);
  const salt = toFr(ethers.toBigInt(ethers.randomBytes(31)));

  const recipientSk = toFr(12345n);
  const recipientPk = mulPointEscalar(Base8, recipientSk.toBigInt());
  const ownerX = toFr(recipientPk[0]);
  const ownerY = toFr(recipientPk[1]);

  const memoId = await Poseidon.hash([
    val,
    assetId,
    timelock,
    ownerX,
    ownerY,
    salt,
  ]);

  const noteOut: NotePlaintext = {
    value: val,
    asset_id: assetId,
    secret: toFr(999n),
    nullifier: toFr(888n),
    timelock: toFr(0n),
    hashlock: toFr(0n),
  };
  const skOut = toFr(777n);

  // Manual encryption to match circuit `sk_out` (encryptNoteDeposit derives keys differently)
  const { aes128Encrypt, deriveSharedSecret, kdfToAesKeyIV } = await import(
    "../src/crypto"
  );
  const ssOut = await deriveSharedSecret(skOut, COMPLIANCE_PK);
  const { key, iv } = await kdfToAesKeyIV(ssOut);
  const plainBytes = await import("../src/crypto/packing").then((m) =>
    m.packNotePlaintext(noteOut),
  );
  const ctOut = await aes128Encrypt(plainBytes, key, iv);

  const epkOut = mulPointEscalar(Base8, skOut.toBigInt());

  console.log(
    "// [PUBLIC_CLAIM] COPY INTO packages/circuits/public_claim/src/main.nr",
  );
  console.log(`
    let memo_id = ${fmt(memoId)};
    let compliance_pubkey_x = ${fmt(COMPLIANCE_PK[0])};
    let compliance_pubkey_y = ${fmt(COMPLIANCE_PK[1])};

    // Private Inputs
    let val = ${fmt(val)};
    let asset_id = ${fmt(assetId)};
    let timelock = ${fmt(timelock)};
    let owner_x = ${fmt(ownerX)};
    let owner_y = ${fmt(ownerY)};
    let salt = ${fmt(salt)};

    let recipient_sk = ${fmt(recipientSk)};

    let note_out = Note {
        asset_id: ${fmt(noteOut.asset_id)}, value: ${fmt(noteOut.value)},
        secret: ${fmt(noteOut.secret)}, nullifier: ${fmt(noteOut.nullifier)},
        timelock: 0, hashlock: 0
    };
    let sk_out = ${fmt(skOut)};

    // Expected Outputs
    let exp_epk_x = ${fmt(epkOut[0])};
    let exp_epk_y = ${fmt(epkOut[1])};
    let exp_ct = ${packToNoir(ctOut)};

    let (epk_x, epk_y, ct, asset_ret) = main(
        memo_id, compliance_pubkey_x, compliance_pubkey_y,
        val, asset_id, timelock, owner_x, owner_y, salt,
        recipient_sk,
        note_out, sk_out
    );

    assert(epk_x == exp_epk_x);
    assert(epk_y == exp_epk_y);
    assert(ct == exp_ct);
    assert(asset_ret == asset_id);
    `);
}

main().catch((err) => { console.error(err); process.exit(1); });
