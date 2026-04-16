import { NotePlaintext, encryptNoteDeposit, toFr, addressToFr } from "../src";
import { Base8, mulPointEscalar } from "@zk-kit/baby-jubjub";
import { packToNoir, fmt } from "./lib/helpers.js";

async function main() {
  console.log("--- DEPOSIT VECTORS ---");
  const COMPLIANCE_SK = 987654321n;
  const COMPLIANCE_PK = mulPointEscalar(Base8, COMPLIANCE_SK);

  const note: NotePlaintext = {
    value: toFr(100n),
    asset_id: addressToFr("0x0d500b1d8e8ef31e21c99d1db9a6444d3adf1270"),
    secret: toFr(123n),
    nullifier: toFr(456n),
    timelock: toFr(0n),
    hashlock: toFr(0n),
  };
  const nonce = toFr(1n);

  const result = await encryptNoteDeposit(
    toFr(11111n),
    nonce,
    note,
    COMPLIANCE_PK,
  );

  console.log(`
    let compliance_pubkey_x = ${fmt(COMPLIANCE_PK[0])};
    let compliance_pubkey_y = ${fmt(COMPLIANCE_PK[1])};
    
    let note_plaintext = Note {
        asset_id: ${fmt(note.asset_id)},
        value: ${fmt(note.value)},
        secret: ${fmt(note.secret)},
        nullifier: ${fmt(note.nullifier)},
        timelock: ${fmt(note.timelock)},
        hashlock: ${fmt(note.hashlock)}
    };
    let ephemeral_sk = ${fmt(result.ephemeral_sk_used)};

    // Expected Outputs
    let exp_epk_x = ${fmt(result.ephemeralPK[0])};
    let exp_epk_y = ${fmt(result.ephemeralPK[1])};
    let exp_ct = ${packToNoir(result.ciphertext)};
    
    let (epk_x, epk_y, val, asset, packed_ct) = main(
        compliance_pubkey_x, compliance_pubkey_y,
        note_plaintext, ephemeral_sk
    );

    assert(epk_x == exp_epk_x);
    assert(epk_y == exp_epk_y);
    assert(val == note_plaintext.value);
    assert(packed_ct == exp_ct);
    `);
}

main().catch((err) => { console.error(err); process.exit(1); });
