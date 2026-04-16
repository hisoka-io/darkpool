import {
  NotePlaintext,
  encryptNoteDeposit,
  toFr,
  addressToFr,
  deriveSharedSecret,
  Poseidon,
  LeanIMT,
} from "../src";
import { Base8, mulPointEscalar } from "@zk-kit/baby-jubjub";
import { Fr } from "@aztec/foundation/fields";
import { packToNoir, fmt } from "./lib/helpers.js";

async function main() {
    console.log("--- GENERATING GAS PAYMENT VECTORS ---\n");

    const COMPLIANCE_SK = 987654321n;
    const COMPLIANCE_PK = mulPointEscalar(Base8, COMPLIANCE_SK);
    const RELAYER_ADDR = addressToFr("0x1111222233334444555566667777888899990000");
    const EXECUTION_HASH = toFr("0xabcdef1234567890"); // Mock payload hash
    const PAYMENT_VAL = 10n;
    const ASSET_ID = addressToFr("0x1234567890123456789012345678901234567890"); // Mock USDC

    const oldVal = 100n;
    const oldNote: NotePlaintext = {
        value: toFr(oldVal),
        asset_id: ASSET_ID,
        secret: toFr(123n),
        nullifier: toFr(456n), // Path A nullifier secret
        timelock: toFr(0n),
        hashlock: toFr(0n),
    };

    const oldNonce = toFr(1n);
    const skView = toFr(555n); // User view key
    const oldRes = await encryptNoteDeposit(skView, oldNonce, oldNote, COMPLIANCE_PK);

    const oldSharedSecret = await deriveSharedSecret(oldRes.ephemeral_sk_used, COMPLIANCE_PK);

    // Build Merkle Tree
    const packedFrs = [];
    let idx = 0;
    for (let p = 0; p < 7; p++) {
        let val = 0n;
        const bytes = p < 6 ? 31 : 22;
        let power = 1n;
        for (let i = 0; i < bytes; i++) {
            val += BigInt(oldRes.ciphertext[idx]) * power;
            power *= 256n;
            idx++;
        }
        packedFrs.push(new Fr(val));
    }
    const oldCommitment = await Poseidon.hash(packedFrs);

    const tree = new LeanIMT(32);
    await tree.insert(oldCommitment);
    const root = tree.getRoot();
    const path = tree.getMerklePath(0); // Index 0

    const changeVal = oldVal - PAYMENT_VAL;
    const changeNote: NotePlaintext = {
        ...oldNote,
        value: toFr(changeVal),
        secret: toFr(789n),    // New secret
        nullifier: toFr(1011n) // New nullifier
    };

    const changeNonce = toFr(2n);
    const changeRes = await encryptNoteDeposit(skView, changeNonce, changeNote, COMPLIANCE_PK);

    console.log(`
    let merkle_root = ${fmt(root)};
    let current_timestamp = 0;
    let payment_value = ${fmt(PAYMENT_VAL)};
    let payment_asset_id = ${fmt(ASSET_ID)};
    let relayer_address = ${fmt(RELAYER_ADDR)};
    let execution_hash = ${fmt(EXECUTION_HASH)};
    let compliance_pubkey_x = ${fmt(COMPLIANCE_PK[0])};
    let compliance_pubkey_y = ${fmt(COMPLIANCE_PK[1])};

    let old_note = Note {
        asset_id: ${fmt(oldNote.asset_id)}, value: ${fmt(oldNote.value)},
        secret: ${fmt(oldNote.secret)}, nullifier: ${fmt(oldNote.nullifier)},
        timelock: ${fmt(oldNote.timelock)}, hashlock: ${fmt(oldNote.hashlock)}
    };
    let old_shared_secret = ${fmt(oldSharedSecret)};
    let old_note_index = 0;
    let old_note_path = [${path.map(p => p.toString()).join(", ")}];
    let hashlock_preimage = 0;

    let change_note = Note {
        asset_id: ${fmt(changeNote.asset_id)}, value: ${fmt(changeNote.value)},
        secret: ${fmt(changeNote.secret)}, nullifier: ${fmt(changeNote.nullifier)},
        timelock: ${fmt(changeNote.timelock)}, hashlock: ${fmt(changeNote.hashlock)}
    };
    let change_ephemeral_sk = ${fmt(changeRes.ephemeral_sk_used)};

    // Expected Outputs
    let exp_nullifier_hash = ${fmt(await Poseidon.hashScalar(oldNote.nullifier))};
    let exp_change_epk_x = ${fmt(changeRes.ephemeralPK[0])};
    let exp_change_epk_y = ${fmt(changeRes.ephemeralPK[1])};
    let exp_change_ct = ${packToNoir(changeRes.ciphertext)};

    let (nf, epk_x, epk_y, ct) = main(
        merkle_root, current_timestamp, payment_value, payment_asset_id,
        relayer_address, execution_hash,
        compliance_pubkey_x, compliance_pubkey_y,
        old_note, old_shared_secret, old_note_index, old_note_path, hashlock_preimage,
        change_note, change_ephemeral_sk
    );

    assert(nf == exp_nullifier_hash);
    assert(epk_x == exp_change_epk_x);
    assert(epk_y == exp_change_epk_y);
    assert(ct == exp_change_ct);
  `);
}

main().catch((err) => { console.error(err); process.exit(1); });