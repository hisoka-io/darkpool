use crate::domains::PSI_DOMAIN;
use poseidon::poseidon2::Poseidon2;

pub global TWO_POW_32: Field = 4294967296;

// The wire-format seam and the note kinds. A spend circuit rejects any unexpected version, and each spend
// path hard-asserts its own note_type so a MULTISIG note can never be spent by a STANDARD verifier or vice
// versa (the on-chain router binds note_type -> verifier; note_type stays in the leaf as the last defense).
pub global NOTE_VERSION: Field = 1;
pub global NOTE_TYPE_STANDARD: Field = 0;
pub global NOTE_TYPE_MULTISIG: Field = 1;
// Reserved for a later break (single-owner predicate notes); NOT an accepted mint output yet.
pub global NOTE_TYPE_CONDITIONAL: Field = 2;

// A minted output's note_type is a sender-chosen witness, so it MUST be in the enabled set. A witnessed
// note_type outside it (e.g. the reserved CONDITIONAL) commits to a leaf no circuit consumes = a silent
// burn; and a future third verifier could retroactively spend it.
pub fn assert_valid_note_type(note_type: Field) {
    assert(
        (note_type == NOTE_TYPE_STANDARD) | (note_type == NOTE_TYPE_MULTISIG),
        "note_type not in {STANDARD, MULTISIG}",
    );
}

// asset_id is a 20-byte ERC20 address; a wider value is rejected so notes stay fungible with clean tokens.
pub fn assert_asset_id(asset_id: Field) {
    let _: [u8; 20] = asset_id.to_be_bytes();
}

// A consumed input, located by its leaf index. Single-tree: the index alone identifies a parent; a tree id
// returns only if a multi-tree layout is ever introduced.
pub struct Parent {
    pub leaf_index: u32,
}

// Committed note plaintext, ordered STABLE-FIRST: version/asset/type/conditions stay equal between a
// consumed and a created note, so a spend hashing both leaves reuses the shared 4-field sponge prefix.
pub struct Note {
    pub note_version: Field,
    pub asset_id: Field,
    pub note_type: Field,
    pub conditions_hash: Field,
    pub value: u128,
    pub owner: Field,
    pub psi: Field,
    pub parents: Field,
}

impl Note {
    // PLAINTEXT-commit leaf over all 8 fields (psi is one of them). Byte-identical to the TS `leaf`.
    pub fn leaf(self) -> Field {
        Poseidon2::hash(
            [
                self.note_version,
                self.asset_id,
                self.note_type,
                self.conditions_hash,
                self.value as Field,
                self.owner,
                self.psi,
                self.parents,
            ],
            8,
        )
    }
}

// Two consumed leaf indexes little-endian in one Field: index0 in bits 0..31, index1 in bits 32..63.
// Deposit and public-claim outputs have no consumed parent, so parents = 0.
pub fn pack_parents(parents: [Parent; 2]) -> Field {
    (parents[0].leaf_index as Field) + (parents[1].leaf_index as Field) * TWO_POW_32
}

// KAT-only inverse; no in-circuit caller (circuits only pack_parents).
pub fn unpack_parents(packed: Field) -> [Parent; 2] {
    let bytes: [u8; 32] = packed.to_le_bytes();
    for i in 8..32 {
        assert(bytes[i] == 0, "packed parents exceeds 2^64");
    }
    [Parent { leaf_index: u32_from_le(bytes, 0) }, Parent { leaf_index: u32_from_le(bytes, 4) }]
}

// Bind an output note's lineage to the leaf indexes actually consumed. The index witnesses passed here MUST
// be the same ones verify_spend feeds to the nullifier and membership proof, so parents cannot be forged
// independently of the inputs that were really spent.
pub fn assert_parents_bound(note: Note, indexes: [Field; 2]) {
    let expected = pack_parents([
        Parent { leaf_index: indexes[0] as u32 },
        Parent { leaf_index: indexes[1] as u32 },
    ]);
    assert(note.parents == expected, "output parents not bound to consumed inputs");
}

fn u32_from_le(bytes: [u8; 32], offset: u32) -> u32 {
    (bytes[offset] as u32)
        + (bytes[offset + 1] as u32) * 256
        + (bytes[offset + 2] as u32) * 65536
        + (bytes[offset + 3] as u32) * 16777216
}

#[test]
fn kat_leaf_fully_populated() {
    let cek = 0x1fbbfa289c50b7ded032c85e5faa8b3790afc2fd059fd3d299294ff879a08bda;
    let note_psi = Poseidon2::hash([cek, PSI_DOMAIN], 2);
    let note = Note {
        note_version: 1,
        asset_id: 0x1234567890123456789012345678901234567890,
        note_type: 0,
        conditions_hash: 0,
        value: 100,
        owner: 0x0bb44e077410f254c45a30b25976ce465e83511d7fda88f26e1296c6978eaf27,
        psi: note_psi,
        parents: 0,
    };
    assert(note.leaf() == 0x1bcd07739b701ccbd05dfb11bb4aaa428b200b37a7cbdc49d575b281b88930cc);
}

#[test]
fn kat_pack_unpack_parents() {
    let parents = [Parent { leaf_index: 2 }, Parent { leaf_index: 4 }];
    let packed = pack_parents(parents);
    assert(packed == 0x400000002);

    let unpacked = unpack_parents(packed);
    assert(unpacked[0].leaf_index == 2);
    assert(unpacked[1].leaf_index == 4);
}

#[test]
fn kat_deposit_parents_zero() {
    let parents = [Parent { leaf_index: 0 }, Parent { leaf_index: 0 }];
    assert(pack_parents(parents) == 0);

    let unpacked = unpack_parents(0);
    assert(unpacked[0].leaf_index == 0);
    assert(unpacked[1].leaf_index == 0);
}

#[test]
fn kat_max_u32_boundary() {
    let parents = [Parent { leaf_index: 0xffffffff }, Parent { leaf_index: 0xffffffff }];
    let packed = pack_parents(parents);
    assert(packed == 0xffffffffffffffff);
    let unpacked = unpack_parents(packed);
    assert(unpacked[0].leaf_index == 0xffffffff);
    assert(unpacked[1].leaf_index == 0xffffffff);
}
