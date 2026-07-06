use crate::domains::PSI_DOMAIN;
use poseidon::poseidon2::Poseidon2;

pub global TWO_POW_32: Field = 4294967296;
pub global TWO_POW_64: Field = 18446744073709551616;

// The wire-format seam and the only shipped note kind. A spend circuit rejects any other version/type.
pub global NOTE_VERSION: Field = 1;
pub global NOTE_TYPE_STANDARD: Field = 0;

// asset_id is a 20-byte ERC20 address; a wider value is rejected so notes stay fungible with clean tokens.
pub fn assert_asset_id(asset_id: Field) {
    let _: [u8; 20] = asset_id.to_be_bytes();
}

// A consumed input; both fields u32 so a pair packs into 64 bits.
pub struct Parent {
    pub tree_num: u32,
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

// pair0 in bits 0..63, pair1 in bits 64..127 (each: tree_num << 32 | leaf_index). Deposit = 0.
pub fn pack_parents(parents: [Parent; 2]) -> Field {
    pack_pair(parents[0]) + pack_pair(parents[1]) * TWO_POW_64
}

fn pack_pair(p: Parent) -> Field {
    (p.tree_num as Field) * TWO_POW_32 + (p.leaf_index as Field)
}

pub fn unpack_parents(packed: Field) -> [Parent; 2] {
    let bytes: [u8; 32] = packed.to_le_bytes();
    for i in 16..32 {
        assert(bytes[i] == 0, "packed parents exceeds 2^128");
    }
    [
        Parent { tree_num: u32_from_le(bytes, 4), leaf_index: u32_from_le(bytes, 0) },
        Parent { tree_num: u32_from_le(bytes, 12), leaf_index: u32_from_le(bytes, 8) },
    ]
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
    let parents = [Parent { tree_num: 1, leaf_index: 2 }, Parent { tree_num: 3, leaf_index: 4 }];
    let packed = pack_parents(parents);
    assert(packed == 0x3000000040000000100000002);

    let unpacked = unpack_parents(packed);
    assert(unpacked[0].tree_num == 1);
    assert(unpacked[0].leaf_index == 2);
    assert(unpacked[1].tree_num == 3);
    assert(unpacked[1].leaf_index == 4);
}

#[test]
fn kat_deposit_parents_zero() {
    let parents = [Parent { tree_num: 0, leaf_index: 0 }, Parent { tree_num: 0, leaf_index: 0 }];
    assert(pack_parents(parents) == 0);

    let unpacked = unpack_parents(0);
    assert(unpacked[0].tree_num == 0);
    assert(unpacked[0].leaf_index == 0);
    assert(unpacked[1].tree_num == 0);
    assert(unpacked[1].leaf_index == 0);
}

#[test]
fn kat_max_u32_boundary() {
    let parents = [
        Parent { tree_num: 0xffffffff, leaf_index: 0xffffffff },
        Parent { tree_num: 0, leaf_index: 0 },
    ];
    let packed = pack_parents(parents);
    let unpacked = unpack_parents(packed);
    assert(unpacked[0].tree_num == 0xffffffff);
    assert(unpacked[0].leaf_index == 0xffffffff);
    assert(unpacked[1].tree_num == 0);
    assert(unpacked[1].leaf_index == 0);
}
