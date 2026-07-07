use ecdh::Point;
use poseidon::poseidon2::Poseidon2;

// owner = Poseidon2(pubkey.x, pubkey.y). Incoming note: in_pub_j; self note: self_spend_pub. The spend
// circuit re-derives this and proves knowledge of the pubkey's scalar.
pub fn pubkey_owner(pk: Point) -> Field {
    Poseidon2::hash([pk.x, pk.y], 2)
}

// KAT: owner of the fixture in_pub_j (789*Base8), byte-identical to TS pubkeyOwner (note/keys.ts) and to
// the owner field used by the DEM KAT. A drift makes a note unspendable.
#[test]
fn kat_pubkey_owner() {
    let in_pub = Point {
        x: 0x158b1d9682257c0832785c20b002c360b7f84f59f253e667659cf90c1455f764,
        y: 0x132a0f65758b4775374cfc0a98d7f8a186e1cad626e4e4cd37b73532d7e50101,
    };
    assert(
        pubkey_owner(in_pub) == 0x2874ae964d8b283e2f521a7f14125fc92747bb9770139b8d4b70ee09e2d83785,
    );
}
