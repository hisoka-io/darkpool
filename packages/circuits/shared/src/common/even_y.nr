//! Tag = point.x aliases (x, +/-y), so an injective tag REQUIRES even y. Ref: intmax2 utils/key.rs.

use ecdh::Point;

// (BN254_Fr + 1) / 2, which is also 2^-1 mod BN254_Fr.
global HALF_MODULUS: Field = 0x183227397098d014dc2822db40c0ac2e9419f4243cdcb848a1f0fac9f8000001;

// Halving decides parity: even y maps to y/2 < HALF_MODULUS, odd y to (y + p)/2 >= HALF_MODULUS.
pub fn is_even_y(p: Point) -> bool {
    (p.y * HALF_MODULUS).lt(HALF_MODULUS)
}

#[test]
fn is_even_y_matches_byte_reference() {
    let reference = |y: Field| -> bool {
        let y_le: [u8; 32] = y.to_le_bytes();
        (y_le[0] & 1) == 0
    };
    for i in 0..256 {
        let y = i as Field;
        assert(is_even_y(Point { x: 0, y }) == reference(y), "small-value parity mismatch");
    }
    // Field edges: p-1 (even), p-2 (odd), and both halves of the modulus.
    let edges = [
        0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000000,
        0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593efffffff,
        HALF_MODULUS,
        HALF_MODULUS - 1,
    ];
    for i in 0..4 {
        let y = edges[i];
        assert(is_even_y(Point { x: 0, y }) == reference(y), "edge parity mismatch");
    }
}

#[test]
fn test_is_even_y_kat() {
    let odd = Point {
        x: 0x1f082615764661f46f203a3d3d4336d5d7273bf17a67d15bd485a7f329f47c93,
        y: 0x288d616819eb80b160bc2157bdbbd872bfe393957ee45a4aa222587e58a1bb47,
    };
    let even = Point {
        x: 0x13bf364f3ed4490cd6a62bf0d6be4923b09ca23e761d654c7033321c381ba057,
        y: 0x2071ecc0c290d14de1059e9e7594170da51ea08c071d2812bb047692e4e91338,
    };
    assert(!is_even_y(odd));
    assert(is_even_y(even));

    let fixture = Point {
        x: 0x158b1d9682257c0832785c20b002c360b7f84f59f253e667659cf90c1455f764,
        y: 0x132a0f65758b4775374cfc0a98d7f8a186e1cad626e4e4cd37b73532d7e50101,
    };
    assert(!is_even_y(fixture));
}
