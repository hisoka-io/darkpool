//! Discovery-tag canonicalization: a tag is a point's .x, which aliases (x, +/-y), so an injective Raven
//! key REQUIRES even y (the wallet rolls until even). even == LE byte-0 LSB == 0. Ref: intmax2
//! utils/key.rs even-y address canonicalization.

use ecdh::Point;

pub fn is_even_y(p: Point) -> bool {
    let y_le: [u8; 32] = p.y.to_le_bytes();
    (y_le[0] & 1) == 0
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
