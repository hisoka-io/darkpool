//! Prime-order subgroup membership by cofactor preimage, replacing the 250-step [r]P ladder: |E| = 8r with r
//! prime, so P is in the order-r subgroup IFF some on-curve Q satisfies 8Q = P. Q is an unconstrained hint, and
//! `q.assert_is_on_curve()` is load-bearing: the addition law is complete only on-curve, so an off-curve hint
//! can be tuned to land outside the subgroup. The identity is accepted; callers keep a non-identity assert.

use ecdh::Point;
use edwards::{bjj::BabyJubJub, CurveTrait};

// 8^-1 mod SUBORDER.
global EIGHT_INV: Field =
    2394026564107420727433200628387514462817212225638746351800188703329891451411;

/// Safety: an untrusted hint; `assert_in_prime_subgroup` binds it completely.
unconstrained fn cofactor_preimage_hint(p: Point) -> (Field, Field) {
    // `from` not `new`: `new` aborts on off-curve p, hiding that the constrained asserts reject it.
    let base = BabyJubJub::from((p.x, p.y));
    let bits: [bool; 254] = EIGHT_INV.to_le_bits();
    let mut acc = BabyJubJub::zero();
    let mut power = base;
    for i in 0..254 {
        if bits[i] {
            acc = acc + power;
        }
        power = power.dbl();
    }
    (acc.x, acc.y)
}

// Split from the hint so a test can drive it with an ADVERSARIAL q: `binder_rejects_an_off_curve_hint` runs this
// exact code, so deleting the on-curve assert turns that test red instead of passing unnoticed.
fn assert_cofactor_preimage<let N: u32>(p: Point, q: Point, msg: str<N>) {
    // Explicit assert, not `new`: a later cleanup could downgrade `new` to `from` unnoticed.
    let q_ed = BabyJubJub::from((q.x, q.y));
    q_ed.assert_is_on_curve();
    let eight_q = q_ed.dbl().dbl().dbl();
    assert(eight_q.x == p.x, msg);
    assert(eight_q.y == p.y, msg);
}

pub fn assert_in_prime_subgroup<let N: u32>(p: Point, msg: str<N>) {
    // Safety: hint only; assert_cofactor_preimage is what establishes membership.
    let (qx, qy) = unsafe { cofactor_preimage_hint(p) };
    assert_cofactor_preimage(p, Point { x: qx, y: qy }, msg);
}

fn valid_subgroup_point() -> Point {
    Point {
        x: 0x2546ab52faee9ab8ead1ad868567473b9757c6456c137274b12a5c51330d764d,
        y: 0x0d7a564269d3675f75799ee9d7574b00d01190b243041994c0e460af507a71aa,
    }
}

#[test]
fn accepts_a_prime_order_point() {
    assert_in_prime_subgroup(valid_subgroup_point(), "not in prime-order subgroup");
}

#[test]
fn accepts_the_identity_by_design() {
    assert_in_prime_subgroup(
        crate::mutation::bad_identity(),
        "not in prime-order subgroup",
    );
}

#[test(should_fail_with = "not in prime-order subgroup")]
fn rejects_an_order_2_point() {
    assert_in_prime_subgroup(crate::mutation::bad_order2(), "not in prime-order subgroup");
}

#[test(should_fail_with = "not in prime-order subgroup")]
fn rejects_a_small_order_point() {
    assert_in_prime_subgroup(
        crate::mutation::bad_small_order(),
        "not in prime-order subgroup",
    );
}

#[test(should_fail_with = "not in prime-order subgroup")]
fn rejects_an_on_curve_non_subgroup_point() {
    assert_in_prime_subgroup(
        crate::mutation::bad_non_subgroup(),
        "not in prime-order subgroup",
    );
}

// Bare `should_fail`: the rejecting assert is the hint's on-curve check, which carries no message.
#[test(should_fail)]
fn rejects_an_off_curve_point() {
    assert_in_prime_subgroup(
        crate::mutation::bad_off_curve(),
        "not in prime-order subgroup",
    );
}

// q.assert_is_on_curve() is load-bearing, as an executable fact: doubling an off-curve (0, y) gives (0, y^2), and
// ZETA16 is a 16th root of unity in BN254 Fr (2^28 | p-1), so the hint (0, ZETA16) satisfies 8Q == (0, -1), the
// ORDER-2 point.
global ZETA16: Field = 0x21082ca216cbbf4e1c6e4f4594dd508c996dfbe1174efb98b11509c6e306460b;

// Off-curve by construction: x == 0 forces y == +/-1 on this curve, and ZETA16 is neither.
fn malicious_hint() -> Point {
    Point { x: 0, y: ZETA16 }
}

// Read the pair together. Without the on-curve check the equality asserts ACCEPT the hint, so they are not what
// rejects it; the production binder REJECTS it. Therefore the on-curve assert is the constraint doing the work,
// and the reject below cannot pass vacuously through a wrong ZETA16.
fn binder_without_on_curve(p: Point, q: Point) -> bool {
    let q_ed = BabyJubJub::from((q.x, q.y));
    let eight_q = q_ed.dbl().dbl().dbl();
    (eight_q.x == p.x) & (eight_q.y == p.y)
}

#[test]
fn the_off_curve_hint_satisfies_the_equality_asserts() {
    assert(
        binder_without_on_curve(crate::mutation::bad_order2(), malicious_hint()),
        "the off-curve hint must reach an order-2 point, else this test no longer pins the invariant",
    );
}

#[test(should_fail)]
fn binder_rejects_an_off_curve_hint() {
    assert_cofactor_preimage(
        crate::mutation::bad_order2(),
        malicious_hint(),
        "not in prime-order subgroup",
    );
}
