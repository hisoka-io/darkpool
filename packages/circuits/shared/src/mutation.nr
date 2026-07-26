//! Test-only BabyJubJub bad-point vectors computed over a=168700, d=168696, BN254 Fr.

use crate::SUBORDER;
use ecdh::{bjj::check_subgroup, Point};
use edwards::{bjj::BabyJubJub, CurveTrait};

/// Order 1, so in every subgroup; only the separate `!is_zero()` guard rejects it.
pub fn bad_identity() -> Point {
    Point { x: 0, y: 1 }
}

/// Off-curve: a*x^2 + y^2 = 168701 != 168697 = 1 + d*x^2*y^2.
pub fn bad_off_curve() -> Point {
    Point { x: 1, y: 1 }
}

/// Order 2, i.e. (0, -1).
pub fn bad_order2() -> Point {
    Point { x: 0, y: 0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000000 }
}

/// Order 8.
pub fn bad_small_order() -> Point {
    Point {
        x: 0x0999e47227c47e8829b0d14b251feed7582d0f5357b304b06d4014ae6ab39f1e,
        y: 0x0aabb7211172d31463c1127d4ba6942cb791c56d8234b5a0abfd1e81afd0d677,
    }
}

/// Order 8*SUBORDER: a full-curve generator, on-curve but outside the prime-order subgroup.
pub fn bad_non_subgroup() -> Point {
    Point {
        x: 0x023343e3445b673d38bcba38f25645adb494b1255b1162bb40f41a59f4d4b45e,
        y: 0x0c19139cb84c680a6e14116da06056174a0cfa121e6e5c2450f87d64fc000001,
    }
}

fn as_ed(p: Point) -> BabyJubJub {
    BabyJubJub::new(p.x, p.y)
}

#[test]
fn vector_identity_is_the_neutral_element() {
    assert(as_ed(bad_identity()).is_zero(), "identity vector is not the neutral element");
}

#[test(should_fail)]
fn vector_off_curve_fails_on_curve_assert() {
    as_ed(bad_off_curve()).assert_is_on_curve();
}

#[test]
fn vector_small_and_non_subgroup_are_on_curve() {
    as_ed(bad_order2()).assert_is_on_curve();
    as_ed(bad_small_order()).assert_is_on_curve();
    as_ed(bad_non_subgroup()).assert_is_on_curve();
}

#[test]
fn vector_small_and_non_subgroup_are_outside_the_subgroup() {
    assert(!check_subgroup(as_ed(bad_order2())), "order-2 vector unexpectedly in subgroup");
    assert(
        !check_subgroup(as_ed(bad_small_order())),
        "small-order vector unexpectedly in subgroup",
    );
    assert(
        !check_subgroup(as_ed(bad_non_subgroup())),
        "non-subgroup vector unexpectedly in subgroup",
    );
}

#[test]
fn scalar_subgroup_boundary_is_suborder() {
    assert(
        SUBORDER == 2736030358979909402780800718157159386076813972158567259200215660948447373041,
        "SUBORDER drifted from the BabyJubJub prime-order subgroup order",
    );
}
