//! Value conservation, called by every consuming op. Values are u128 so bounded-arity sums stay << p and
//! cannot wrap the field; u128 add is overflow-checked so an output set wrapping past 2^128 is rejected.
//! `public_out` is cleartext value leaving the pool (withdraw/gas amount), 0 when all value stays in notes.

pub fn assert_conserved<let NIN: u32, let NOUT: u32>(
    inputs: [u128; NIN],
    outputs: [u128; NOUT],
    public_out: u128,
) {
    let mut total_in: u128 = 0;
    for i in 0..NIN {
        total_in += inputs[i];
    }
    let mut total_out: u128 = public_out;
    for i in 0..NOUT {
        total_out += outputs[i];
    }
    assert(total_in == total_out, "value not conserved");
}

#[test]
fn conserves_split_one_in_two_out() {
    assert_conserved([100], [40, 60], 0);
}

#[test]
fn conserves_withdraw_with_public_out() {
    assert_conserved([100], [60], 40);
}

#[test(should_fail_with = "value not conserved")]
fn rejects_inflation() {
    assert_conserved([100], [100, 100], 0);
}

#[test(should_fail_with = "attempt to add with overflow")]
fn rejects_output_overflow() {
    assert_conserved(
        [100],
        [0x80000000000000000000000000000000, 0x80000000000000000000000000000064],
        0,
    );
}
