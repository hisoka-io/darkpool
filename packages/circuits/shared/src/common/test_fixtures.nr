use crate::note::Note;
use ecdh::Point;

// byte-identical to the TS/Solidity golden vectors; changing any breaks cross-language parity
pub global FIXTURE_COMPLIANCE_X: Field =
    0x085ed469c9a9f102b6d4f6f909b8ceaf6ca49b39759ac2e0feb7e0aada8b7111;
pub global FIXTURE_COMPLIANCE_Y: Field =
    0x245e25ab2bd42f0280a5ade750828dd6868f5225ae798d6b51c676f519c8f4e8;

pub fn fixture_compliance_pk() -> Point {
    Point { x: FIXTURE_COMPLIANCE_X, y: FIXTURE_COMPLIANCE_Y }
}

pub fn fixture_note() -> Note {
    Note {
        note_version: 1,
        asset_id: 0x1234567890123456789012345678901234567890,
        note_type: 0,
        conditions_hash: 0,
        value: 100,
        owner: 0x2874ae964d8b283e2f521a7f14125fc92747bb9770139b8d4b70ee09e2d83785,
        psi: 0x0981a88f9e119b057498a4ab99ed5379a1ea91c642454fc0c07aacc1f5cd5731,
        parents: 0,
    }
}
