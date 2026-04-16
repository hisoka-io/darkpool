use poseidon::poseidon2::Poseidon2;
use edwards::{bjj::BabyJubJub as Point, CurveTrait, ScalarField};
use std::ops::Add;

pub struct DLEQProof {
    pub U: Point,
    pub V: Point,
    pub z: Field,
}

global BASE8: [Field; 2] = [
    5299619240641551281634865583518297030282874472190772894086521144482721001553,
    16950150798460657717958625567821834550301663161624707787222815936182638968203,
];

pub fn verify_dleq(B: Point, C: Point, P: Point, proof: DLEQProof) {
    let G = Point::new(BASE8[0], BASE8[1]);

    let e = Poseidon2::hash(
        [proof.U.x, proof.U.y, proof.V.x, proof.V.y, G.x, G.y, C.x, C.y, B.x, B.y, P.x, P.y],
        12,
    );

    let scalar_z: ScalarField<64> = ScalarField::from(proof.z);
    let e_scalar: ScalarField<64> = ScalarField::from(e);

    let zG = G.mul(scalar_z);
    let rhs1 = proof.U.add(B.mul(e_scalar));
    assert(zG.x == rhs1.x);
    assert(zG.y == rhs1.y);

    let zC = C.mul(scalar_z);
    let rhs2 = proof.V.add(P.mul(e_scalar));

    assert(zC.x == rhs2.x);
    assert(zC.y == rhs2.y);
}
#[test]
fn test_dleq() {
    let B = Point {
        x: 0x2332011090130807bcd9a204354a459873e1ee0873a362d97fc2ccc1f2c5b588,
        y: 0x03a37a8623ff0aa6639f53155bee484c982f5caf0b298328b03da1e58b9a542e,
    };
    let C = Point {
        x: 0x085ed469c9a9f102b6d4f6f909b8ceaf6ca49b39759ac2e0feb7e0aada8b7111,
        y: 0x245e25ab2bd42f0280a5ade750828dd6868f5225ae798d6b51c676f519c8f4e8,
    };
    let P = Point {
        x: 0x0a4e16c84328ba21d37ce75a32e8a5d3a3b078a54fe5a91ab8508b92134765b5,
        y: 0x12d9eba076d2785d154be0e4abce6c06fbb2dcaf5f3d4bfa7d0d53a73b668964,
    };

    let proof = DLEQProof {
        U: Point {
            x: 0x0596c33d2aaa0e419e3e4565d419ead1084900290bd38e9742601161c51e6a3e,
            y: 0x216cab5afb8997a35dc303e2cb221917c1958a47eb7e7005eec9a3de57ab16ed,
        },
        V: Point {
            x: 0x1a28b45b210031b2f860ce229404b70078db004c9c97fa8b6d1420e97ccbcffb,
            y: 0x1314d8f3e5b7c0e47ab6eb52a6a34e7364e2bb9dc4d9c2b2579776d78234fe24,
        },
        z: 0x04897686d7c2ba45a54879774f065f10a5822265efa77ba80d21a2dff7446044,
    };

    verify_dleq(B, C, P, proof);
}
