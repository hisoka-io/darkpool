use crate::{assert_subgroup_scalar, DLEQ_DOMAIN};
use edwards::{bjj::BabyJubJub as Point, CurveTrait, ScalarField};
use poseidon::poseidon2::Poseidon2;
use std::ops::Add;

pub struct DLEQProof {
    pub U: Point,
    pub V: Point,
    pub z: Field,
}

// https://docs.iden3.io/publications/pdfs/Baby-Jubjub.pdf
// https://eips.ethereum.org/EIPS/eip-2494
global BASE8: [Field; 2] = [
    5299619240641551281634865583518297030282874472190772894086521144482721001553,
    16950150798460657717958625567821834550301663161624707787222815936182638968203,
];

pub fn verify_dleq(B: Point, C: Point, P: Point, proof: DLEQProof) {
    assert_subgroup_scalar(proof.z);
    proof.U.assert_is_on_curve();
    proof.V.assert_is_on_curve();
    let G = Point::new(BASE8[0], BASE8[1]);

    let e = Poseidon2::hash(
        [
            DLEQ_DOMAIN,
            proof.U.x,
            proof.U.y,
            proof.V.x,
            proof.V.y,
            G.x,
            G.y,
            C.x,
            C.y,
            B.x,
            B.y,
            P.x,
            P.y,
        ],
        13,
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
        x: 0x0cf064598cbf9e0f91228a743567873ef0f2001edabb432b546f6ffa0a25afe5,
        y: 0x1209bec18717eb6499e330d9196458e04b91f995e16d76f2e4c322705c77242f,
    };
    let C = Point {
        x: 0x085ed469c9a9f102b6d4f6f909b8ceaf6ca49b39759ac2e0feb7e0aada8b7111,
        y: 0x245e25ab2bd42f0280a5ade750828dd6868f5225ae798d6b51c676f519c8f4e8,
    };
    let P = Point {
        x: 0x0464508630b85bedcc795e1f2f26a5fbd9c36b074cbbb0946c182f608ec975ab,
        y: 0x2d3d62b4b8421137315a7903873c39feba45e5520d585d43136d5f249588cff4,
    };

    let proof = DLEQProof {
        U: Point {
            x: 0x1d64dd17ea8ab929f2fc70b07e3b4a32256154b07fdeac12c275afd11aa79bb3,
            y: 0x286ddd321efe47f7b0359a6980950340334fe0919f07487ea55a7c519ef45bf4,
        },
        V: Point {
            x: 0x04ce27a5b2b411f3c3896091abf72ce1bddc90c792617e2cf5888dfe50019af3,
            y: 0x21321e1e9b1cf666ec968a71514c826848bf32a81b208bff3df0b8517b439366,
        },
        z: 0x00b2bfd422ade54128c2fc4a819eb508e27675a811051cb904ae4396df9f28f6,
    };

    verify_dleq(B, C, P, proof);
}
