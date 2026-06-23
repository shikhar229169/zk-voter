use poseidon::poseidon2::Poseidon2;
use common;

fn main(root: pub Field, nullifier_hash: pub Field, proposal_id: pub Field, vote: pub u8, secret: Field, nullifier: Field, merkle_proof: [Field; 20], is_even: [bool; 20]) {
    let commitment = Poseidon2::hash([nullifier, secret, proposal_id], 3);
    let calculated_root = common::get_merkle_root(commitment, merkle_proof, is_even);
    let expected_nullifier_hash = Poseidon2::hash([nullifier, proposal_id], 2);

    assert(root == calculated_root);
    assert(nullifier_hash == expected_nullifier_hash);
    assert(vote == vote);
}
