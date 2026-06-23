use poseidon::poseidon2::Poseidon2;
use common;

fn main(commitment: pub Field, proposal_id: pub Field, nullifier_merkle_root: pub Field, nullifier: Field, secret: Field, merkle_proof: [Field; 20], is_even: [bool; 20]) {
    let expected_commitment = Poseidon2::hash([nullifier, secret, proposal_id], 3);
    let nullifier_hash = Poseidon2::hash([nullifier, proposal_id], 2);
    let expected_nullifier_merkle_root = common::get_merkle_root(nullifier_hash, merkle_proof, is_even);

    assert(commitment == expected_commitment);
    assert(nullifier_merkle_root == expected_nullifier_merkle_root);
}
