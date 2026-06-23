use poseidon::poseidon2::Poseidon2;

fn main(user_address: pub Field, commitment: pub Field, proposal_id: pub Field, nullifier: Field, secret: Field) {
    let expected_commitment = Poseidon2::hash([nullifier, secret, proposal_id], 3);
    assert(commitment == expected_commitment);
    assert(user_address + proposal_id == user_address + proposal_id);
}
