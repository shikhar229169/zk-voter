use poseidon;

pub fn get_merkle_root(commitment: Field, merkle_proof: [Field; 20], is_even: [bool; 20]) -> Field {
    let mut computed_root = commitment;
    
    for i in 0..20 {
        let (left, right) = if is_even[i] {
            (computed_root, merkle_proof[i])
        } else {
            (merkle_proof[i], computed_root)
        };

        computed_root = poseidon::poseidon2::Poseidon2::hash([left, right], 2);
    }

    computed_root
}
