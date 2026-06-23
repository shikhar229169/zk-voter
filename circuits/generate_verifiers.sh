#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

nargo compile
bb write_vk --oracle_hash keccak -b target/commitment.json -o ./target/commitment
bb write_vk --oracle_hash keccak -b target/vote.json -o ./target/vote
bb write_vk --oracle_hash keccak -b target/voted_proof.json -o ./target/voted_proof
bb write_solidity_verifier -k ./target/commitment/vk -o ../src/verifiers/CommitmentVerifier.sol
bb write_solidity_verifier -k ./target/vote/vk -o ../src/verifiers/VoteVerifier.sol
bb write_solidity_verifier -k ./target/voted_proof/vk -o ../src/verifiers/VotedProofVerifier.sol
