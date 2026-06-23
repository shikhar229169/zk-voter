// SPDX-License-Identifier: MIT

pragma solidity 0.8.35;

import {Test, console2} from "forge-std/Test.sol";
import {ZKVoter} from "../src/ZKVoter.sol";
import {Poseidon2_BN254 as Poseidon2, Field} from "@poseidon/src/bn254/solidity/Poseidon2.sol";
import {HonkVerifier as CommitmentVerifier} from "../src/verifiers/CommitmentVerifier.sol";
import {HonkVerifier as VoteVerifier} from "../src/verifiers/VoteVerifier.sol";
import {HonkVerifier as VotedProofVerifier} from "../src/verifiers/VotedProofVerifier.sol";
import {IVerifier} from "../src/verifiers/IVerifier.sol";

contract ZkVoterTest is Test {
    ZKVoter voter;
    Poseidon2 hasher;
    address alice;
    address bob;

    uint32 private constant DEPTH = 20;

    function setUp() external {
        hasher = new Poseidon2();
        CommitmentVerifier commitmentVerifier = new CommitmentVerifier();
        VoteVerifier voteVerifier = new VoteVerifier();
        VotedProofVerifier votedProofVerifier = new VotedProofVerifier();

        voter = new ZKVoter(
            DEPTH,
            hasher,
            IVerifier(address(commitmentVerifier)),
            IVerifier(address(voteVerifier)),
            IVerifier(address(votedProofVerifier))
        );

        // start first proposal
        voter.makeNewProposal("Billi bole meow?", 1 days);
        voter.makeNewProposal("Will meow?", 1 days);
    }

    function testMakeVoteCommitment() external {
        uint32 proposalId = 0;
        (, , bytes32 commitment, bytes memory proof) = generateCommitmentWithProof(alice, proposalId);

        vm.prank(alice);
        vm.expectEmit(false, false, false, true);
        emit ZKVoter.VoteCommitmentMade(proposalId, commitment);
        voter.makeVoteCommitment(proof, commitment, proposalId);

        vm.expectRevert();
        voter.makeVoteCommitment(proof, commitment, proposalId);
    }
    
    function testCastVote() external {
        uint32 proposalId = 0;
        (bytes32 nullifier, bytes32 secret, bytes32 commitment) = _makeCommitment(alice, proposalId);
        _castAndVerifyVote(nullifier, secret, commitment, proposalId);
    }

    function _makeCommitment(address user, uint32 proposalId) internal returns (bytes32 nullifier, bytes32 secret, bytes32 commitment) {
        bytes memory proof;
        (nullifier, secret, commitment, proof) = generateCommitmentWithProof(user, proposalId);

        vm.prank(user);
        vm.expectEmit(false, false, false, true);
        emit ZKVoter.VoteCommitmentMade(proposalId, commitment);
        voter.makeVoteCommitment(proof, commitment, proposalId);
    }

    function _castAndVerifyVote(bytes32 nullifier, bytes32 secret, bytes32 commitment, uint32 proposalId) internal {
        ZKVoter.Vote vote = ZKVoter.Vote.For;
        uint256 prevForVotesCount = voter.getProposalInfo(proposalId).forVotes;
        (bytes memory voteProof, bytes memory votedProof, bytes32 nullifierHash, bytes32 root, bytes32 nullifierRoot) = generateCastVoteProof(nullifier, secret, commitment, proposalId, vote);

        vm.expectEmit(false, false, false, true);
        emit ZKVoter.Voted(proposalId, vote);
        voter.castVote(voteProof, root, nullifierHash, proposalId, vote);

        assertEq(voter.getProposalInfo(proposalId).forVotes, prevForVotesCount + 1);
        assert(voter.s_nullifierHashes(nullifierHash));
        assert(voter.s_hasVoted(alice, proposalId) == false);

        voter.markVoted(votedProof, alice, proposalId, nullifierRoot);
        assert(voter.s_hasVoted(alice, proposalId));

        vm.expectRevert();
        voter.castVote(voteProof, root, nullifierHash, proposalId, vote);
    }

    function testCastVoteFailsIfIncorrectVoteSupplied() external {
        uint32 proposalId = 0;
        (bytes32 nullifier, bytes32 secret, bytes32 commitment, bytes memory proof) = generateCommitmentWithProof(alice, proposalId);

        vm.prank(alice);
        vm.expectEmit(false, false, false, true);
        emit ZKVoter.VoteCommitmentMade(proposalId, commitment);
        voter.makeVoteCommitment(proof, commitment, proposalId);

        ZKVoter.Vote vote = ZKVoter.Vote.For;

        (bytes memory voteProof, , bytes32 nullifierHash, bytes32 root, ) = generateCastVoteProof(nullifier, secret, commitment, proposalId, vote);
        vm.expectRevert();
        voter.castVote(voteProof, root, nullifierHash, proposalId, ZKVoter.Vote.Against);
    }

    function generateCommitmentWithProof(address user, uint32 proposalId) internal returns (bytes32 nullifier, bytes32 secret, bytes32 commitment, bytes memory proof) {
        string[] memory commands = new string[](5);
        commands[0] = "npx";
        commands[1] = "tsx";
        commands[2] = "js-scripts/generateCommitment.ts";
        commands[3] = vm.toString(proposalId);
        commands[4] = vm.toString(user);

        bytes memory output = vm.ffi(commands);
        (commitment, nullifier, secret, proof) = abi.decode(output, (bytes32, bytes32, bytes32, bytes));
    }

    function generateCastVoteProof(bytes32 nullifier, bytes32 secret, bytes32 commitment, uint32 proposalId, ZKVoter.Vote vote) internal returns (bytes memory proof, bytes memory votedProof, bytes32 nullifierHash, bytes32 root, bytes32 nullifierRoot) {
        string[] memory commands = new string[](11);

        commands[0] = "npx";
        commands[1] = "tsx";
        commands[2] = "js-scripts/generateVoteProof.ts";
        commands[3] = vm.toString(nullifier);
        commands[4] = vm.toString(secret);
        commands[5] = vm.toString(proposalId);
        commands[6] = vm.toString(uint8(vote));
        commands[7] = vm.toString((uint256(1)));
        commands[8] = vm.toString(commitment);
        commands[9] = vm.toString((uint256(1)));

        bytes32 _nullifierHash = Field.toBytes32(hasher.hash_2(Field.toField(nullifier), Field.toField(proposalId)));
        commands[10] = vm.toString(_nullifierHash);

        bytes memory output = vm.ffi(commands);
        (proof, votedProof, root, nullifierHash, nullifierRoot) = abi.decode(output, (bytes, bytes, bytes32, bytes32, bytes32));
    }
}