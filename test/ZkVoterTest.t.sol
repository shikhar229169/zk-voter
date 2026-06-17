// SPDX-License-Identifier: MIT

pragma solidity 0.8.35;

import {Test, console2} from "forge-std/Test.sol";
import {ZKVoter} from "../src/ZKVoter.sol";
import {Poseidon2_BN254 as Poseidon2} from "@poseidon/src/bn254/solidity/Poseidon2.sol";
import {HonkVerifier as CommitmentVerifier} from "../src/verifiers/CommitmentVerifier.sol";
import {HonkVerifier as VoteVerifier} from "../src/verifiers/VoteVerifier.sol";
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

        voter = new ZKVoter(
            DEPTH,
            hasher,
            IVerifier(address(commitmentVerifier)),
            IVerifier(address(voteVerifier))
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
        (bytes32 nullifier, bytes32 secret, bytes32 commitment, bytes memory proof) = generateCommitmentWithProof(alice, proposalId);

        vm.prank(alice);
        vm.expectEmit(false, false, false, true);
        emit ZKVoter.VoteCommitmentMade(proposalId, commitment);
        voter.makeVoteCommitment(proof, commitment, proposalId);

        ZKVoter.Vote vote = ZKVoter.Vote.For;

        uint256 prevForVotesCount = voter.getProposalInfo(proposalId).forVotes;

        (bytes memory voteProof, bytes32 nullifierHash, bytes32 root) = generateCastVoteProof(nullifier, secret, commitment, proposalId, vote);
        vm.expectEmit(false, false, false, true);
        emit ZKVoter.Voted(proposalId, vote);
        voter.castVote(voteProof, root, nullifierHash, proposalId, vote);

        uint256 currentForVotesCount = voter.getProposalInfo(proposalId).forVotes;

        assert(voter.s_nullifierHashes(nullifierHash));
        assertEq(currentForVotesCount, prevForVotesCount + 1);

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

        (bytes memory voteProof, bytes32 nullifierHash, bytes32 root) = generateCastVoteProof(nullifier, secret, commitment, proposalId, vote);
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

    function generateCastVoteProof(bytes32 nullifier, bytes32 secret, bytes32 commitment, uint32 proposalId, ZKVoter.Vote vote) internal returns (bytes memory proof, bytes32 nullifierHash, bytes32 root) {
        string[] memory commands = new string[](9);

        commands[0] = "npx";
        commands[1] = "tsx";
        commands[2] = "js-scripts/generateVoteProof.ts";
        commands[3] = vm.toString(nullifier);
        commands[4] = vm.toString(secret);
        commands[5] = vm.toString(proposalId);
        commands[6] = vm.toString(uint8(vote));
        commands[7] = vm.toString((uint256(1)));
        commands[8] = vm.toString(commitment);

        console2.log(commands[3]);
        console2.log(commands[4]);
        console2.log(commands[8]);

        bytes memory output = vm.ffi(commands);
        (proof, root, nullifierHash) = abi.decode(output, (bytes, bytes32, bytes32));
    }
}