// SPDX-License-Identifier: MIT

pragma solidity 0.8.35;

import {IncrementalMerkleTree, Poseidon2} from "./IncrementalMerkleTree.sol";
import {IVerifier} from "./verifiers/IVerifier.sol";

contract ZKVoter is IncrementalMerkleTree {
    // errors
    error ZKVoter__NotOwner();
    error ZKVoter__ProposalNotActive();
    error ZKVoter__CommitmentAlreadyConsumed();
    error ZKVoter__InvalidProof();
    error ZKVoter__ProposalAlreadyCommitted();
    error ZKVoter__ProposalNotFound();
    error ZkVoter__ProposalDeadlineReached();
    error ZKVoter__NullifierHashConsumed();
    error ZKVoter__InvalidVote();
    error ZKVoter__UnknownRoot();

    // structs
    struct Proposal {
        string proposal;
        uint256 forVotes;
        uint256 againstVotes;
        uint256 abstainVotes;
        uint256 createdAt;
        uint256 deadline;
    }

    enum Vote {
        For,
        Against,
        Abstain
    }

    // variables
    mapping(bytes32 => bool) public s_commitments;
    mapping(bytes32 => bool) public s_nullifierHashes;
    mapping(uint32 => Proposal) public s_proposals;
    mapping(address => mapping(uint32 => bool)) public s_commitmentMade;
    uint32 public s_nextProposalIndex;
    address public immutable i_owner;
    IVerifier public immutable i_commitmentVerifier;
    IVerifier public immutable i_castVoteVerifier;

    // modifiers
    modifier onlyOwner() {
        if (msg.sender != i_owner) {
            revert ZKVoter__NotOwner();
        }
        _;
    }

    constructor(uint32 _depth, Poseidon2 _hasher, IVerifier _commitmentVerifier, IVerifier _castVoteVerifier) IncrementalMerkleTree(_depth, _hasher) {
        i_owner = msg.sender;
        i_commitmentVerifier = _commitmentVerifier;
        i_castVoteVerifier = _castVoteVerifier;
    }

    // events
    event ProposalCreated(uint32 proposalId, uint256 creationTime);
    event VoteCommitmentMade(uint32 proposalId, bytes32 commitment);
    event Voted(uint32 proposalId, Vote vote);

    // functions
    function makeNewProposal(string memory _proposal, uint256 _duration) external onlyOwner returns (uint32 proposalId) {
        proposalId = s_nextProposalIndex++;
        s_proposals[proposalId] = Proposal({
            proposal: _proposal,
            forVotes: 0,
            againstVotes: 0,
            abstainVotes: 0,
            createdAt: block.timestamp,
            deadline: block.timestamp + _duration
        });

        emit ProposalCreated(proposalId, block.timestamp);
    }

    // @todo improvement: For each proposal have whitelisted voters with a separate merkle root1
    function makeVoteCommitment(bytes memory _proof, bytes32 _commitment, uint32 _proposalId) external {
        // check commitment consumed
        if (s_commitments[_commitment]) {
            revert ZKVoter__CommitmentAlreadyConsumed();
        }

        if (s_commitmentMade[msg.sender][_proposalId]) {
            revert ZKVoter__ProposalAlreadyCommitted();
        }

        if (_proposalId >= s_nextProposalIndex) {
            revert ZKVoter__ProposalNotFound();
        }

        if (s_proposals[_proposalId].deadline < block.timestamp) {
            revert ZkVoter__ProposalDeadlineReached();
        }

        // verify commitment for msg.sender
        bytes32[] memory publicInputs = new bytes32[](3);
        publicInputs[0] = bytes32(uint256(uint160(msg.sender)));
        publicInputs[1] = _commitment;
        publicInputs[2] = bytes32(uint256(_proposalId));
        bool result = i_commitmentVerifier.verify(_proof, publicInputs);

        if (!result) {
            revert ZKVoter__InvalidProof();
        }

        s_commitments[_commitment] = true;
        s_commitmentMade[msg.sender][_proposalId] = true;
        _insert(_commitment);

        emit VoteCommitmentMade(_proposalId, _commitment);
    }

    function castVote(bytes memory _proof, bytes32 root, bytes32 nullifierHash, uint32 proposalId, Vote vote) external {
        if (s_nullifierHashes[nullifierHash]) {
            revert ZKVoter__NullifierHashConsumed();
        }

        if (!isKnownRoot(root)) {
            revert ZKVoter__UnknownRoot();
        }

        bytes32[] memory publicInputs = new bytes32[](4);
        publicInputs[0] = root;
        publicInputs[1] = nullifierHash;
        publicInputs[2] = bytes32(uint256(proposalId));
        publicInputs[3] = bytes32(uint256(uint8(vote)));

        bool result = i_castVoteVerifier.verify(_proof, publicInputs);

        if (!result) {
            revert ZKVoter__InvalidProof();
        }

        s_nullifierHashes[nullifierHash] = true;

        if (s_proposals[proposalId].deadline < block.timestamp) {
            revert ZkVoter__ProposalDeadlineReached();
        }

        if (vote == Vote.For) {
            s_proposals[proposalId].forVotes++;
        }
        else if (vote == Vote.Against) {
            s_proposals[proposalId].againstVotes++;
        }
        else if (vote == Vote.Abstain) {
            s_proposals[proposalId].abstainVotes++;
        }
        else {
            revert ZKVoter__InvalidVote();
        }

        emit Voted(proposalId, vote);
    }

    function getProposalInfo(uint32 proposalId) external view returns (Proposal memory) {
        return s_proposals[proposalId];
    }
}
