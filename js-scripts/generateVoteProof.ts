import { Noir } from "@noir-lang/noir_js";
import { Barretenberg, UltraHonkBackend } from "@aztec/bb.js";
import { ethers } from "ethers";
import { merkleTree as getMerkleTree } from "./MerkleTree";
import path from "path";
import fs from "fs";

async function generateVoteProof(): Promise<string> {
    const args = process.argv.slice(2);
    const nullifier = args[0];
    const secret = args[1];
    const proposalId = args[2];
    const vote = args[3];
    const leaves = parseInt(args[4]);
    if (isNaN(leaves) || leaves <= 0) {
        throw new Error("Invalid leaves length");
    }
    const commitmentLeaves = args.slice(5, 5 + leaves);

    if (commitmentLeaves.length != leaves) {
        throw new Error("Leaves count mismatch");
    }

    const nullifierLeavesCount = parseInt(args[5 + leaves]);
    
    if (isNaN(nullifierLeavesCount) || nullifierLeavesCount <= 0) {
        throw new Error("Invalid nullifier leaves length");
    }
    
    const nullifierLeaveStartIndex = 5 + leaves + 1;
    const nullifierLeaves = args.slice(nullifierLeaveStartIndex, nullifierLeaveStartIndex + nullifierLeavesCount);

    const circuitPath = path.resolve(__dirname, "../circuits/target/vote.json");
    const circuitJSON = JSON.parse(fs.readFileSync(circuitPath, 'utf-8'));
    const voteCircuit = new Noir(circuitJSON);
    const bb = await Barretenberg.new({threads: 1});
    const provingBackend = new UltraHonkBackend(circuitJSON.bytecode, bb);

    const nullifierField = getUint8Array(nullifier);
    const secretField = getUint8Array(secret);
    const proposalIdField = toField(proposalId);

    const commitment = await bb.poseidon2Hash({inputs: [nullifierField, secretField, proposalIdField]});
    const nullifierHash = await bb.poseidon2Hash({inputs: [nullifierField, proposalIdField]});

    const merkleTree = await getMerkleTree(commitmentLeaves);
    const commitmentStr = convertToBytesString(commitment.hash);
    const commitmentIdx = merkleTree.getIndex(commitmentStr);
    const commitmentMerkleProof = merkleTree.proof(commitmentIdx);

    const inputs = {
        root: commitmentMerkleProof.root.toString(),
        nullifier_hash: convertToBytesString(nullifierHash.hash),
        proposal_id: proposalId,
        vote: vote,
        secret: secret,
        nullifier: nullifier,
        merkle_proof: commitmentMerkleProof.pathElements.map((r: any) => r.toString()),
        is_even: commitmentMerkleProof.pathIndices.map((r: any) => r % 2 == 0),
    };

    const { witness } = await voteCircuit.execute(inputs);

    const consoleLog = console.log;
    console.log = () => {};

    const { proof } = await provingBackend.generateProof(witness, { verifierTarget: 'evm' });

    console.log = consoleLog;

    const votedProofCktPath = path.resolve(__dirname, "../circuits/target/voted_proof.json");
    const votedProofCktJson = JSON.parse(fs.readFileSync(votedProofCktPath, 'utf-8'));
    const votedProofCircuit = new Noir(votedProofCktJson);
    const votedProofCktProvingBackend = new UltraHonkBackend(votedProofCktJson.bytecode, bb);

    const nullifierMerkleTree = await getMerkleTree(nullifierLeaves);
    const nullifierIndex = nullifierMerkleTree.getIndex(convertToBytesString(nullifierHash.hash));
    const nullifierMerkleProof = nullifierMerkleTree.proof(nullifierIndex);

    const votedProofCktInputs = {
        commitment: commitmentStr,
        proposal_id: proposalId,
        nullifier_merkle_root: nullifierMerkleProof.root,
        nullifier: nullifier,
        secret: secret,
        merkle_proof: nullifierMerkleProof.pathElements.map((r: any) => r.toString()),
        is_even: nullifierMerkleProof.pathIndices.map((r: any) => r % 2 == 0),
    };

    const { witness: votedProofWitness } = await votedProofCircuit.execute(votedProofCktInputs);

    console.log = () => {};

    const { proof: votedProof } = await votedProofCktProvingBackend.generateProof(votedProofWitness, { verifierTarget: 'evm' });
    
    console.log = consoleLog;

    return ethers.AbiCoder.defaultAbiCoder().encode(
        ['bytes', 'bytes', 'bytes32', 'bytes32', 'bytes32'],
        [proof, votedProof, commitmentMerkleProof.root, nullifierHash.hash, nullifierMerkleProof.root],
    );
}

function toField(input: any): Uint8Array {
    const hex = input.toString(16).padStart(64, "0");
    return Uint8Array.from(Buffer.from(hex, "hex"));
}

function getUint8Array(str: string) {
    const clean = str.startsWith("0x") ? str.slice(2) : str;
    const padded = clean.padStart(64, "0");
    return Uint8Array.from(Buffer.from(padded, 'hex'));
}

function convertToBytesString(arrayLike: any) {
    return '0x' + Buffer.from(arrayLike).toString("hex");
}

(async() => {
    generateVoteProof()
    .then((result) => {
        process.stdout.write(result);
        process.exit(0);
    })
    .catch((error) => {
        console.error(error.message || "Error generating proof for vote");
        process.exit(1);
    });
})();
