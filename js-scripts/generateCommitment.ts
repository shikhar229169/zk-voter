import {Barretenberg, randomBytes, BN254_FR_MODULUS, UltraHonkBackend} from "@aztec/bb.js";
import {ethers} from "ethers";
import {Noir} from "@noir-lang/noir_js";
import path from "path";
import fs from "fs";
  
async function generateCommitment(proposalId: number, bb: Barretenberg): Promise<{nullifier: Uint8Array, secret: Uint8Array, commitment: Uint8Array}> {
    const nullifier = getRandomField();
    const secret = getRandomField();
    const proposalIdArr = toField(proposalId);

    const commitment = await bb.poseidon2Hash({inputs: [nullifier, secret, proposalIdArr]});
    
    return {nullifier, secret, commitment: commitment.hash}
}

async function generateCommitmentWithProof(): Promise<string> {
    const args = process.argv.slice(2);
    const proposalId = parseInt(args[0]);
    const userAddress = args[1];
    const bb = await Barretenberg.new({threads: 1});
    
    if (isNaN(proposalId) || proposalId < 0 ) {
        throw new Error("Invalid proposal id");
    }

    const {nullifier, secret, commitment} = await generateCommitment(proposalId, bb);

    const circuitPath = path.resolve(__dirname, "../../circuits/target/commitment.json");
    const circuit = JSON.parse(fs.readFileSync(circuitPath, "utf-8"));
    const noirCircuit = new Noir(circuit);
    const provingBackend = new UltraHonkBackend(circuit.bytecode, bb);

    const inputs = {
        // public inputs
        user_address: userAddress,
        commitment: ethers.hexlify(commitment),
        proposal_id: proposalId,

        // private inputs
        nullifier: ethers.hexlify(nullifier),
        secret: ethers.hexlify(secret),
    };

    const consoleLog = console.log;
    console.log = () => {};

    const {witness} = await noirCircuit.execute(inputs);
    const {proof} = await provingBackend.generateProof(witness, {verifierTarget: "evm"});

    console.log = consoleLog;

    return ethers.AbiCoder.defaultAbiCoder().encode(
        ["bytes32", "bytes32", "bytes32", "bytes"],
        [commitment, nullifier, secret, proof],
    );
}

function getRandomField(): Uint8Array {
    const rand = BigInt("0x" + Buffer.from(randomBytes(32)).toString("hex"));
    const inField = rand % BN254_FR_MODULUS;
    const hex = inField.toString(16).padStart(64, "0");
    return Uint8Array.from(Buffer.from(hex, "hex"));
}

function toField(input: any): Uint8Array {
    const hex = input.toString(16).padStart(64, "0");
    return Uint8Array.from(Buffer.from(hex, "hex"));
}

function convertToBytesString(arrayLike: any) {
    return '0x' + Buffer.from(arrayLike).toString("hex");
}

(async() => {
    generateCommitmentWithProof()
    .then((result) => {
        process.stdout.write(result);
        process.exit(0);
    })
    .catch((error) => {
        console.error(error.message || "Error in generating commitment");
        process.exit(1);
    });
})();
