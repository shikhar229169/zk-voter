// SPDX-License-Identifier: MIT

pragma solidity 0.8.35;

import {Poseidon2_BN254 as Poseidon2, Field} from "@poseidon/src/bn254/solidity/Poseidon2.sol";

library IncrementalMerkleTree {
    error IncrementalMerkleTree__DepthShouldBeMoreThanZero();
    error IncrementalMerkleTree__DepthShouldBeLessThan32();
    error IncrementalMerkleTree__IndexOutOfBounds(uint256 index);
    error IncrementalMerkleTree__MaxLeavesReached();
    error IncrementalMerkleTree__AlreadyInitialized();
    error IncrementalMerkleTree__NotInitialized();

    struct MerkleTree {
        uint32 depth;
        uint32 nextLeafIndex;
        uint32 maxLeaves;
        mapping(uint256 => bytes32) merkleRoots;
        uint32 currentRootIndex;
        mapping(uint32 => bytes32) cachedSubtree;
        Poseidon2 hasher;
        bool initialized;
    }

    uint32 internal constant ROOT_HISTORY_SIZE = 30;
    uint256 internal constant FIELD_MODULUS = 21888242871839275222246405745257275088548364400416034343698204186575808495617;

    modifier onlyInitialized(MerkleTree storage tree) {
        if (!tree.initialized) {
            revert IncrementalMerkleTree__NotInitialized();
        }
        _;
    }

    function init(MerkleTree storage tree, uint32 _depth, Poseidon2 _hasher) internal {
        if (tree.initialized) {
            revert IncrementalMerkleTree__AlreadyInitialized();
        }

        if (_depth == 0) {
            revert IncrementalMerkleTree__DepthShouldBeMoreThanZero();
        }

        if (_depth >= 32) {
            revert IncrementalMerkleTree__DepthShouldBeLessThan32();
        }

        tree.depth = _depth;
        tree.maxLeaves = uint32(2) ** _depth;
        tree.merkleRoots[0] = zeros(_depth);
        tree.hasher = _hasher;
        tree.initialized = true;
    }

    function insert(MerkleTree storage tree, bytes32 _leaf) internal onlyInitialized(tree) returns (uint32) {
        uint32 _nextLeafIndex = tree.nextLeafIndex++;
        if (_nextLeafIndex >= tree.maxLeaves) {
            revert IncrementalMerkleTree__MaxLeavesReached();
        }

        mapping(uint32 => bytes32) storage cachedSubtree = tree.cachedSubtree;

        uint32 currentIdx = _nextLeafIndex;
        bytes32 currentHash = _leaf;

        uint256 _depth = tree.depth;

        for (uint32 i = 0; i < _depth; ) {
            bytes32 left;
            bytes32 right;
            if (currentIdx % 2 == 0) {
                left = currentHash;
                right = zeros(i);
                cachedSubtree[i] = currentHash;
            }
            else {
                left = cachedSubtree[i];
                right = currentHash;
            }

            currentHash = Field.toBytes32(tree.hasher.hash_2(Field.toField(left), Field.toField(right)));
            currentIdx = currentIdx / 2;

            unchecked {
                ++i;
            }
        }

        uint32 newRootIndex = (tree.currentRootIndex + 1) % ROOT_HISTORY_SIZE;
        tree.currentRootIndex = newRootIndex;
        tree.merkleRoots[newRootIndex] = currentHash;
        return _nextLeafIndex;
    }

    function isKnownRoot(MerkleTree storage tree, bytes32 _root) internal view onlyInitialized(tree) returns (bool) {
        if (_root == bytes32(0)) {
            return false;
        }

        for (uint256 i = 0; i < ROOT_HISTORY_SIZE; ) {
            if (tree.merkleRoots[i] == _root) {
                return true;
            }

            unchecked {
                ++i;
            }
        }

        return false;
    }

    function zeros(uint256 i) internal pure returns (bytes32) {
        if (i == 0) return bytes32(0x0d823319708ab99ec915efd4f7e03d11ca1790918e8f04cd14100aceca2aa9ff);
        else if (i == 1) return bytes32(0x170a9598425eb05eb8dc06986c6afc717811e874326a79576c02d338bdf14f13);
        else if (i == 2) return bytes32(0x273b1a40397b618dac2fc66ceb71399a3e1a60341e546e053cbfa5995e824caf);
        else if (i == 3) return bytes32(0x16bf9b1fb2dfa9d88cfb1752d6937a1594d257c2053dff3cb971016bfcffe2a1);
        else if (i == 4) return bytes32(0x1288271e1f93a29fa6e748b7468a77a9b8fc3db6b216ce5fc2601fc3e9bd6b36);
        else if (i == 5) return bytes32(0x1d47548adec1068354d163be4ffa348ca89f079b039c9191378584abd79edeca);
        else if (i == 6) return bytes32(0x0b98a89e6827ef697b8fb2e280a2342d61db1eb5efc229f5f4a77fb333b80bef);
        else if (i == 7) return bytes32(0x231555e37e6b206f43fdcd4d660c47442d76aab1ef552aef6db45f3f9cf2e955);
        else if (i == 8) return bytes32(0x03d0dc8c92e2844abcc5fdefe8cb67d93034de0862943990b09c6b8e3fa27a86);
        else if (i == 9) return bytes32(0x1d51ac275f47f10e592b8e690fd3b28a76106893ac3e60cd7b2a3a443f4e8355);
        else if (i == 10) return bytes32(0x16b671eb844a8e4e463e820e26560357edee4ecfdbf5d7b0a28799911505088d);
        else if (i == 11) return bytes32(0x115ea0c2f132c5914d5bb737af6eed04115a3896f0d65e12e761ca560083da15);
        else if (i == 12) return bytes32(0x139a5b42099806c76efb52da0ec1dde06a836bf6f87ef7ab4bac7d00637e28f0);
        else if (i == 13) return bytes32(0x0804853482335a6533eb6a4ddfc215a08026db413d247a7695e807e38debea8e);
        else if (i == 14) return bytes32(0x2f0b264ab5f5630b591af93d93ec2dfed28eef017b251e40905cdf7983689803);
        else if (i == 15) return bytes32(0x170fc161bf1b9610bf196c173bdae82c4adfd93888dc317f5010822a3ba9ebee);
        else if (i == 16) return bytes32(0x0b2e7665b17622cc0243b6fa35110aa7dd0ee3cc9409650172aa786ca5971439);
        else if (i == 17) return bytes32(0x12d5a033cbeff854c5ba0c5628ac4628104be6ab370699a1b2b4209e518b0ac5);
        else if (i == 18) return bytes32(0x1bc59846eb7eafafc85ba9a99a89562763735322e4255b7c1788a8fe8b90bf5d);
        else if (i == 19) return bytes32(0x1b9421fbd79f6972a348a3dd4721781ec25a5d8d27342942ae00aba80a3904d4);
        else if (i == 20) return bytes32(0x087fde1c4c9c27c347f347083139eee8759179d255ec8381c02298d3d6ccd233);
        else if (i == 21) return bytes32(0x1e26b1884cb500b5e6bbfdeedbdca34b961caf3fa9839ea794bfc7f87d10b3f1);
        else if (i == 22) return bytes32(0x09fc1a538b88bda55a53253c62c153e67e8289729afd9b8bfd3f46f5eecd5a72);
        else if (i == 23) return bytes32(0x14cd0edec3423652211db5210475a230ca4771cd1e45315bcd6ea640f14077e2);
        else if (i == 24) return bytes32(0x1d776a76bc76f4305ef0b0b27a58a9565864fe1b9f2a198e8247b3e599e036ca);
        else if (i == 25) return bytes32(0x1f93e3103fed2d3bd056c3ac49b4a0728578be33595959788fa25514cdb5d42f);
        else if (i == 26) return bytes32(0x138b0576ee7346fb3f6cfb632f92ae206395824b9333a183c15470404c977a3b);
        else if (i == 27) return bytes32(0x0745de8522abfcd24bd50875865592f73a190070b4cb3d8976e3dbff8fdb7f3d);
        else if (i == 28) return bytes32(0x2ffb8c798b9dd2645e9187858cb92a86c86dcd1138f5d610c33df2696f5f6860);
        else if (i == 29) return bytes32(0x2612a1395168260c9999287df0e3c3f1b0d8e008e90cd15941e4c2df08a68a5a);
        else if (i == 30) return bytes32(0x10ebedce66a910039c8edb2cd832d6a9857648ccff5e99b5d08009b44b088edf);
        else if (i == 31) return bytes32(0x213fb841f9de06958cf4403477bdbff7c59d6249daabfee147f853db7c808082);
        else revert IncrementalMerkleTree__IndexOutOfBounds(i);
    }
}