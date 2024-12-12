// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {ISP1Verifier} from "@sp1-contracts/ISP1Verifier.sol";

library PublicValuesLib {
    struct PublicValues {
        bytes32 ab_genesis_hash;
        bytes32 ab_curr_hash;
        bytes32 ab_next_hash;
        // bytes bls_aggregate_key;
    }
}

contract ABOracle {
    address public verifier;

    bytes32 private programVKey;
    bytes32 private ab_genesis_hash;
    bytes32 private ab_curr_hash;

    address private owner;

    modifier isOwner() {
        require(msg.sender == owner, "Caller is not owner");
        _;
    }

    constructor(
        address _verifier,
        bytes32 _programVKey,
        bytes32 _ab_genesis_hash
   ) {
        verifier = _verifier;
        programVKey = _programVKey;
        ab_genesis_hash = _ab_genesis_hash;
        ab_curr_hash = _ab_genesis_hash;
        owner = msg.sender;
    }

    function setProgramVKey(bytes32 _programVKey) public isOwner {
        programVKey = _programVKey;
    }

    function getABGenesisHash() external view returns(bytes32) {
        return ab_genesis_hash;
    }

    function getABCurrentHash() external view returns(bytes32) {
        return ab_curr_hash;
    }

    using PublicValuesLib for PublicValuesLib.PublicValues;

    function rotate_ab(
        bytes32 ab_next_hash,
        // bytes calldata bls_aggregate_key,
        bytes calldata proofBytes
    ) public {
        PublicValuesLib.PublicValues memory publicValues = PublicValuesLib.PublicValues({
            ab_genesis_hash: ab_genesis_hash,
            ab_curr_hash: ab_curr_hash,
            ab_next_hash: ab_next_hash
            // bls_aggregate_key: bls_aggregate_key
        });

        // ABI encode the public values
        bytes memory encodedPublicValues = abi.encode(publicValues);

        // Call the verifyProof function from SP1Verifier
        ISP1Verifier(verifier).verifyProof(programVKey, encodedPublicValues, proofBytes);

        ab_curr_hash = ab_next_hash;
    }
}
