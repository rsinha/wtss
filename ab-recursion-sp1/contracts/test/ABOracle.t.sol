// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {Test, console} from "forge-std/Test.sol";
import {stdJson} from "forge-std/StdJson.sol";
import {ABOracle, PublicValuesLib} from "../src/ABOracle.sol";
import {SP1VerifierGateway} from "@sp1-contracts/SP1VerifierGateway.sol";

struct SP1ProofFixtureJson {
    bytes32 ab_genesis_hash;
    bytes32 ab_curr_hash;
    bytes32 ab_next_hash;
    // bytes bls_aggregate_key;
    bytes proof;
    bytes publicValues;
    bytes32 vkey;
}

contract ABOracleTest is Test {
    using stdJson for string;
    using PublicValuesLib for PublicValuesLib.PublicValues;

    address verifier;
    ABOracle public ab_oracle;

    function toString(uint8 digit) public pure returns (string memory) {
        require(digit < 10, "Input must be a single digit (0-9)");

        bytes memory result = new bytes(1);
        result[0] = bytes1(uint8(digit) + 48); // ASCII offset for numbers

        return string(result);
    }

    function loadFixture(uint8 i) public view returns (SP1ProofFixtureJson memory) {
        string memory root = vm.projectRoot();
        string memory path = string.concat(
            root,
            "/src/fixtures/",
            toString(i), "to", toString(i + 1),
            "-fixture",
            // "-with_bls_aggregate",
            ".json"
        );
        string memory json = vm.readFile(path);
        bytes memory jsonBytes = json.parseRaw(".");
        return abi.decode(jsonBytes, (SP1ProofFixtureJson));
    }

    function setUp() public {
        SP1ProofFixtureJson memory fixture = loadFixture(0);

        verifier = address(new SP1VerifierGateway(address(1)));
        ab_oracle = new ABOracle(verifier, fixture.vkey, fixture.ab_genesis_hash);
    }

    function test_ValidABOracleProof0to1() public {
        SP1ProofFixtureJson memory fixture = loadFixture(0);

        vm.mockCall(verifier, abi.encodeWithSelector(SP1VerifierGateway.verifyProof.selector), abi.encode(true));

        ab_oracle.rotate_ab(
            fixture.ab_next_hash,
            // fixture.bls_aggregate_key,
            fixture.proof
        );
        assertEq(ab_oracle.getABCurrentHash(), fixture.ab_next_hash, "AB should be correctly rotated");
    }

    function test_InvalidABOracleProof() public {
        SP1ProofFixtureJson memory fixture = loadFixture(0);

        // Create a fake proof.
        bytes memory fakeProof = new bytes(fixture.proof.length);

        // Expect the rotation to revert
        vm.expectRevert();
        ab_oracle.rotate_ab(
            fixture.ab_next_hash,
            // fixture.bls_aggregate_key,
            fakeProof
        );
    }
}
