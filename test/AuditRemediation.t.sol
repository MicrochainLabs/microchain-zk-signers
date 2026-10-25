// SPDX-License-Identifier: MIT
pragma solidity ^0.8.27;

import { Test } from "forge-std/Test.sol";

import { IERC8039, ERC8039Constants } from "../contracts/ERC8039/IERC8039.sol";
import { ZKMultiSigEcdsaProofVerifier } from "../contracts/ERC8039/ZKMultiSigEcdsaProofVerifier.sol";
import { PrivateStateValidationProofVerifier } from "../contracts/ERC8039/PrivateStateValidationProofVerifier.sol";
import { HonkVerifier } from "../noir/target/zk_multi_sig_ecdsa_private_state_validation.sol";
import { ZKMultiSigValidator } from "../contracts/nexus/modules/validators/ZKMultiSigValidator.sol";
import { ZKMultiSigEcdsaFactory } from "../contracts/safe/ZKMultiSigEcdsaFactory.sol";
import { ZKMultiSigEcdsaProxy } from "../contracts/safe/ZKMultiSigEcdsaProxy.sol";
import { ZKMultiSigEcdsaSingleton } from "../contracts/safe/ZKMultiSigEcdsaSingleton.sol";
import { PackedUserOperation } from "account-abstraction/interfaces/PackedUserOperation.sol";

/// @dev ERC-8039 verifier stub: accepts `PROOF` for any (hash, root) pair that has been allow-listed.
contract MockERC8039Verifier is IERC8039 {
    bytes public constant PROOF = hex"deadbeef00112233445566778899aabbccddeeff";
    mapping(bytes32 => bool) public allowed;

    function allow(bytes32 hash, bytes32 root) external {
        allowed[keccak256(abi.encode(hash, root))] = true;
    }

    function allowRootOnly(bytes32 root) external {
        allowed[keccak256(abi.encode(root))] = true;
    }

    function verifyProof(bytes calldata publicInputs, bytes calldata proof) external view returns (bytes4) {
        if (keccak256(proof) != keccak256(PROOF)) return bytes4(0);
        bytes32[] memory inputs = abi.decode(publicInputs, (bytes32[]));
        bytes32 key;
        if (inputs.length == 33) {
            bytes32 hash;
            for (uint256 i = 0; i < 32; i++) {
                hash |= bytes32(uint256(uint8(uint256(inputs[i]))) << (8 * (31 - i)));
            }
            key = keccak256(abi.encode(hash, inputs[32]));
        } else if (inputs.length == 1) {
            key = keccak256(abi.encode(inputs[0]));
        }
        return allowed[key] ? ERC8039Constants.PROOF_MAGIC_VALUE : bytes4(0);
    }

    function getProofType() external pure returns (bytes32) { return bytes32(0); }
    function metadata() external pure returns (string memory) { return ""; }
}

/// @dev Minimal ERC-7579-style account: forwards ERC-1271 to the validator with `msg.sender` as `sender`
///      (exactly what Nexus does) and exposes an EIP-5267 domain.
contract MockAccount {
    ZKMultiSigValidator public validator;
    string public name;

    constructor(ZKMultiSigValidator _validator, string memory _name) {
        validator = _validator;
        name = _name;
    }

    function install(bytes calldata data) external { validator.onInstall(data); }

    function isValidSignature(bytes32 hash, bytes calldata sig) external view returns (bytes4) {
        return validator.isValidSignatureWithSender(msg.sender, hash, sig);
    }

    function validateUserOp(PackedUserOperation calldata op, bytes32 opHash) external returns (uint256) {
        return validator.validateUserOp(op, opHash);
    }

    function eip712Domain()
        external
        view
        returns (bytes1, string memory, string memory, uint256, address, bytes32, uint256[] memory)
    {
        return (hex"0f", name, "1", block.chainid, address(this), bytes32(0), new uint256[](0));
    }

    function domainSeparator() public view returns (bytes32) {
        return keccak256(
            abi.encode(
                keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"),
                keccak256(bytes(name)),
                keccak256("1"),
                block.chainid,
                address(this)
            )
        );
    }

    /// @dev ERC-7739 `PersonalSign` digest the owners must actually sign for `hash`.
    function personalSignDigest(bytes32 hash) external view returns (bytes32) {
        bytes32 structHash = keccak256(abi.encode(keccak256("PersonalSign(bytes prefixed)"), hash));
        return keccak256(abi.encodePacked(hex"1901", domainSeparator(), structHash));
    }
}

/// @dev Reverting stand-in for a generated HonkVerifier.
contract RevertingHonk {
    function verify(bytes calldata, bytes32[] calldata) external pure returns (bool) {
        revert("boom");
    }
}

contract AuditRemediationTest is Test {
    MockERC8039Verifier txVerifier;
    MockERC8039Verifier stateVerifier;
    ZKMultiSigValidator validator;
    MockAccount accountA;
    MockAccount accountB;

    bytes PROOF;
    bytes32 constant ROOT = bytes32(uint256(0x1234));
    bytes32 constant HASH = keccak256("some dapp hash");
    address dapp = makeAddr("dapp");

    function setUp() public {
        // ERC-7739's `_erc1271IsValidSignatureViaRPC` treats gasprice == 0 as an off-chain call;
        // emulate an on-chain environment.
        vm.txGasPrice(1);
        txVerifier = new MockERC8039Verifier();
        PROOF = txVerifier.PROOF();
        stateVerifier = new MockERC8039Verifier();
        validator = new ZKMultiSigValidator(address(stateVerifier), address(txVerifier));
        accountA = new MockAccount(validator, "A");
        accountB = new MockAccount(validator, "B");

        stateVerifier.allowRootOnly(ROOT);
        bytes memory initData = abi.encode(ROOT, PROOF);
        accountA.install(initData);
        accountB.install(initData);
    }

    /*//////////////////////////////////////////////////////////////////////////
                         F-01 / F-02: Nexus ERC-1271 path
    //////////////////////////////////////////////////////////////////////////*/

    function test_erc7739_detection() public view {
        bytes32 probe = bytes32(~uint256(0) / 0xffff * 0x7739);
        assertEq(validator.isValidSignatureWithSender(dapp, probe, ""), bytes4(0x77390001));
    }

    function test_erc1271_keyedOnAccount_personalSign() public {
        // Signers sign the ERC-7739 PersonalSign digest bound to account A.
        txVerifier.allow(accountA.personalSignDigest(HASH), ROOT);

        vm.prank(dapp);
        assertEq(accountA.isValidSignature(HASH, PROOF), bytes4(0x1626ba7e));
    }

    function test_erc1271_noCrossAccountReplay() public {
        // Same root on both accounts; a proof bound to A must not validate for B.
        txVerifier.allow(accountA.personalSignDigest(HASH), ROOT);

        vm.prank(dapp);
        assertEq(accountB.isValidSignature(HASH, PROOF), bytes4(0xffffffff));
    }

    function test_erc1271_rawHashRejectedForUnsafeCaller() public {
        // A proof over the raw dapp hash (no account binding) is NOT accepted from a third party.
        txVerifier.allow(HASH, ROOT);

        vm.prank(dapp);
        assertEq(accountA.isValidSignature(HASH, PROOF), bytes4(0xffffffff));
    }

    function test_erc1271_rawHashAcceptedWhenAccountIsCaller() public {
        // The account itself is a "safe caller" (e.g. Nexus enable-mode), raw hash is used.
        txVerifier.allow(HASH, ROOT);

        vm.prank(address(accountA));
        assertEq(accountA.isValidSignature(HASH, PROOF), bytes4(0x1626ba7e));
    }

    function test_erc1271_requesterStateRootIsIgnored() public {
        // Regression for F-01: a requester that registered its own root must not be able to
        // make the victim account validate against it.
        bytes32 attackerRoot = bytes32(uint256(0xbad));
        stateVerifier.allowRootOnly(attackerRoot);
        MockAccount attacker = new MockAccount(validator, "attacker");
        attacker.install(abi.encode(attackerRoot, PROOF));
        txVerifier.allow(accountA.personalSignDigest(HASH), attackerRoot);

        vm.prank(address(attacker));
        assertEq(accountA.isValidSignature(HASH, PROOF), bytes4(0xffffffff));
    }

    function test_erc1271_typedDataSign() public {
        // TypedDataSign flow: signature = proof ‖ APP_DOMAIN_SEPARATOR ‖ contents ‖ contentsDescription ‖ uint16(len)
        bytes32 appDomain = keccak256("app domain");
        bytes32 contents = keccak256("contents struct hash");
        bytes32 hash = keccak256(abi.encodePacked(hex"1901", appDomain, contents));
        string memory contentsType = "Mail(address to,string body)";

        bytes32 typedDataSignTypehash = keccak256(
            abi.encodePacked(
                "TypedDataSign(Mail contents,string name,string version,uint256 chainId,address verifyingContract,bytes32 salt)",
                contentsType
            )
        );
        bytes32 structHash = keccak256(
            abi.encode(
                typedDataSignTypehash,
                contents,
                keccak256(bytes(accountA.name())),
                keccak256("1"),
                block.chainid,
                address(accountA),
                bytes32(0)
            )
        );
        bytes32 finalDigest = keccak256(abi.encodePacked(hex"1901", appDomain, structHash));
        txVerifier.allow(finalDigest, ROOT);

        bytes memory sig = abi.encodePacked(
            PROOF, appDomain, contents, contentsType, uint16(bytes(contentsType).length)
        );

        vm.prank(dapp);
        assertEq(accountA.isValidSignature(hash, sig), bytes4(0x1626ba7e));
        vm.prank(dapp);
        assertEq(accountB.isValidSignature(hash, sig), bytes4(0xffffffff));
    }

    function test_validateUserOp_usesCaller() public {
        bytes32 opHash = keccak256("userop");
        txVerifier.allow(opHash, ROOT);
        PackedUserOperation memory op;
        op.sender = address(0xdead); // must be ignored
        op.signature = PROOF;
        assertEq(accountA.validateUserOp(op, opHash), 0);

        MockAccount fresh = new MockAccount(validator, "fresh");
        assertEq(fresh.validateUserOp(op, opHash), 1);
    }

    /*//////////////////////////////////////////////////////////////////////////
                         F-04 / F-05: Safe proxy & singleton
    //////////////////////////////////////////////////////////////////////////*/

    function test_proxy_onlyFactoryCanDeploy() public {
        ZKMultiSigEcdsaFactory factory = new ZKMultiSigEcdsaFactory(address(stateVerifier));
        address singleton = address(factory.SINGLETON());
        vm.expectRevert(bytes("ZK MultiSig: Only factory can deploy"));
        new ZKMultiSigEcdsaProxy(singleton, ROOT, address(txVerifier));
    }

    function test_factory_createSigner_and_verify() public {
        ZKMultiSigEcdsaFactory factory = new ZKMultiSigEcdsaFactory(address(stateVerifier));
        address signer = factory.createSigner(ROOT, address(txVerifier), PROOF);
        assertEq(signer, factory.getSigner(ROOT, address(txVerifier)));
        assertGt(signer.code.length, 0);

        txVerifier.allow(HASH, ROOT);
        (bool ok, bytes memory ret) = signer.staticcall(
            abi.encodeWithSignature("isValidSignature(bytes32,bytes)", HASH, PROOF)
        );
        assertTrue(ok);
        assertEq(abi.decode(ret, (bytes4)), bytes4(0x1626ba7e));

        // Factory's deploy-less verification path (direct staticcall into the singleton) still works
        assertEq(
            factory.isValidSignatureForSigner(HASH, PROOF, ROOT, address(txVerifier)),
            bytes4(0x1626ba7e)
        );
    }

    function test_singleton_directCallRejected() public {
        ZKMultiSigEcdsaFactory factory = new ZKMultiSigEcdsaFactory(address(stateVerifier));
        ZKMultiSigEcdsaSingleton singleton = factory.SINGLETON();
        assertEq(singleton.FACTORY(), address(factory));

        // Attacker appends an always-true verifier + arbitrary root to a direct call.
        MockERC8039Verifier evil = new MockERC8039Verifier();
        evil.allow(HASH, ROOT);
        bytes memory data = abi.encodePacked(
            abi.encodeWithSignature("isValidSignature(bytes32,bytes)", HASH, evil.PROOF()),
            ROOT,
            address(evil)
        );
        (bool ok, bytes memory ret) = address(singleton).staticcall(data);
        assertTrue(ok);
        assertEq(abi.decode(ret, (bytes4)), bytes4(0));
    }

    /*//////////////////////////////////////////////////////////////////////////
                         I-01: ERC-8039 adapters never revert
    //////////////////////////////////////////////////////////////////////////*/

    function test_adapters_doNotRevert() public {
        RevertingHonk honk = new RevertingHonk();
        ZKMultiSigEcdsaProofVerifier txAdapter = new ZKMultiSigEcdsaProofVerifier(address(honk));
        PrivateStateValidationProofVerifier stAdapter =
            new PrivateStateValidationProofVerifier(HonkVerifier(address(honk)));

        bytes32[] memory one = new bytes32[](1);
        bytes32[] memory thirtyThree = new bytes32[](33);

        // wrong lengths
        assertEq(txAdapter.verifyProof(abi.encode(one), hex""), bytes4(0));
        assertEq(stAdapter.verifyProof(abi.encode(thirtyThree), hex""), bytes4(0));
        // garbage encodings
        assertEq(txAdapter.verifyProof(hex"01", hex""), bytes4(0));
        assertEq(stAdapter.verifyProof(hex"", hex""), bytes4(0));
        // right length but reverting verifier
        assertEq(txAdapter.verifyProof(abi.encode(thirtyThree), hex"aa"), bytes4(0));
        assertEq(stAdapter.verifyProof(abi.encode(one), hex"aa"), bytes4(0));
    }
}
