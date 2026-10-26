import { poseidon } from "@iden3/js-crypto";
import { LeanIMT } from "@zk-kit/lean-imt";
import { Hex, toHex } from "viem";
import { randomBytes } from "crypto";

/**
 * Shared commitment helpers for the Microchain ZK Signers protocol.
 *
 * The on-chain commitment is
 *
 *     state_root = Poseidon3(signers_root, Poseidon1(threshold), salt)
 *
 * and MUST match `compute_state_root` in both Noir circuits
 * (`noir/zk_multi_sig_ecdsa` and `noir/zk_multi_sig_ecdsa_private_state_validation`).
 *
 * `salt` is a private random field element that makes the commitment hiding. Without it the
 * signer set and threshold could be recovered from the public state root by enumerating
 * candidate addresses. The salt must be stored by the owners together with the signer list;
 * it is required to generate every proof and cannot be recovered from on-chain data.
 */

/** BN254 scalar field modulus (the Noir `Field` type). */
export const BN254_FIELD_MODULUS =
    21888242871839275222246405745257275088548364400416034343698204186575808495617n;

export const MAX_SIGNERS = 5;

/** Poseidon2 used for the LeanIMT nodes (arity 2). */
export const treeHash = (a: bigint, b: bigint) => poseidon.hash([a, b]);

/** Numerically sorts addresses, matching the strict byte-wise ordering enforced by the circuit. */
export function sortAddresses<T extends string>(addresses: T[]): T[] {
    return [...addresses].sort((a, b) => {
        const x = BigInt(a);
        const y = BigInt(b);
        return x < y ? -1 : x > y ? 1 : 0;
    });
}

/** Leaf for an address: Poseidon1(address). */
export function addressLeaf(address: string): bigint {
    return poseidon.hash([BigInt(address)]);
}

/**
 * Builds the signers LeanIMT.
 * @param signers       Signer addresses (any order / case).
 * @param leavesAreHashed `true` when `signers` already contains Poseidon1(address) leaves.
 */
export function buildSignersTree(signers: string[], leavesAreHashed = false): LeanIMT {
    if (signers.length === 0 || signers.length > MAX_SIGNERS) {
        throw new Error(`Signer set must contain between 1 and ${MAX_SIGNERS} addresses`);
    }
    if (new Set(signers.map(s => BigInt(s))).size !== signers.length) {
        throw new Error("Signer set contains duplicate addresses");
    }
    const tree = new LeanIMT(treeHash);
    for (const signer of sortAddresses(signers)) {
        tree.insert(leavesAreHashed ? BigInt(signer) : addressLeaf(signer));
    }
    return tree;
}

/** `state_root = Poseidon3(signers_root, Poseidon1(threshold), salt)` */
export function computeStateRoot(signersRoot: bigint, threshold: number | bigint, salt: bigint): bigint {
    const t = BigInt(threshold);
    if (t <= 0n || t > BigInt(MAX_SIGNERS)) {
        throw new Error(`Threshold must be in [1, ${MAX_SIGNERS}]`);
    }
    if (salt === 0n) {
        throw new Error("Salt must be non-zero");
    }
    return poseidon.hash([signersRoot, poseidon.hash([t]), salt]);
}

/** Generates a fresh random salt (uniform in the BN254 scalar field, non-zero). */
export function generateSalt(): bigint {
    for (;;) {
        // 31 random bytes are always < field modulus; rejection on 0 keeps it non-zero.
        const s = BigInt(toHex(randomBytes(31)));
        if (s !== 0n) return s;
    }
}

/** Parses and validates a user-supplied salt (hex or decimal). */
export function parseSalt(salt: string | undefined): bigint {
    if (salt === undefined || salt.trim() === "") {
        throw new Error(
            "Missing private salt. Pass the salt that was generated when the account was created (--privatesalt)."
        );
    }
    let value: bigint;
    try {
        value = BigInt(salt.trim());
    } catch {
        throw new Error("Invalid salt: expected a hex (0x…) or decimal number");
    }
    if (value <= 0n || value >= BN254_FIELD_MODULUS) {
        throw new Error("Invalid salt: must be non-zero and smaller than the BN254 field modulus");
    }
    return value;
}

export function fieldToHex(value: bigint): Hex {
    return toHex(value);
}

/**
 * Prints the private salt once, with a backup warning. The salt is not a signing key
 * (it cannot authorize transactions) but it is required to generate every proof and
 * cannot be recovered from on-chain data: losing it locks the account.
 */
export function printSaltBackupNotice(saltHex: Hex, saltProvided: boolean) {
    console.log("\n🔑 PRIVATE SALT (" + (saltProvided ? "as provided" : "freshly generated") + "):");
    console.log("   " + saltHex);
    console.log("   ⚠️  Back this value up together with the private signer list and threshold.");
    console.log("   ⚠️  It is required for every proof (--privatesalt) and is NOT recoverable from chain.");
    console.log("   ⚠️  Anyone holding it together with the signer list can de-anonymise the account.");
}
