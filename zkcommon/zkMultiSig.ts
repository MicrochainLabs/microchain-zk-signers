import { readFileSync } from "fs";
import { join } from "path";
import type { Hex } from "viem";
import {
    createMultiSigState,
    generateMultiSigProof,
    generateStateValidationProof,
    generateSalt,
    parseSalt,
    saltToHex,
    type MultiSigConfig,
    type MultiSigState,
    type ProveOptions,
    type SignersFormat,
} from "zk-smart-account-kit-sdk/zk-multisig";

/**
 * Glue between the CLI (zksafe / zknexus) and `zk-smart-account-kit-sdk`.
 *
 * All commitment, signers-tree, salt and proof logic lives in the SDK; this file only loads the compiled
 * circuits from `noir/target` and adapts the CLI's argument conventions.
 */

type CircuitName = "zk_multi_sig_ecdsa" | "zk_multi_sig_ecdsa_private_state_validation";

/** Loads a compiled circuit artifact from `noir/target` (relative to the working directory). */
export function loadCircuit(name: CircuitName): unknown {
    return JSON.parse(readFileSync(join(process.cwd(), "noir", "target", `${name}.json`), "utf-8"));
}

/**
 * Maps the CLI's `--signersaddressesformat` flag (0 / "normal": addresses, 1 / "hash": Poseidon-hashed addresses).
 * Hardhat passes task parameters as strings, so numeric strings are accepted.
 */
export function signersFormatFromFlag(flag: number | string): SignersFormat {
    const value = typeof flag === "string" ? flag.trim().toLowerCase() : flag;
    if (value === 0 || value === "0" || value === "normal") return "address";
    if (value === 1 || value === "1" || value === "hash") return "poseidon-hash";
    throw new Error("Invalid owner addresses format variable value (0 / normal: Normal address) or (1 / hash: Poseidon Hash address)");
}

/** Hardhat passes task parameters as strings; the SDK requires a real integer threshold. */
export function parseThreshold(threshold: number | string): number {
    const value = typeof threshold === "string" ? Number(threshold.trim()) : threshold;
    if (!Number.isInteger(value)) {
        throw new Error(`Invalid private threshold: expected an integer, got "${threshold}"`);
    }
    return value;
}

/**
 * Derives the private configuration. A fresh random salt is generated unless one is supplied
 * (e.g. to re-create a known configuration).
 */
export function deriveState(
    signers: string[],
    threshold: number | string,
    privateSalt?: string,
): { state: MultiSigState; saltHex: Hex; saltProvided: boolean } {
    const saltProvided = privateSalt !== undefined && privateSalt.trim() !== "";
    const salt = saltProvided ? parseSalt(privateSalt) : generateSalt();
    const state = createMultiSigState({ signers, threshold: parseThreshold(threshold), salt });
    return { state, saltHex: saltToHex(salt), saltProvided };
}

/** Proves that the state root of `config` commits to a valid configuration (needed to create an account). */
export async function proveStateValidation(config: MultiSigConfig, options?: ProveOptions) {
    console.log("Generating state validation proof...");
    const startTime = Date.now();
    const proofData = await generateStateValidationProof(config, loadCircuit("zk_multi_sig_ecdsa_private_state_validation"), options);
    console.log(`State validation proof generated and verified in ${Date.now() - startTime}ms`);
    return proofData;
}

/**
 * Proves that `threshold` members of the private signer set signed `txHash`.
 * Fails early if the configuration does not match `onChainStateRoot`.
 */
export async function proveTransaction(
    config: MultiSigConfig,
    txHash: Hex,
    signatures: Hex[],
    onChainStateRoot: Hex,
    options?: ProveOptions,
) {
    console.log("Generating proof...");
    const startTime = Date.now();
    const proofData = await generateMultiSigProof(config, txHash, signatures, onChainStateRoot, loadCircuit("zk_multi_sig_ecdsa"), options);
    console.log(`Proof generated and verified in ${Date.now() - startTime}ms`);
    console.log(`Proof size: ${proofData.proof.length / 2 - 1} bytes`);
    console.log(`Public inputs: ${proofData.publicInputs.length}`);
    return proofData;
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
