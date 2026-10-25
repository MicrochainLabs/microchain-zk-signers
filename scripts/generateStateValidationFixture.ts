/**
 * Regenerates test/fixtures/state_validation_{proof,root}.hex with a real UltraHonk proof of the
 * salted state-validation circuit, using the shared Noir/TS test vector.
 *
 *   TS_NODE_TRANSPILE_ONLY=1 npx ts-node scripts/generateStateValidationFixture.ts
 *
 * Must be re-run whenever noir/zk_multi_sig_ecdsa_private_state_validation changes.
 */
import { readFileSync, writeFileSync } from "fs";
import { join } from "path";
import { Noir } from "@noir-lang/noir_js";
import { Barretenberg, UltraHonkBackend } from "@aztec/bb.js";
import { toHex, pad } from "viem";
import { computeStateRoot, fieldToHex } from "../zkcommon/stateRoot";

const SIGNERS_ROOT = 16223743289759414337474221898890222788896083712324022742978151074941795950178n;
const THRESHOLD = 2;
const SALT = BigInt("0x0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef");

async function main() {
    const root = computeStateRoot(SIGNERS_ROOT, THRESHOLD, SALT);
    const circuit = JSON.parse(readFileSync(join(process.cwd(), "noir", "target", "zk_multi_sig_ecdsa_private_state_validation.json"), "utf-8"));

    const api = await Barretenberg.new({ threads: 1 });
    try {
        const backend = new UltraHonkBackend(circuit.bytecode, api);
        const noir = new Noir(circuit);
        const { witness } = await noir.execute({
            signers_root: toHex(SIGNERS_ROOT),
            threshold: THRESHOLD,
            salt: fieldToHex(SALT),
            on_chain_state_root: pad(toHex(root), { size: 32 }),
        });
        const proofData = await backend.generateProof(witness, { verifierTarget: "evm" });
        if (!(await backend.verifyProof(proofData, { verifierTarget: "evm" }))) {
            throw new Error("Generated proof does not verify");
        }
        const dir = join(process.cwd(), "test", "fixtures");
        writeFileSync(join(dir, "state_validation_proof.hex"), toHex(proofData.proof));
        writeFileSync(join(dir, "state_validation_root.hex"), pad(toHex(root), { size: 32 }));
        console.log("state root  :", pad(toHex(root), { size: 32 }));
        console.log("proof bytes :", proofData.proof.length);
        console.log("public inputs:", proofData.publicInputs);
    } finally {
        await api.destroy();
    }
}

main().catch(e => { console.error(e); process.exit(1); });
