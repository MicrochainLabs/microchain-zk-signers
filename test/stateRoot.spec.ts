import { expect } from "chai";
import {
    buildMultiSigTree,
    computeStateRoot,
    generateSalt,
    parseSalt,
} from "zk-smart-account-kit-sdk/zk-multisig";

const BN254_FIELD_MODULUS = 21888242871839275222246405745257275088548364400416034343698204186575808495617n;

// Shared vector with the Noir circuits (`TEST_*` globals in noir/*/src/main.nr).
const SIGNERS_ROOT = 16223743289759414337474221898890222788896083712324022742978151074941795950178n;
const THRESHOLD = 2;
const SALT = BigInt("0x0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef");
const STATE_ROOT = 20321389246711366214573318284446720008267991448836355782945972567979658685784n;
const LEGACY_UNSALTED_ROOT = 10223786790855367822232839749406742084971735911793673331153158573476372880461n;

describe("zk-smart-account-kit-sdk state root (shared Noir vectors)", () => {
    it("computeStateRoot matches the Noir compute_state_root test vector", () => {
        expect(computeStateRoot(SIGNERS_ROOT, THRESHOLD, SALT)).to.equal(STATE_ROOT);
    });

    it("salted root differs from the legacy unsalted construction", () => {
        expect(computeStateRoot(SIGNERS_ROOT, THRESHOLD, SALT)).to.not.equal(LEGACY_UNSALTED_ROOT);
    });

    it("root depends on the salt", () => {
        expect(computeStateRoot(SIGNERS_ROOT, THRESHOLD, SALT + 1n)).to.not.equal(STATE_ROOT);
    });

    it("rejects a zero salt and out-of-range thresholds", () => {
        expect(() => computeStateRoot(SIGNERS_ROOT, THRESHOLD, 0n)).to.throw("Invalid salt");
        expect(() => computeStateRoot(SIGNERS_ROOT, 0, SALT)).to.throw("threshold");
        expect(() => computeStateRoot(SIGNERS_ROOT, 6, SALT)).to.throw("threshold");
    });

    it("generateSalt returns distinct non-zero field elements", () => {
        const a = generateSalt();
        const b = generateSalt();
        expect(a).to.not.equal(0n);
        expect(a < BN254_FIELD_MODULUS).to.equal(true);
        expect(a).to.not.equal(b);
    });

    it("parseSalt accepts hex/decimal and rejects invalid values", () => {
        expect(parseSalt("0x0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")).to.equal(SALT);
        expect(parseSalt(SALT.toString())).to.equal(SALT);
        expect(() => parseSalt(undefined)).to.throw("Missing private salt");
        expect(() => parseSalt("")).to.throw("Missing private salt");
        expect(() => parseSalt("0")).to.throw("Invalid salt");
        expect(() => parseSalt(BN254_FIELD_MODULUS.toString())).to.throw("BN254 field modulus");
        expect(() => parseSalt("not-a-number")).to.throw("Invalid salt");
    });

    it("buildMultiSigTree is order- and case-insensitive and rejects duplicates", () => {
        const signers = [
            "0x70997970C51812dc3A010C7d01b50e0d17dc79C8",
            "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266",
            "0x3C44CdDdB6a900fa2b585dd299e03d12FA4293BC",
        ];
        const a = buildMultiSigTree(signers).signersRoot;
        const b = buildMultiSigTree([...signers].reverse().map(s => s.toLowerCase())).signersRoot;
        expect(a).to.equal(b);
        expect(() => buildMultiSigTree([signers[0], signers[0].toLowerCase()])).to.throw("duplicate");
        expect(() => buildMultiSigTree([])).to.throw("between 1 and");
    });
});
