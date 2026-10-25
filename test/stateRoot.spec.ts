import { expect } from "chai";
import {
    BN254_FIELD_MODULUS,
    buildSignersTree,
    computeStateRoot,
    generateSalt,
    parseSalt,
} from "../zkcommon/stateRoot";

// Shared vector with the Noir circuits (`TEST_*` globals in noir/*/src/main.nr).
const SIGNERS_ROOT = 16223743289759414337474221898890222788896083712324022742978151074941795950178n;
const THRESHOLD = 2;
const SALT = BigInt("0x0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef");
const STATE_ROOT = 20321389246711366214573318284446720008267991448836355782945972567979658685784n;
const LEGACY_UNSALTED_ROOT = 10223786790855367822232839749406742084971735911793673331153158573476372880461n;

describe("zkcommon/stateRoot", () => {
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
        expect(() => computeStateRoot(SIGNERS_ROOT, THRESHOLD, 0n)).to.throw("Salt must be non-zero");
        expect(() => computeStateRoot(SIGNERS_ROOT, 0, SALT)).to.throw("Threshold");
        expect(() => computeStateRoot(SIGNERS_ROOT, 6, SALT)).to.throw("Threshold");
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
        expect(() => parseSalt("0")).to.throw("non-zero");
        expect(() => parseSalt(BN254_FIELD_MODULUS.toString())).to.throw("field modulus");
        expect(() => parseSalt("not-a-number")).to.throw("Invalid salt");
    });

    it("buildSignersTree is order- and case-insensitive and rejects duplicates", () => {
        const signers = [
            "0x70997970C51812dc3A010C7d01b50e0d17dc79C8",
            "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266",
            "0x3C44CdDdB6a900fa2b585dd299e03d12FA4293BC",
        ];
        const a = buildSignersTree(signers).root;
        const b = buildSignersTree([...signers].reverse().map(s => s.toLowerCase())).root;
        expect(a).to.equal(b);
        expect(() => buildSignersTree([signers[0], signers[0].toLowerCase()])).to.throw("duplicate");
        expect(() => buildSignersTree([])).to.throw("between 1 and");
    });
});
