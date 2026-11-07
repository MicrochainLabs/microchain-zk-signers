use poseidon::poseidon::bn254::hash_1 as poseidon1;
use poseidon::poseidon::bn254::hash_3 as poseidon3;

pub global MAX_THRESHOLD: u8 = 5;
pub global MAX_SIGNERS: u32 = 5;

/// Compute the on-chain commitment to the private signer configuration.
///
///     state_root = Poseidon3(signers_root, Poseidon1(threshold), salt)
///
/// `salt` is a private, uniformly random, non-zero field element. It makes the
/// commitment hiding: without it the (public) address space and the tiny
/// threshold range make the signer set recoverable from `state_root` by a
/// dictionary attack. This function MUST stay identical to the one in
/// `zk_multi_sig_ecdsa` and to `computeStateRoot` in `zkcommon/stateRoot.ts`.
pub fn compute_state_root(signers_root: Field, threshold: u8, salt: Field) -> Field {
    let threshold_hash = poseidon1([threshold as Field]);
    poseidon3([signers_root, threshold_hash, salt])
}

/// Verify the private state configuration.
///
/// This function validates that:
/// 1. The signers_root and salt are non-zero
/// 2. The threshold is within acceptable bounds
/// 3. The state root correctly combines signers_root + threshold + salt
fn validate_private_state_inputs(
    signers_root: Field,
    threshold: u8,
    salt: Field,
    on_chain_state_root: Field
) {
    // Validate signers_root is non-zero (defense-in-depth)
    assert(signers_root != 0, "Signers root cannot be zero");

    // A zero salt would degrade the commitment to a non-hiding one
    assert(salt != 0, "Salt cannot be zero");

    // Validate threshold is reasonable
    assert(threshold > 0, "Threshold must be greater than 0");
    assert(threshold <= MAX_THRESHOLD, "Threshold exceeds maximum allowed");
    assert(threshold as u32 <= MAX_SIGNERS, "Threshold cannot exceed number of signers");

    let state_root = compute_state_root(signers_root, threshold, salt);
    assert(on_chain_state_root == state_root, "State root mismatch");
}

fn main(
    signers_root: Field,
    threshold: u8,
    salt: Field,
    on_chain_state_root: pub Field
) {
    validate_private_state_inputs(signers_root, threshold, salt, on_chain_state_root);
}

// Shared test vector (also used by zk_multi_sig_ecdsa and zkcommon/stateRoot.ts):
//   signers_root = 16223743289759414337474221898890222788896083712324022742978151074941795950178
//   threshold    = 2
//   salt         = 0x0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef
//   state_root   = 20321389246711366214573318284446720008267991448836355782945972567979658685784
global TEST_SIGNERS_ROOT: Field = 16223743289759414337474221898890222788896083712324022742978151074941795950178;
global TEST_THRESHOLD: u8 = 2;
global TEST_SALT: Field = 0x0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef;
global TEST_STATE_ROOT: Field = 20321389246711366214573318284446720008267991448836355782945972567979658685784;

#[test]
fn test_main() {
    //nargo test --show-output
    main(TEST_SIGNERS_ROOT, TEST_THRESHOLD, TEST_SALT, TEST_STATE_ROOT)
}

#[test]
fn test_salt_is_part_of_commitment() {
    // The unsalted (legacy) construction must not be accepted for a salted root.
    let legacy_root = 10223786790855367822232839749406742084971735911793673331153158573476372880461;
    assert(compute_state_root(TEST_SIGNERS_ROOT, TEST_THRESHOLD, TEST_SALT) != legacy_root);
}

#[test(should_fail_with = "Salt cannot be zero")]
fn test_zero_salt_rejected() {
    let root = compute_state_root(TEST_SIGNERS_ROOT, TEST_THRESHOLD, 0);
    main(TEST_SIGNERS_ROOT, TEST_THRESHOLD, 0, root)
}

#[test(should_fail_with = "State root mismatch")]
fn test_wrong_salt_rejected() {
    main(TEST_SIGNERS_ROOT, TEST_THRESHOLD, TEST_SALT + 1, TEST_STATE_ROOT)
}

#[test(should_fail_with = "Signers root cannot be zero")]
fn test_zero_signers_root_rejected() {
    let root = compute_state_root(0, TEST_THRESHOLD, TEST_SALT);
    main(0, TEST_THRESHOLD, TEST_SALT, root)
}

#[test(should_fail_with = "Threshold must be greater than 0")]
fn test_zero_threshold_rejected() {
    let root = compute_state_root(TEST_SIGNERS_ROOT, 0, TEST_SALT);
    main(TEST_SIGNERS_ROOT, 0, TEST_SALT, root)
}

#[test(should_fail_with = "Threshold exceeds maximum allowed")]
fn test_threshold_above_max_rejected() {
    let root = compute_state_root(TEST_SIGNERS_ROOT, 6, TEST_SALT);
    main(TEST_SIGNERS_ROOT, 6, TEST_SALT, root)
}
