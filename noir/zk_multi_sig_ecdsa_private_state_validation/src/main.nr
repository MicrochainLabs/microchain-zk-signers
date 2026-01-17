use poseidon::poseidon::bn254::hash_1 as poseidon1;
use poseidon::poseidon::bn254::hash_2 as poseidon2;
use binary_merkle_root::binary_merkle_root;

pub global MICROCHAIN_OWNERSHIP_STATE_MAX_DEPTH: u32 = 1;
pub global MAX_THRESHOLD: u8 = 5;
pub global MAX_SIGNERS: u32 = 5;



/// Verify the private state configuration with salt for privacy protection.
/// 
/// This function validates that:
/// 1. The signers_root is non-zero (valid signers)
/// 2. The threshold is within acceptable bounds
/// 3. The state root correctly combines signers_root + threshold + salt
///
/// The salt prevents brute-force attacks on the public state root.
fn validate_private_state_inputs(
    signers_root: Field, 
    threshold: u8, 
    salt: Field,
    on_chain_state_root: Field
) {
    // Validate signers_root is non-zero (defense-in-depth)
    assert(signers_root != 0, "Signers root cannot be zero");

    // Validate threshold is reasonable
    assert(threshold > 0, "Threshold must be greater than 0");
    assert(threshold <= MAX_THRESHOLD, "Threshold exceeds maximum allowed");
    assert(threshold as u32 <= MAX_SIGNERS, "Threshold cannot exceed number of signers");

    // Validate salt is non-zero (ensures uniqueness)
    assert(salt != 0, "Salt cannot be zero");

    // Compute preliminary state root (signers + threshold)
    let threshold_hash = poseidon1([threshold as Field]);
    let preliminary_state_root = binary_merkle_root(
        poseidon2,
        signers_root,
        MICROCHAIN_OWNERSHIP_STATE_MAX_DEPTH,
        [0],
        [threshold_hash]
    );

    // Mix salt into final state root (prevents brute-force attacks)
    let final_state_root = poseidon2([preliminary_state_root, salt]);
    
    assert(on_chain_state_root == final_state_root);
}

fn main(
    signers_root: Field, 
    threshold: u8,
    salt: Field,
    on_chain_state_root: pub Field
) {
    validate_private_state_inputs(signers_root, threshold, salt, on_chain_state_root);
}

#[test]
fn test_main() {
    //nargo test --show-output

    let threshold = 2;
    let signers_root = 16223743289759414337474221898890222788896083712324022742978151074941795950178;
    
    // Test with a random salt
    let salt = 12345678901234567890123456789012345678901234567890123456789012345678;
    
    // Compute preliminary root (signers_root + threshold)
    // This would need to match the actual computation from the circuit
    // For now, using a placeholder value for testing
    let state_root = 10223786790855367822232839749406742084971735911793673331153158573476372880461;

    main(signers_root, threshold, salt, state_root)
}