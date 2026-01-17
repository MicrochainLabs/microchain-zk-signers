use dep::std;
use poseidon::poseidon::bn254::hash_1 as poseidon1;
use poseidon::poseidon::bn254::hash_2 as poseidon2;
use binary_merkle_root::binary_merkle_root;
use keccak256::keccak256;

// Maximum depth of the Merkle Tree.
pub global SIGNERS_MAX_DEPTH: u32 = 4;
pub global MICROCHAIN_OWNERSHIP_STATE_MAX_DEPTH: u32 = 1;
pub global MAX_SIGNERS: u32 = 5;

type Address = [u8; 20];
type Signature = [u8; 64];
type Hash = [u8; 32];
struct  PubKey {
    x: [u8; 32],
    y: [u8; 32],
}

/// Compare two arrays of bytes, return true if a > b.
fn cmp_gt<let N: u32>(a: [u8; N], b: [u8; N]) -> bool {
    let mut result = false;
    let mut done = false;
    for i in 0..N {
        if !done {
            if a[i] > b[i] {
                result = true;
                done = true;
            } else if a[i] < b[i] {
                result = false;
                done = true;
            }
        }
    }
    result
}

/// Verify if the signatures are valid and the signers are in the owners list.
fn verify_signers(signers: [PubKey; MAX_SIGNERS], signers_root: Field, threshold: u8, merkle_proof_length: [u32; MAX_SIGNERS], merkle_proof_indices: [[u1; SIGNERS_MAX_DEPTH]; MAX_SIGNERS], merkle_proof_siblings: [[Field; SIGNERS_MAX_DEPTH]; MAX_SIGNERS], signatures: [Signature; MAX_SIGNERS], salt: Field, txn_hash: Hash, on_chain_state_root: Field) {
    
    let mut curr_owner = [0; 20];
    let mut num_verified_signatures = 0;
    // We use the generator point of the secp256k1 curve as the NIL value.
    let g_x = [121, 190, 102, 126, 249, 220, 187, 172, 85, 160, 98, 149, 206, 135, 11, 7, 2, 155, 252, 219, 45, 206, 40, 217, 89, 242, 129, 91, 22, 248, 23, 152];
    let g_y = [72, 58, 218, 119, 38, 163, 196, 101, 93, 164, 251, 252, 14, 17, 8, 168, 253, 23, 180, 72, 166, 133, 84, 25, 156, 71, 208, 143, 251, 16, 212, 184];
    for i in 0..MAX_SIGNERS {
        // check only if the signature is not NIL
        if (signers[i].x != g_x) & (signers[i].y != g_y) {
            // First, check that it verifies
            assert(std::ecdsa_secp256k1::verify_signature(signers[i].x, signers[i].y, signatures[i], txn_hash));
            // Then, find the address to which the verifying key corresponds.
            let mut uncompressed_pubkey = [0; 64];
            for j in 0..32 {
                uncompressed_pubkey[j] = signers[i].x[j];
                uncompressed_pubkey[j + 32] = signers[i].y[j];
            }
            let pubkey_hash = keccak256(uncompressed_pubkey, 64);
            let mut address: Address = [0; 20];
            for j in 0..20 {
                address[j] = pubkey_hash[j + 12];
            }
            // Check the uniquiness of each signature by requiring and asserting they are sorted in strictly increasing order.
            // We need this to avoid the same signature being used mulitple times.
            // (Check Safe verification code for more details - it does the same checking).
            assert(cmp_gt(address, curr_owner));

            // Check that the address is in the merkle tree of owners.   
            let mut result : Field = 0;
            let mut v : Field = 1;
            for k in 0..20 {
                result += address[19 - k] as Field * v;
                v *= 256 as Field;
            }

            let address_hash = poseidon1([result]);
            let merkle_root = binary_merkle_root(
                poseidon2,
                address_hash,
                merkle_proof_length[i],
                merkle_proof_indices[i],
                merkle_proof_siblings[i],
            );
            assert(signers_root == merkle_root);

            curr_owner = address;
            num_verified_signatures += 1;
        }
    }
    
    assert(num_verified_signatures >= threshold);

    // Compute state root: depth 1 tree with signers_root (left) and threshold (right)
    // Hash threshold for consistency with other leaf values in the Merkle tree
    let threshold_hash = poseidon1([threshold as Field]);
    let preliminary_state_root = binary_merkle_root(
        poseidon2,
        signers_root,
        MICROCHAIN_OWNERSHIP_STATE_MAX_DEPTH,
        [0],
        [threshold_hash]
    );
    let final_state_root = poseidon2([preliminary_state_root, salt]);
    assert(on_chain_state_root == final_state_root);

}

fn main(
    signers: [PubKey; MAX_SIGNERS], 
    threshold: u8, 
    signers_root: Field, 
    merkle_proof_length: [u32; MAX_SIGNERS], 
    indices: [[u1; SIGNERS_MAX_DEPTH]; MAX_SIGNERS], 
    siblings: [[Field; SIGNERS_MAX_DEPTH]; MAX_SIGNERS], 
    signatures: [Signature; MAX_SIGNERS], 
    salt: Field,
    txn_hash: pub Hash, 
    on_chain_state_root: pub Field) {
    verify_signers(signers, signers_root, threshold, merkle_proof_length, indices, siblings, signatures, salt, txn_hash, on_chain_state_root);
}

#[test]
fn test_main() {
//nargo test --show-output

    let threshold = 2;
    let signers = [
        PubKey{
            x: [
                72,   1,  30, 230,  91,  21,  46,  66,
                193,  95, 233, 248,  86, 207, 140,  91,
                80, 119,  39, 144, 184,  39,  70, 134,
                141, 250, 220, 201, 167, 248, 255, 243

            ],
            y: [
                0, 100, 194,  43, 149, 206, 172, 238,
                115, 114, 169, 155, 254, 212, 156,   4,
                240,  92,  23, 239, 117, 215,  50, 241,
                167,  57, 189, 116,   7, 168,  46, 156

            ]
        },
        PubKey{
            x: [
                83,  30, 186,  98, 194, 161,  18, 194,
                105, 174, 111,  22,  52,  22, 165, 173,
                24,  91, 191, 117, 231,  80, 246, 155,
                1, 246, 254, 192, 186,  81,   0,  69

            ],
            y: [
                106, 239, 250, 131,  78, 113, 201, 129,
                169, 246, 116,  42,  70, 202, 220,  29,
                44, 206,  19,  82, 241,  25,  34,  66,
                75,  96,  55,  20, 216,  80, 127,  52

            ]
        },
        PubKey{
            x: [
                121, 190, 102, 126, 249, 220, 187, 172,
                85, 160,  98, 149, 206, 135,  11,   7,
                2, 155, 252, 219,  45, 206,  40, 217,
                89, 242, 129,  91,  22, 248,  23, 152
            ],
            y: [
                72,  58, 218, 119,  38, 163, 196, 101,
                93, 164, 251, 252,  14,  17,   8, 168,
                253,  23, 180,  72, 166, 133,  84,  25,
                156,  71, 208, 143, 251,  16, 212, 184
            ]
        },
        PubKey{
            x: [
                121, 190, 102, 126, 249, 220, 187, 172,
                85, 160,  98, 149, 206, 135,  11,   7,
                2, 155, 252, 219,  45, 206,  40, 217,
                89, 242, 129,  91,  22, 248,  23, 152
            ],
            y: [
                72,  58, 218, 119,  38, 163, 196, 101,
                93, 164, 251, 252,  14,  17,   8, 168,
                253,  23, 180,  72, 166, 133,  84,  25,
                156,  71, 208, 143, 251,  16, 212, 184
            ]
        },
        PubKey{
            x: [
                121, 190, 102, 126, 249, 220, 187, 172,
                85, 160,  98, 149, 206, 135,  11,   7,
                2, 155, 252, 219,  45, 206,  40, 217,
                89, 242, 129,  91,  22, 248,  23, 152
            ],
            y: [
                72,  58, 218, 119,  38, 163, 196, 101,
                93, 164, 251, 252,  14,  17,   8, 168,
                253,  23, 180,  72, 166, 133,  84,  25,
                156,  71, 208, 143, 251,  16, 212, 184
            ]
        }
    ];
    let signatures = [
        [
            134, 189, 173, 134, 181,  61,  58, 170, 191, 212,  52,
            175, 208,  12, 213,  19, 162, 231, 240,  19, 229, 245,
            28, 183, 130, 239,  97, 224,  34, 197,  84, 224,  72,
            125,  63, 153, 152, 195,   0, 127, 186,  70, 238,  84,
            148,  67, 247,  64,  60,  49, 210,   7,   6, 251, 154,
            157, 136, 132,  32, 230,  80,  24, 114, 193

        ],
        [
            223, 109, 120,  50, 167, 182, 208, 234, 236,  43,  28,
            65,  82,  71, 133, 117,   0, 215,  99, 106, 104, 130,
            254, 100, 107, 187,   8, 147,  33, 240, 182, 145,  69,
            240,   7, 137, 134, 145,  25, 151, 218, 232,  34, 173,
            229,  61, 158, 229, 139, 128, 216, 218, 170,  37, 191,
            86, 235, 109, 110,  85, 221,   1,  60, 211

        ],

        [
            121, 190, 102, 126, 249, 220, 187, 172,  85, 160,  98,
            149, 206, 135,  11,   7,   2, 155, 252, 219,  45, 206,
            40, 217,  89, 242, 129,  91,  22, 248,  23, 152,  72,
            58, 218, 119,  38, 163, 196, 101,  93, 164, 251, 252,
            14,  17,   8, 168, 253,  23, 180,  72, 166, 133,  84,
            25, 156,  71, 208, 143, 251,  16, 212, 184
        ],
        [
            121, 190, 102, 126, 249, 220, 187, 172,  85, 160,  98,
            149, 206, 135,  11,   7,   2, 155, 252, 219,  45, 206,
            40, 217,  89, 242, 129,  91,  22, 248,  23, 152,  72,
            58, 218, 119,  38, 163, 196, 101,  93, 164, 251, 252,
            14,  17,   8, 168, 253,  23, 180,  72, 166, 133,  84,
            25, 156,  71, 208, 143, 251,  16, 212, 184
        ],
        [
            121, 190, 102, 126, 249, 220, 187, 172,  85, 160,  98,
            149, 206, 135,  11,   7,   2, 155, 252, 219,  45, 206,
            40, 217,  89, 242, 129,  91,  22, 248,  23, 152,  72,
            58, 218, 119,  38, 163, 196, 101,  93, 164, 251, 252,
            14,  17,   8, 168, 253,  23, 180,  72, 166, 133,  84,
            25, 156,  71, 208, 143, 251,  16, 212, 184
        ]
    ];
    let txn_hash = [
        233, 164, 235, 190,  68, 158,  98, 117,
        14,  91,  81, 167, 194, 152, 149, 192,
        121, 106,  12, 186,  94,   4,  35, 240,
        213, 220,  12, 196, 113, 141, 210, 117


    ];
    let signers_root = 16223743289759414337474221898890222788896083712324022742978151074941795950178;
    let merkle_proof_length = [ 2, 1, 0, 0, 0];
    let indices = [ 
        [ 0, 0, 0, 0 ],
        [ 1, 0, 0, 0 ],
        [ 0, 0, 0, 0 ],
        [ 0, 0, 0, 0 ],
        [ 0, 0, 0, 0 ]
     ];
    let siblings =  [
        [ 12517834438782012532142902368981775795544279798764039177004793700602327702286, 20482135275829837109546745489042441667237462547252720092535479030520979794670, 0, 0 ],
        [ 19321118740171137787160613615629793082668961880615698531220246514284540091326, 0, 0, 0 ],
        [ 0, 0, 0, 0],
        [ 0, 0, 0, 0],
        [ 0, 0, 0, 0]
    ];

    let salt = 1;
    let state_root = 10223786790855367822232839749406742084971735911793673331153158573476372880461;

    main(signers, threshold, signers_root, merkle_proof_length, indices, siblings, signatures, salt, txn_hash, state_root)
}