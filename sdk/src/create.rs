use ethrex_common::Address;
use ethrex_rlp::encode::RLPEncode;
use keccak_hash::{H256, keccak};
use rand::RngCore;
use rand_xoshiro::Xoshiro256PlusPlus;
use rand_xoshiro::rand_core::SeedableRng;
use rand_xoshiro::rand_core::TryRngCore;
use rayon::prelude::*;
use std::iter;

use crate::utils::to_checksum_address;

pub const DETERMINISTIC_DEPLOYER: &str = "0x4e59b44847b379578588920cA78FbF26c0B4956C";

/// address = keccak256(rlp([sender_address,sender_nonce]))[12:]
pub fn compute_create_address(sender_address: Address, sender_nonce: u64) -> Address {
    let mut encoded = Vec::new();
    (sender_address, sender_nonce).encode(&mut encoded);
    let keccak_bytes = keccak(encoded).0;
    Address::from_slice(&keccak_bytes[12..])
}

/// address = keccak256(0xff || deployer_address || salt || keccak256(initialization_code))[12:]
pub fn compute_create2_address(
    deployer_address: Address,
    init_code_hash: H256,
    salt: H256,
) -> Address {
    Address::from_slice(
        &keccak(
            [
                &[0xff],
                deployer_address.as_bytes(),
                &salt.0,
                init_code_hash.as_bytes(),
            ]
            .concat(),
        )
        .as_bytes()[12..],
    )
}

/// Brute-force Create2 address generation
/// This function generates random salts until it finds one that matches the specified criteria.
/// `begins`, `ends`, and `contains` are optional filters for the generated address.
/// If they are not provided, the function will not filter based on that criterion.
/// Returns the salt and the generated address.
pub fn brute_force_create2(
    deployer: Address,
    init_code_hash: H256,
    mut begins: Option<String>,
    mut ends: Option<String>,
    mut contains: Option<String>,
    case_sensitive: bool,
) -> (H256, Address) {
    // If we don't care about case convert everything to lowercase.
    if !case_sensitive {
        begins = begins.map(|b| b.to_lowercase());
        ends = ends.map(|e| e.to_lowercase());
        contains = contains.map(|c| c.to_lowercase());
    }
    loop {
        // Generate random salt
        let mut salt_bytes = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut salt_bytes);
        let salt = H256::from(salt_bytes);

        // Compute Create2 Address
        let candidate_address = compute_create2_address(deployer, init_code_hash, salt);

        // Address as string without 0x prefix
        let addr_str = if !case_sensitive {
            format!("{candidate_address:x}")
        } else {
            to_checksum_address(&format!("{candidate_address:x}"))
        };

        // Validate that address satisfies the requirements given by the user.
        let matches_begins = begins.as_ref().is_none_or(|b| addr_str.starts_with(b));
        let matches_ends = ends.as_ref().is_none_or(|e| addr_str.ends_with(e));
        let matches_contains = contains.as_ref().is_none_or(|c| addr_str.contains(c));

        if matches_begins && matches_ends && matches_contains {
            return (salt, candidate_address);
        }
    }
}

pub fn brute_force_create2_rayon(
    deployer: Address,
    init_code_hash: H256,
    begins: Option<String>,
    ends: Option<String>,
    contains: Option<String>,
    case_sensitive: bool,
) -> (H256, Address) {
    // If not case sensitive make the comparison with lowercase
    let begins = begins.map(|s| if case_sensitive { s } else { s.to_lowercase() });
    let ends = ends.map(|s| if case_sensitive { s } else { s.to_lowercase() });
    let contains = contains.map(|s| if case_sensitive { s } else { s.to_lowercase() });

    let mut rng = Xoshiro256PlusPlus::from_os_rng();
    let mut bytes = [0u8; 32];

    iter::repeat_with(|| {
        rng.try_fill_bytes(&mut bytes).unwrap();
        H256::from(bytes)
    })
    .par_bridge() // Convert into a parallel iterator
    .find_any(|salt| {
        // Find a salt that satisfies the criteria set by the user.
        let addr = compute_create2_address(deployer, init_code_hash, *salt);

        // Convert address to string, if it's not case sensitive leave it in lowercase.
        let addr_str = if !case_sensitive {
            format!("{addr:x}") // we could compare bytes directly but this produces cleaner code
        } else {
            to_checksum_address(&format!("{addr:x}"))
        };

        let matches_begins = begins.as_deref().is_none_or(|b| addr_str.starts_with(b));
        let matches_ends = ends.as_deref().is_none_or(|e| addr_str.ends_with(&e));
        let matches_contains = contains.as_deref().is_none_or(|c| addr_str.contains(c));

        matches_begins && matches_ends && matches_contains
    })
    .map(|salt| {
        let addr = compute_create2_address(deployer, init_code_hash, salt);
        (salt, addr)
    })
    .expect("should eventually find a match")
}

#[test]
fn compute_address() {
    use std::str::FromStr;

    // Example Transaction: https://etherscan.io/tx/0x99b6e68fa690db1df9a969b838fb27e1254c0fc115428b3cc5695ab74ffe3943
    assert_eq!(
        Address::from_str("0x552b0c6688fcae5cf0164f27fd129b882a42fa05").unwrap(),
        compute_create_address(
            Address::from_str("0x899c284A89E113056a72dC9ade5b60E80DD3c94f").unwrap(),
            1
        )
    );
}
