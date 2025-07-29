use ethrex_common::Address;
use ethrex_rlp::encode::RLPEncode;
use keccak_hash::{H256, keccak};
use rand::{RngCore, thread_rng};
use rayon::prelude::*;

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
    begins: Option<String>,
    ends: Option<String>,
    contains: Option<String>,
    case_sensitive: bool,
) -> (H256, Address) {
    // If not case sensitive make the comparison with lowercase

    let mut rng = thread_rng();
    let begins = begins.map(|s| if case_sensitive { s } else { s.to_lowercase() });
    let ends = ends.map(|s| if case_sensitive { s } else { s.to_lowercase() });
    let contains = contains.map(|s| if case_sensitive { s } else { s.to_lowercase() });

    loop {
        // Generate a batch of random salts (100k is a good number)
        let salts: Vec<H256> = (0..100000)
            .map(|_| {
                let mut salt_bytes = [0u8; 32];
                rng.fill_bytes(&mut salt_bytes);
                H256::from(salt_bytes)
            })
            .collect();

        if let Some(salt) = salts.par_iter().find_any(|salt| {
            let addr = compute_create2_address(deployer, init_code_hash, **salt);
            let addr_str = if !case_sensitive {
                format!("{addr:x}")
            } else {
                to_checksum_address(&format!("{addr:x}"))
            };

            let matches_begins = begins.as_deref().is_none_or(|b| addr_str.starts_with(b));
            let matches_ends = ends.as_deref().is_none_or(|e| addr_str.ends_with(e));
            let matches_contains = contains.as_deref().is_none_or(|c| addr_str.contains(c));

            matches_begins && matches_ends && matches_contains
        }) {
            let addr = compute_create2_address(deployer, init_code_hash, *salt);
            break (*salt, addr);
        }
    }
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
