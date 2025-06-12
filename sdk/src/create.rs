use ethrex_common::Address;
use ethrex_rlp::encode::RLPEncode;
use keccak_hash::keccak;

/// address = keccak256(rlp([sender_address,sender_nonce]))[12:]
pub fn compute_create_address(sender_address: Address, sender_nonce: u64) -> Address {
    let mut encoded = Vec::new();
    (sender_address, sender_nonce).encode(&mut encoded);
    let keccak_bytes = keccak(encoded).0;
    Address::from_slice(&keccak_bytes[12..])
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
