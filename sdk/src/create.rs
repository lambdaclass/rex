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
