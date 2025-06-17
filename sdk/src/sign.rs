use ethrex_common::H256;
use secp256k1::SecretKey;

pub fn sign_hash(hash: H256, private_key: SecretKey) -> Vec<u8> {
    let signed_msg = secp256k1::SECP256K1.sign_ecdsa_recoverable(
        &secp256k1::Message::from_digest(*hash.as_fixed_bytes()),
        &private_key,
    );
    let (msg_signature_recovery_id, msg_signature) = signed_msg.serialize_compact();

    let msg_signature_recovery_id = msg_signature_recovery_id.to_i32() + 27;

    [&msg_signature[..], &[msg_signature_recovery_id as u8]].concat()
}
