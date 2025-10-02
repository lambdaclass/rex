use ethrex_common::{Address, Bytes, H256};
use keccak_hash::keccak;
use secp256k1::Error;
use secp256k1::SecretKey;

/// This function receives a hash and a SecretKey and signs it using secp256k1.
pub fn sign_hash(hash: H256, private_key: SecretKey) -> Vec<u8> {
    let signed_msg = secp256k1::SECP256K1.sign_ecdsa_recoverable(
        &secp256k1::Message::from_digest(*hash.as_fixed_bytes()),
        &private_key,
    );
    let (msg_signature_recovery_id, msg_signature) = signed_msg.serialize_compact();

    let msg_signature_recovery_id = i32::from(msg_signature_recovery_id) + 27;

    [&msg_signature[..], &[msg_signature_recovery_id as u8]].concat()
}

/// This function takes signatures that are computed as a 0x45 signature, as described in EIP-191 (https://eips.ethereum.org/EIPS/eip-191),
/// then it has an extra byte concatenated at the end, which is a scalar value added to the signatures parity,
/// as described in the Yellow Paper Section 4.2 in the specification of a transaction's w field. (https://ethereum.github.io/yellowpaper/paper.pdf).
pub fn get_address_from_message_and_signature(
    message: Bytes,
    signature: Bytes,
) -> Result<Address, Error> {
    let raw_recovery_id = if signature[64] >= 27 {
        signature[64] - 27
    } else {
        signature[64]
    };

    let recovery_id = secp256k1::ecdsa::RecoveryId::try_from(raw_recovery_id as i32)?;

    let signature =
        secp256k1::ecdsa::RecoverableSignature::from_compact(&signature[..64], recovery_id)?;

    let payload = [
        b"\x19Ethereum Signed Message:\n",
        message.len().to_string().as_bytes(),
        message.as_ref(),
    ]
    .concat();

    let signer_public_key = signature.recover(&secp256k1::Message::from_digest(
        *keccak(payload).as_fixed_bytes(),
    ))?;

    Ok(Address::from_slice(
        &keccak(&signer_public_key.serialize_uncompressed()[1..])[12..],
    ))
}
