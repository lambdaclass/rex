use ethrex_common::{Address, Bytes, U256, types::TxType};
use ethrex_l2_common::calldata::Value;
use ethrex_l2_rpc::signer::{LocalSigner, Signer};
use ethrex_l2_sdk::{build_generic_tx, calldata::encode_calldata, send_generic_transaction};
use ethrex_rpc::{
    EthClient,
    clients::{EthClientError, Overrides},
};
use keccak_hash::{H256, keccak};
use secp256k1::SecretKey;

use crate::l2::constants::{
    EMERGENCY_EXECUTE_SIGNATURE, UPGRADE_RISC0_VERIFICATION_KEY_SIGNATURE,
    UPGRADE_SP1_VERIFICATION_KEY_SIGNATURE, VERIFICATION_KEYS_SIGNATURE,
};

/// Which verifier a verification key belongs to. The ids match
/// `SP1_VERIFIER_ID` and `RISC0_VERIFIER_ID` in `OnChainProposer`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Prover {
    Sp1,
    Risc0,
}

impl Prover {
    pub fn verifier_id(self) -> u8 {
        match self {
            Prover::Sp1 => 1,
            Prover::Risc0 => 2,
        }
    }

    fn upgrade_signature(self) -> &'static str {
        match self {
            Prover::Sp1 => UPGRADE_SP1_VERIFICATION_KEY_SIGNATURE,
            Prover::Risc0 => UPGRADE_RISC0_VERIFICATION_KEY_SIGNATURE,
        }
    }
}

/// The key a batch is committed under: keccak of the git sha the binary reports,
/// hashed as ASCII text.
///
/// It must be the **full** sha, exactly as `ethrex --version` prints it after
/// `HEAD-`. Hashing an abbreviated sha produces a different key, and since
/// `commitBatch` rejects a commit hash it holds no key for, the upgraded
/// sequencer would fail to commit anything with no indication that the sha was
/// the problem.
pub fn commit_hash_from_git_sha(git_sha: &str) -> H256 {
    keccak(git_sha.trim().as_bytes())
}

/// Reads `OnChainProposer.verificationKeys[commit_hash][verifier_id]`.
///
/// A zero result means batches committed under `commit_hash` cannot be
/// committed at all, not merely that they cannot be proved.
pub async fn get_verification_key(
    eth_client: &EthClient,
    on_chain_proposer: Address,
    commit_hash: H256,
    prover: Prover,
) -> Result<H256, EthClientError> {
    let calldata = encode_calldata(
        VERIFICATION_KEYS_SIGNATURE,
        &[
            Value::FixedBytes(commit_hash.as_fixed_bytes().to_vec().into()),
            Value::Uint(U256::from(prover.verifier_id())),
        ],
    )
    .map_err(|error| EthClientError::Custom(error.to_string()))?;

    let raw = eth_client
        .call(on_chain_proposer, calldata.into(), Overrides::default())
        .await?;

    let trimmed = raw.trim_start_matches("0x");
    let bytes = hex::decode(trimmed).map_err(|error| EthClientError::Custom(error.to_string()))?;
    if bytes.len() != 32 {
        return Err(EthClientError::Custom(format!(
            "expected a 32-byte verification key, got {} bytes",
            bytes.len()
        )));
    }
    Ok(H256::from_slice(&bytes))
}

/// Registers `verification_key` against `commit_hash` on the OnChainProposer.
///
/// `upgradeSP1VerificationKey` is `onlyOwner`, and in a deployment with a
/// Timelock that owner is the Timelock itself, so passing `timelock` routes the
/// call through `emergencyExecute` (Security Council, no delay). Calling the
/// OnChainProposer directly from an EOA in that setup reverts with
/// `OwnableUnauthorizedAccount`; leave `timelock` as `None` only when an EOA
/// still owns the contract.
#[allow(clippy::too_many_arguments)]
pub async fn register_verification_key(
    eth_client: &EthClient,
    on_chain_proposer: Address,
    timelock: Option<Address>,
    prover: Prover,
    commit_hash: H256,
    verification_key: H256,
    from: Address,
    from_pk: SecretKey,
) -> Result<H256, EthClientError> {
    let upgrade_calldata = encode_calldata(
        prover.upgrade_signature(),
        &[
            Value::FixedBytes(commit_hash.as_fixed_bytes().to_vec().into()),
            Value::FixedBytes(verification_key.as_fixed_bytes().to_vec().into()),
        ],
    )
    .map_err(|error| EthClientError::Custom(error.to_string()))?;

    let (to, calldata) = match timelock {
        Some(timelock) => {
            let routed = encode_calldata(
                EMERGENCY_EXECUTE_SIGNATURE,
                &[
                    Value::Address(on_chain_proposer),
                    Value::Uint(U256::zero()),
                    Value::Bytes(upgrade_calldata.into()),
                ],
            )
            .map_err(|error| EthClientError::Custom(error.to_string()))?;
            (timelock, routed)
        }
        None => (on_chain_proposer, upgrade_calldata),
    };

    let tx = build_generic_tx(
        eth_client,
        TxType::EIP1559,
        to,
        from,
        Bytes::from(calldata),
        Overrides {
            from: Some(from),
            ..Default::default()
        },
    )
    .await?;

    let signer = Signer::Local(LocalSigner::new(from_pk));
    send_generic_transaction(eth_client, tx, &signer).await
}
