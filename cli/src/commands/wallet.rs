use clap::Subcommand;
use coins_bip32::ecdsa::SigningKey;
use coins_bip32::path::DerivationPath;
use coins_bip39::{English, Mnemonic};
use ethrex_common::{Address, H256};
use ethrex_l2_common::utils::get_address_from_secret_key;
use rex_sdk::utils::to_checksum_address;
use secp256k1::SecretKey;
use std::ops::RangeInclusive;
use std::str::FromStr;

#[derive(Subcommand)]
pub(crate) enum Command {
    #[clap(
        about = "Derive Ethereum accounts from a BIP-39 mnemonic",
        long_about = "Derive Ethereum accounts from a BIP-39 mnemonic using the standard \
                      m/44'/60'/0'/0/{index} path. Useful for recovering keys from Kurtosis \
                      pre-funded accounts, Anvil/Hardhat test mnemonics, or hardware wallets \
                      seeded with a known phrase."
    )]
    Derive {
        #[arg(
            long,
            env = "MNEMONIC",
            help = "BIP-39 mnemonic phrase (12 or 24 words, space-separated). Can also be passed via the MNEMONIC env var."
        )]
        mnemonic: String,
        #[arg(
            long,
            default_value = "0",
            value_parser = parse_index_range,
            help = "Account index or inclusive range, e.g. '0', '0-4'."
        )]
        index: RangeInclusive<u32>,
        #[arg(
            long,
            default_value = "",
            help = "Optional BIP-39 passphrase (empty by default)."
        )]
        passphrase: String,
        #[arg(
            long,
            default_value_t = false,
            help = "Print only comma-separated address,private_key pairs, one per line (machine-friendly)."
        )]
        csv: bool,
    },
}

impl Command {
    pub fn run(self) -> eyre::Result<()> {
        match self {
            Command::Derive {
                mnemonic,
                index,
                passphrase,
                csv,
            } => {
                let mnemonic: Mnemonic<English> =
                    Mnemonic::<English>::new_from_phrase(&mnemonic)
                        .map_err(|e| eyre::eyre!("invalid mnemonic: {e}"))?;

                for i in index {
                    let path = DerivationPath::from_str(&format!("m/44'/60'/0'/0/{i}"))
                        .map_err(|e| eyre::eyre!("invalid derivation path: {e}"))?;
                    let xpriv = mnemonic
                        .derive_key(&path, Some(&passphrase))
                        .map_err(|e| eyre::eyre!("key derivation failed at index {i}: {e}"))?;
                    let signing_key: &SigningKey = xpriv.as_ref();
                    let secret_bytes: [u8; 32] = signing_key.to_bytes().into();
                    let secret = SecretKey::from_slice(&secret_bytes)
                        .map_err(|e| eyre::eyre!("secp256k1 error at index {i}: {e}"))?;
                    let address: Address = get_address_from_secret_key(&secret.secret_bytes())
                        .map_err(|e| eyre::eyre!(e))?;
                    let pk = H256::from(secret_bytes);

                    if csv {
                        println!(
                            "0x{},{:x}",
                            to_checksum_address(&format!("{address:x}")),
                            pk
                        );
                    } else {
                        println!("Index:       {i}");
                        println!(
                            "Address:     0x{}",
                            to_checksum_address(&format!("{address:x}"))
                        );
                        println!("Private Key: {pk:x}");
                        println!();
                    }
                }
                Ok(())
            }
        }
    }
}

fn parse_index_range(s: &str) -> eyre::Result<RangeInclusive<u32>> {
    if let Some((lo, hi)) = s.split_once('-') {
        let lo: u32 = lo
            .parse()
            .map_err(|e| eyre::eyre!("invalid range start '{lo}': {e}"))?;
        let hi: u32 = hi
            .parse()
            .map_err(|e| eyre::eyre!("invalid range end '{hi}': {e}"))?;
        if hi < lo {
            return Err(eyre::eyre!("range end {hi} is less than start {lo}"));
        }
        Ok(lo..=hi)
    } else {
        let idx: u32 = s
            .parse()
            .map_err(|e| eyre::eyre!("invalid index '{s}': {e}"))?;
        Ok(idx..=idx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Standard test mnemonic used by Anvil/Hardhat. Derives a well-known set
    // of addresses — if this test starts failing, the derivation path is wrong.
    const TEST_MNEMONIC: &str = "test test test test test test test test test test test junk";

    #[test]
    fn derives_anvil_account_zero() {
        let mnemonic = Mnemonic::<English>::new_from_phrase(TEST_MNEMONIC).unwrap();
        let path = DerivationPath::from_str("m/44'/60'/0'/0/0").unwrap();
        let key = mnemonic.derive_key(&path, Some("")).unwrap();
        let signing_key: &SigningKey = key.as_ref();
        let secret_bytes: [u8; 32] = signing_key.to_bytes().into();
        let secret = SecretKey::from_slice(&secret_bytes).unwrap();
        let addr = get_address_from_secret_key(&secret.secret_bytes()).unwrap();
        assert_eq!(
            format!("0x{addr:x}"),
            "0xf39fd6e51aad88f6f4ce6ab8827279cfffb92266"
        );
    }

    #[test]
    fn parses_index_range() {
        assert_eq!(parse_index_range("0").unwrap(), 0..=0);
        assert_eq!(parse_index_range("2-5").unwrap(), 2..=5);
        assert!(parse_index_range("5-2").is_err());
        assert!(parse_index_range("abc").is_err());
    }
}
