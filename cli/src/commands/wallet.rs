use clap::Subcommand;
use coins_bip32::ecdsa::SigningKey;
use coins_bip32::path::DerivationPath;
use coins_bip39::{English, Mnemonic};
use ethrex_common::{Address, H256};
use ethrex_l2_common::utils::get_address_from_secret_key;
use rex_sdk::utils::to_checksum_address;
use secp256k1::SecretKey;
use std::fs::OpenOptions;
use std::io::Write;
use std::ops::RangeInclusive;
use std::path::PathBuf;
use std::str::FromStr;

#[derive(Subcommand)]
pub(crate) enum Command {
    #[clap(
        about = "Derive Ethereum accounts from a BIP-39 mnemonic (writes keys to a file)",
        long_about = "Derive Ethereum accounts from a BIP-39 mnemonic using the standard \
                      m/44'/60'/0'/0/{index} path. Keys are written to the file given by \
                      --output (never stdout) with mode 0600 on Unix. stdout only shows the \
                      derived addresses and the output path, so pasting a terminal log never \
                      leaks secrets. Read the file back with `cat` when you need the keys."
    )]
    Derive {
        #[arg(
            long,
            env = "MNEMONIC",
            help = "BIP-39 mnemonic phrase (12 or 24 words, space-separated). Also read from the MNEMONIC env var."
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
            short = 'o',
            long = "output",
            help = "Path to write derived keys to. Created with mode 0600 on Unix. Use --force to overwrite an existing file."
        )]
        output: PathBuf,
        #[arg(
            long,
            default_value_t = false,
            help = "Overwrite the output file if it already exists."
        )]
        force: bool,
    },
}

struct DerivedKey {
    index: u32,
    address: Address,
    private_key: H256,
}

impl Command {
    pub fn run(self) -> eyre::Result<()> {
        match self {
            Command::Derive {
                mnemonic,
                index,
                passphrase,
                output,
                force,
            } => {
                let mnemonic: Mnemonic<English> =
                    Mnemonic::<English>::new_from_phrase(&mnemonic)
                        .map_err(|e| eyre::eyre!("invalid mnemonic: {e}"))?;

                let mut keys: Vec<DerivedKey> = Vec::new();
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
                    let address = get_address_from_secret_key(&secret.secret_bytes())
                        .map_err(|e| eyre::eyre!(e))?;
                    keys.push(DerivedKey {
                        index: i,
                        address,
                        private_key: H256::from(secret_bytes),
                    });
                }

                write_keys_file(&output, &keys, force)?;

                println!("Wrote {} key(s) to {}", keys.len(), output.display());
                for k in &keys {
                    println!(
                        "  index {:>3}  0x{}",
                        k.index,
                        to_checksum_address(&format!("{:x}", k.address))
                    );
                }
                Ok(())
            }
        }
    }
}

fn write_keys_file(path: &std::path::Path, keys: &[DerivedKey], force: bool) -> eyre::Result<()> {
    let mut opts = OpenOptions::new();
    opts.write(true);
    if force {
        opts.create(true).truncate(true);
    } else {
        opts.create_new(true);
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }

    let mut file = opts.open(path).map_err(|e| {
        if e.kind() == std::io::ErrorKind::AlreadyExists {
            eyre::eyre!(
                "{} already exists; pass --force to overwrite",
                path.display()
            )
        } else {
            eyre::eyre!("failed to open {}: {e}", path.display())
        }
    })?;

    // Belt-and-braces: also set mode after open in case the file existed
    // under --force (OpenOptions::mode only applies on creation).
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perm = file.metadata()?.permissions();
        perm.set_mode(0o600);
        file.set_permissions(perm)?;
    }

    writeln!(
        file,
        "# rex wallet derive — {} key(s), m/44'/60'/0'/0/{{index}}",
        keys.len()
    )?;
    for k in keys {
        writeln!(file)?;
        writeln!(file, "Index:       {}", k.index)?;
        writeln!(
            file,
            "Address:     0x{}",
            to_checksum_address(&format!("{:x}", k.address))
        )?;
        writeln!(file, "Private Key: {:x}", k.private_key)?;
    }
    file.sync_all()?;
    Ok(())
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

    #[test]
    fn write_keys_file_creates_file_with_expected_content() {
        let tmp = std::env::temp_dir().join(format!("rex-wallet-test-{}.txt", std::process::id()));
        let _ = std::fs::remove_file(&tmp);

        let keys = vec![DerivedKey {
            index: 0,
            address: Address::from_low_u64_be(0xc0ffee),
            private_key: H256::from_low_u64_be(0x1234),
        }];
        write_keys_file(&tmp, &keys, false).unwrap();

        let contents = std::fs::read_to_string(&tmp).unwrap();
        assert!(contents.contains("Index:       0"));
        assert!(contents.contains("Private Key:"));
        assert!(contents.contains("0x"));

        // Second write without --force should fail.
        let err = write_keys_file(&tmp, &keys, false).unwrap_err();
        assert!(format!("{err}").contains("already exists"));

        // With --force it should overwrite.
        write_keys_file(&tmp, &keys, true).unwrap();

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&tmp).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o600, "file must be 0600");
        }

        std::fs::remove_file(&tmp).ok();
    }
}
