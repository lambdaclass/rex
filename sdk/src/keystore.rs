use crate::errors::KeystoreError;
use dirs::data_dir;
use eth_keystore::{decrypt_key, new as eth_keystore_new};
use lazy_static::lazy_static;
use rand::rngs::OsRng;
use secp256k1::SecretKey;
use std::fs;
use std::path::Path;

lazy_static! {
    pub static ref KEYSTORE_DEFAULT_PATH: String = {
        let data_dir = data_dir().expect("Failed to get base directories");
        data_dir
            .join("rex/keystores/")
            .to_str()
            .expect("Failed to convert path to string")
            .to_owned()
    };
}

/// creates a new keystore in the given path and name using the password
/// if no path is provided, uses KEYSTORE_DEFAULT_PATH
/// if no name is provided, generates a random one
/// returns the SecretKey generated a the UUID of the filesystem
pub fn create_new_keystore<S>(
    path: Option<&str>,
    name: Option<&str>,
    password: S,
) -> Result<(SecretKey, String), KeystoreError>
where
    S: AsRef<[u8]>,
{
    let path = match path {
        Some(p) => Path::new(p),
        None => {
            // check if default path exists or create it
            let p = Path::new(KEYSTORE_DEFAULT_PATH.as_str());
            if !p.exists() {
                fs::create_dir_all(KEYSTORE_DEFAULT_PATH.as_str())
                    .map_err(|e| KeystoreError::ErrorCreatingDefaultDir(e.to_string()))?;
            }
            p
        }
    };
    let mut rng = OsRng;
    let (key_vec, uuid) = eth_keystore_new(path, &mut rng, password, name)
        .map_err(|e| KeystoreError::ErrorCreatingKeystore(e.to_string()))?;
    let secret_key = SecretKey::from_slice(&key_vec)
        .map_err(|e| KeystoreError::ErrorCreatingSecretKey(e.to_string()))?;
    Ok((secret_key, uuid))
}

/// loads the SecretKey from a given Keystore
/// if path is not provided, uses KEYSTORE_DEFAULT_PATH
/// returns the SecretKey loaded
pub fn load_keystore<S>(
    path: Option<&str>,
    name: &str,
    password: S,
) -> Result<SecretKey, KeystoreError>
where
    S: AsRef<[u8]>,
{
    let path = match path {
        Some(p) => Path::new(p).join(name),

        None => Path::new(KEYSTORE_DEFAULT_PATH.as_str()).join(name),
    };
    let key_vec = decrypt_key(path, password)
        .map_err(|e| KeystoreError::ErrorOpeningKeystore(e.to_string()))?;
    let secret_key = SecretKey::from_slice(&key_vec)
        .map_err(|e| KeystoreError::ErrorCreatingSecretKey(e.to_string()))?;
    Ok(secret_key)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    pub fn test_create_and_load_keystore() {
        assert_eq!(
            create_new_keystore(None, Some("RexTest"), "LambdaClass")
                .unwrap()
                .0,
            load_keystore(None, "RexTest", "LambdaClass").unwrap()
        );
    }
}
