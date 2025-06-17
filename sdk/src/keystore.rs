use crate::errors::KeystoreError;
use dirs::data_dir;
use eth_keystore::{decrypt_key, new as eth_keystore_new};
use rand::rngs::OsRng;
use secp256k1::SecretKey;
use std::fs;
use std::path::Path;

fn get_keystore_default_path() -> String {
    data_dir()
        .expect("Failed to get base directories")
        .join("rex/keystores/")
        .to_str()
        .expect("Failed to convert path to string")
        .to_owned()
}

/// Creates a new keystore in the given path and name using the password.
/// If no path is provided, uses keystore_default_path.
/// If no name is provided, generates a random one.
/// Returns the SecretKey and the UUID of the keystore file.
pub fn create_new_keystore<S>(
    path: Option<&str>,
    name: Option<&str>,
    password: S,
) -> Result<(SecretKey, String), KeystoreError>
where
    S: AsRef<[u8]>,
{
    let keystore_default_path = get_keystore_default_path();
    let path = match path {
        Some(p) => Path::new(p),
        None => {
            // check if default path exists or create it
            let p = Path::new(keystore_default_path.as_str());
            if !p.exists() {
                fs::create_dir_all(keystore_default_path.as_str())
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

/// Loads the SecretKey from a given Keystore.
/// If path is not provided, uses KEYSTORE_DEFAULT_PATH.
/// Returns the SecretKey loaded.
pub fn load_keystore_from_path<S>(
    path: Option<&str>,
    name: &str,
    password: S,
) -> Result<SecretKey, KeystoreError>
where
    S: AsRef<[u8]>,
{
    let keystore_default_path = get_keystore_default_path();
    let path = path
        .map_or(Path::new(keystore_default_path.as_str()), Path::new)
        .join(name);

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
            load_keystore_from_path(None, "RexTest", "LambdaClass").unwrap()
        );
    }
}
