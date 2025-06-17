use crate::errors::KeystoreError;
use dirs::data_dir;
use eth_keystore::{decrypt_key, new as eth_keystore_new};
use lazy_static::lazy_static;
use rand::rngs::OsRng;
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

pub fn create_new_keystore<S>(
    path: Option<&str>,
    name: Option<&str>,
    password: S,
) -> Result<(Vec<u8>, String), KeystoreError>
where
    S: AsRef<[u8]>,
{
    let path = match path {
        Some(p) => Path::new(p),
        None => {
            // check if default path exists or create it
            let p = Path::new(KEYSTORE_DEFAULT_PATH.as_str());
            if !p.exists() {
                fs::create_dir_all(KEYSTORE_DEFAULT_PATH.as_str()).unwrap();
            }
            p
        }
    };
    let mut rng = OsRng;
    Ok(eth_keystore_new(path, &mut rng, password, name).unwrap())
}

pub fn load_keystore<S>(
    path: Option<&str>,
    name: &str,
    password: S,
) -> Result<Vec<u8>, KeystoreError>
where
    S: AsRef<[u8]>,
{
    let path = match path {
        Some(p) => Path::new(p).join(name),

        None => Path::new(KEYSTORE_DEFAULT_PATH.as_str()).join(name),
    };
    Ok(decrypt_key(path, password).unwrap())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    pub fn test_create_and_load_keystore() {
        assert_eq!(
            create_new_keystore(None, Some("Test"), "REX").unwrap().0,
            load_keystore(None, "Test", "REX").unwrap()
        );
    }
}
