use crate::client::EthClientError;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error(transparent)]
    EthClientError(#[from] EthClientError),
}

#[derive(Debug, thiserror::Error)]
pub enum KeystoreError {
    #[error("Error creating default dir: {0}")]
    ErrorCreatingDefaultDir(String),
    #[error("Error creating keystore: {0}")]
    ErrorCreatingKeystore(String),
    #[error("Error creating secret key: {0}")]
    ErrorCreatingSecretKey(String),
    #[error("Error opening keystore: {0}")]
    ErrorOpeningKeystore(String),
}
