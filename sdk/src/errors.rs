use crate::client::EthClientError;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error(transparent)]
    EthClientError(#[from] EthClientError),
}

#[derive(Debug, thiserror::Error)]
pub enum KeystoreError {
    #[error("Error sending request")]
    Err,
}
