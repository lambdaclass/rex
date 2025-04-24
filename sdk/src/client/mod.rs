pub mod eth;
pub use eth::{EthClient, errors::EthClientError, eth_sender::Overrides};

pub use ethrex_rpc::clients::auth;
