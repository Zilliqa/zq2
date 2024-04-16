use jsonrpsee::{server::IdProvider, types::SubscriptionId};

use super::to_hex::ToHex;

#[derive(Debug)]
pub struct EthIdProvider;

impl IdProvider for EthIdProvider {
    fn next_id(&self) -> SubscriptionId<'static> {
        rand::random::<u64>().to_hex().into()
    }
}
