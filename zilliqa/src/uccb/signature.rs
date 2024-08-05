use std::collections::HashMap;

use alloy::primitives::{Address, Bytes, Signature};

pub trait SignatureTracker {
    fn add_signature(&mut self, address: Address, signature: Signature) -> Option<Signature>;

    fn into_ordered_signatures(self) -> Vec<Bytes>;
}

impl SignatureTracker for HashMap<Address, Signature> {
    fn add_signature(&mut self, address: Address, signature: Signature) -> Option<Signature> {
        self.insert(address, signature)
    }

    fn into_ordered_signatures(self) -> Vec<Bytes> {
        let mut list = self.into_iter().collect::<Vec<(Address, Signature)>>();
        list.sort_by_cached_key(|(address, _)| *address);
        list.into_iter()
            .map(|(_, signature)| Bytes::from(signature.as_bytes().to_vec()))
            .collect()
    }
}
