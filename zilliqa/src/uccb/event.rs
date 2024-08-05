use std::collections::HashMap;

use alloy::{
    primitives::{Address, Bytes, Signature, U256},
    signers::local::PrivateKeySigner,
    sol_types::sol,
};
use anyhow::Result;
/*
use ethers::{
    abi::{self, Token},
    signers::LocalWallet,
    types::{Address, Bytes, Signature, H256, U256},
    utils::hash_message,
};
*/
use serde::{Deserialize, Serialize};

//use crate::uccb::contracts::RelayedFilter;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RelayEvent {
    pub source_chain_id: U256,
    pub target_chain_id: U256,
    pub target: Address,
    pub call: Bytes,
    pub gas_limit: U256,
    pub nonce: U256,
}

impl RelayEvent {
    /*
        pub fn from(event: RelayedFilter, source_chain_id: U256) -> Self {
            RelayEvent {
                source_chain_id,
                target_chain_id: event.target_chain_id,
                target: event.target,
                call: event.call,
                gas_limit: event.gas_limit,
                nonce: event.nonce,
            }
        }

        pub fn hash(&self) -> H256 {
            hash_message(abi::encode(&[
                Token::Uint(self.source_chain_id),
                Token::Uint(self.target_chain_id),
                Token::Address(self.target),
                Token::Bytes(self.call.to_vec()),
                Token::Uint(self.gas_limit),
                Token::Uint(self.nonce),
            ]))
        }
        pub fn sign(&self, signer: &PrivateKeySigner) -> Result<Signature> {
            let &credentials = signer.credentials();
    credentials.sign(&)
            let data = self.hash();
            let signature = wallet.sign_hash(data)?;

            Ok(signature)
        }
        */
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct RelayEventSignatures {
    // pub event: Option<RelayEvent>,
    pub dispatched: bool,
    pub signatures: HashMap<Address, Signature>,
}

impl RelayEventSignatures {
    pub fn new(/*event: RelayEvent,*/ address: Address, signature: Signature) -> Self {
        RelayEventSignatures {
            // event: Some(event),
            dispatched: false,
            signatures: HashMap::from([(address, signature)]),
        }
    }
}
