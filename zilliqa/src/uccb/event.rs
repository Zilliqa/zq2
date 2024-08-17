use std::collections::HashMap;

use alloy::{
    dyn_abi::DecodedEvent,
    primitives::{eip191_hash_message, Address, Bytes, Signature, B256, U256},
    signers::{
        local::{LocalSigner, PrivateKeySigner},
        Signer,
    },
    sol_types::{sol_data, SolValue},
};
use anyhow::{anyhow, Result};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RelayedEvent {
    pub source_chain_id: U256,
    pub target_chain_id: U256,
    pub target: Address,
    pub call: Bytes,
    pub gas_limit: U256,
    pub nonce: U256,
}

impl RelayedEvent {
    pub fn try_from(event: DecodedEvent, source_chain_id: U256) -> Result<Self> {
        let indexed = event.indexed;
        let values = event.body;
        if indexed.len() != 1 || values.len() != 4 {
            return Err(anyhow!("Incorrect number of values"));
        }

        let target = values[0].as_address().unwrap();
        let target_chain_id = indexed[0].as_uint().unwrap().0;
        let gas_limit = values[2].as_uint().unwrap().0;
        let nonce = values[3].as_uint().unwrap().0;
        let call = Bytes::from(values[1].as_bytes().unwrap().to_vec());

        Ok(Self {
            source_chain_id,
            target_chain_id,
            target,
            call,
            gas_limit,
            nonce,
        })
    }

    pub fn hash(&self) -> B256 {
        eip191_hash_message(
            &(
                self.source_chain_id, //: U256,
                self.target_chain_id, //: U256,
                self.target,          //: Address,
                self.call.to_vec(),   //: Bytes,
                self.gas_limit,       //: U256,
                self.nonce,           //: U256,
            )
                .abi_encode(),
        )
    }

    pub async fn sign(&self, signer: &PrivateKeySigner) -> Result<Signature> {
        let data = self.hash();
        let signature = signer.sign_message(data.as_slice()).await?;

        Ok(signature)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct RelayEventSignatures {
    pub event: Option<RelayedEvent>,
    pub dispatched: bool,
    pub signatures: HashMap<Address, Signature>,
}

impl RelayEventSignatures {
    pub fn new(event: RelayedEvent, address: Address, signature: Signature) -> Self {
        RelayEventSignatures {
            event: Some(event),
            dispatched: false,
            signatures: HashMap::from([(address, signature)]),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DispatchedEvent {
    pub source_chain_id: U256,
    pub target: Address,
    pub success: bool,
    pub response: Bytes,
    pub nonce: U256,
}

impl DispatchedEvent {
    pub fn try_from(event: DecodedEvent, source_chain_id: U256) -> Result<Self> {
        let indexed = event.indexed;
        let values = event.body;
        if indexed.len() != 3 || values.len() != 2 {
            return Err(anyhow!("Incorrect number of values"));
        }

        let source_chain_id = indexed[0].as_uint().unwrap().0;
        let target = indexed[1].as_address().unwrap();
        let success = values[0].as_bool().unwrap();
        let response = Bytes::from(values[1].as_bytes().unwrap().to_vec());
        let nonce = indexed[2].as_uint().unwrap().0;

        Ok(Self {
            source_chain_id,
            target,
            success,
            response,
            nonce,
        })
    }
}
