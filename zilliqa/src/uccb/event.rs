use std::collections::HashMap;

use alloy::{
    dyn_abi::DecodedEvent,
    primitives::{eip191_hash_message, Address, Bytes, Signature, B256, U256},
    signers::{
        local::{LocalSigner, PrivateKeySigner},
        Signer, SignerSync,
    },
};
use anyhow::{anyhow, Result};
use libp2p::core::DecodeError;
use serde::{Deserialize, Serialize};

/*
#[derive(Debug)]
enum EventConversionError {
    IncorrectValueCount,
}
*/

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
        eip191_hash_message(&self)
    }

    pub async fn sign(&self, signer: &PrivateKeySigner) -> Result<Signature> {
        let data = self.hash();
        let signature = signer.sign_message(data.as_slice()).await?;

        Ok(signature)
    }
}

impl core::convert::AsRef<[u8]> for RelayEvent {
    fn as_ref(&self) -> &[u8] {
        unsafe {
            std::slice::from_raw_parts(
                self as *const RelayEvent as *const u8,
                std::mem::size_of::<RelayEvent>(),
            )
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct RelayEventSignatures {
    pub event: Option<RelayEvent>,
    pub dispatched: bool,
    pub signatures: HashMap<Address, Signature>,
}

impl RelayEventSignatures {
    pub fn new(event: RelayEvent, address: Address, signature: Signature) -> Self {
        RelayEventSignatures {
            event: Some(event),
            dispatched: false,
            signatures: HashMap::from([(address, signature)]),
        }
    }
}
