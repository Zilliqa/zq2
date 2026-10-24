use std::num::NonZeroU128;

use alloy::primitives::{Address, U256};
use anyhow::Result;
use ethabi::Token;
use libp2p::PeerId;
use tracing::debug;

use crate::{
    cfg::Fork,
    contracts,
    crypto::NodePublicKey,
    error::ensure_success,
    message::BlockHeader,
    state::{State, contract_addr},
};

impl State {
    pub fn deposit_contract_version(&self, current_block: BlockHeader) -> Result<u128> {
        let result = self.call_contract(
            Address::ZERO,
            Some(contract_addr::DEPOSIT_PROXY),
            contracts::deposit::VERSION.encode_input(&[]).unwrap(),
            0,
            current_block,
        )?;
        contracts::deposit::VERSION.decode_output(&ensure_success(result)?)?[0]
            .clone()
            .into_uint()
            .map_or(Ok(0), |v| Ok(v.as_u128()))
    }

    pub fn leader(
        &self,
        view: u64,
        current_block: BlockHeader,
        fork: &Fork,
    ) -> Result<NodePublicKey> {
        let data = {
            if fork.randao_support {
                contracts::deposit::LEADER_AT_VIEW_WITH_RANDAO
                    .encode_input(&[Token::Uint(view.into())])?
            } else {
                contracts::deposit::LEADER_AT_VIEW.encode_input(&[Token::Uint(view.into())])?
            }
        };

        let result = self.call_contract(
            Address::ZERO,
            Some(contract_addr::DEPOSIT_PROXY),
            data,
            0,
            current_block,
        )?;
        let leader = ensure_success(result)?;

        NodePublicKey::from_bytes(
            &contracts::deposit::LEADER_AT_VIEW.decode_output(&leader)?[0]
                .clone()
                .into_bytes()
                .unwrap(),
        )
    }

    pub fn get_stakers(&self, current_block: BlockHeader) -> Result<Vec<NodePublicKey>> {
        let data: Vec<u8> = contracts::deposit::GET_STAKERS.encode_input(&[])?;

        let result = self.call_contract(
            Address::ZERO,
            Some(contract_addr::DEPOSIT_PROXY),
            data,
            0,
            current_block,
        )?;
        let stakers = ensure_success(result)?;

        let stakers = contracts::deposit::GET_STAKERS
            .decode_output(&stakers)
            .unwrap()[0]
            .clone()
            .into_array()
            .unwrap();

        stakers
            .into_iter()
            .map(|k| NodePublicKey::from_bytes(&k.into_bytes().unwrap()))
            .collect()
    }

    pub fn committee(&self) -> Result<()> {
        let data = contracts::deposit::COMMITTEE.encode_input(&[])?;

        let result = self.call_contract(
            Address::ZERO,
            Some(contract_addr::DEPOSIT_PROXY),
            data,
            0,
            BlockHeader::default(),
        )?;
        let committee = ensure_success(result)?;
        let committee = contracts::deposit::COMMITTEE.decode_output(&committee)?;
        debug!("committee: {committee:?}");

        Ok(())
    }

    pub fn get_stake(
        &self,
        public_key: NodePublicKey,
        current_block: BlockHeader,
    ) -> Result<Option<NonZeroU128>> {
        let data =
            contracts::deposit::GET_STAKE.encode_input(&[Token::Bytes(public_key.as_bytes())])?;

        let result = self.call_contract(
            Address::ZERO,
            Some(contract_addr::DEPOSIT_PROXY),
            data,
            0,
            current_block,
        )?;
        let stake = ensure_success(result)?;

        let stake = NonZeroU128::new(U256::from_be_slice(&stake).to());

        Ok(stake)
    }

    pub fn get_reward_address(&self, public_key: NodePublicKey) -> Result<Option<Address>> {
        let data = contracts::deposit::GET_REWARD_ADDRESS
            .encode_input(&[Token::Bytes(public_key.as_bytes())])?;

        let result = self.call_contract(
            Address::ZERO,
            Some(contract_addr::DEPOSIT_PROXY),
            data,
            0,
            BlockHeader::default(),
        )?;
        let return_value = ensure_success(result)?;

        let addr = contracts::deposit::GET_REWARD_ADDRESS.decode_output(&return_value)?[0]
            .clone()
            .into_address()
            .unwrap();
        let addr = Address::new(addr.0);

        Ok((!addr.is_zero()).then_some(addr))
    }

    pub fn get_peer_id(&self, public_key: NodePublicKey) -> Result<Option<PeerId>> {
        let data =
            contracts::deposit::GET_PEER_ID.encode_input(&[Token::Bytes(public_key.as_bytes())])?;

        let result = self.call_contract(
            Address::ZERO,
            Some(contract_addr::DEPOSIT_PROXY),
            data,
            0,
            BlockHeader::default(),
        )?;
        let return_value = ensure_success(result)?;

        let data = contracts::deposit::GET_PEER_ID.decode_output(&return_value)?[0]
            .clone()
            .into_bytes()
            .unwrap();

        Ok(Some(PeerId::from_bytes(&data)?))
    }
}
