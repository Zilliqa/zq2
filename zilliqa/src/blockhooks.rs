use alloy::primitives::Address;
use anyhow::Result;
use ethabi::{Event, Log, RawLog, Token};
use tracing::{error, warn};

use crate::{
    contracts,
    message::IntershardCall,
    state::contract_addr,
    transaction::{EvmGas, TransactionReceipt},
};

fn filter_receipts(
    receipts: &[TransactionReceipt],
    event: Event,
    emitter: Address,
) -> Result<Vec<Log>> {
    let logs: Result<Vec<_>, _> = receipts
        .iter()
        .flat_map(|receipt| &receipt.logs)
        .filter_map(|log| log.as_evm()) // Only consider EVM logs
        .filter(|log| {
            log.address == emitter
                && ethabi::ethereum_types::H256(log.topics[0].0) == event.signature()
        })
        .map(|log| {
            event
                // parse_log_whole can't be used here because it doesn't seem to work
                // with dynamically-sized types (e.g. `bytes`), throwing a spurious error
                .parse_log(RawLog {
                    topics: log
                        .topics
                        .iter()
                        .map(|t| ethabi::ethereum_types::H256(t.0))
                        .collect(),
                    data: log.data.clone(),
                })
                .map_err(|e| {
                    warn!("Error parsing event log: {e}. The log was: {log:?}");
                    e
                })
        })
        .collect();

    Ok(logs?)
}

pub fn get_launch_shard_messages(receipts: &[TransactionReceipt]) -> Result<Vec<u64>> {
    let shard_logs = filter_receipts(
        receipts,
        contracts::shard_registry::SHARD_ADDED_EVT.clone(),
        contract_addr::SHARD_REGISTRY,
    )?;
    Ok(shard_logs
        .into_iter()
        .filter_map(|log| {
            log.params
                .into_iter()
                .find(|param| param.name == "id")
                .and_then(|param| param.value.into_uint())
                .or_else(|| {
                    warn!("ShardAdded event does not contain an id!");
                    None
                })
                .and_then(|id| u64::try_from(id).ok())
        })
        .collect())
}

pub fn get_link_creation_messages(receipts: &[TransactionReceipt]) -> Result<Vec<(u64, u64)>> {
    let link_logs = filter_receipts(
        receipts,
        contracts::shard_registry::LINK_ADDED_EVT.clone(),
        contract_addr::SHARD_REGISTRY,
    )?;
    // TODO: this is very ugly
    // I wonder if there's a better way to parse events in general
    Ok(link_logs
        .into_iter()
        .filter_map(|log| {
            let Some([from, to]) = <[_; 2]>::try_from(log.params)
                .ok()
                .filter(|[from, to]| from.name == "from" && to.name == "to")
            else {
                warn!("LinkAdded event does not contain expected (from, to) values!");
                return None;
            };
            let (Some(from), Some(to)) = (
                u64::try_from(from.value.into_uint()?).ok(),
                u64::try_from(to.value.into_uint()?).ok(),
            ) else {
                warn!("LinkAdded event from/to is not a uint that fits in a u64!");
                return None;
            };
            Some((from, to))
        })
        .collect())
}

#[inline]
fn parse_intershard_call(values: Vec<Token>) -> Option<(u64, IntershardCall)> {
    let [
        destination_shard,
        source_address,
        no_target,
        target_address,
        source_chain_id,
        bridge_nonce,
        calldata,
        gas_limit,
        gas_price,
    ] = <[Token; 9]>::try_from(values).ok()?;

    Some((
        u64::try_from(destination_shard.into_uint()?).ok()?,
        IntershardCall {
            source_address: Address::new(source_address.into_address()?.0),
            target_address: if no_target.into_bool()? {
                None
            } else {
                Some(Address::new(target_address.into_address()?.0))
            },
            source_chain_id: u64::try_from(source_chain_id.into_uint()?).ok()?,
            bridge_nonce: u64::try_from(bridge_nonce.into_uint()?).ok()?,
            calldata: calldata.into_bytes()?,
            gas_limit: EvmGas(u64::try_from(gas_limit.into_uint()?).ok()?),
            gas_price: u128::try_from(gas_price.into_uint()?).ok()?,
        },
    ))
}

pub fn get_cross_shard_messages(
    receipts: &[TransactionReceipt],
) -> Result<Vec<(u64, IntershardCall)>> {
    let bridge_logs = filter_receipts(
        receipts,
        contracts::intershard_bridge::RELAYED_EVT.clone(),
        contract_addr::INTERSHARD_BRIDGE,
    )?;
    Ok(bridge_logs
        .into_iter()
        .filter_map(|Log { params }| {
            let values = params
                .into_iter()
                .map(|param| param.value)
                .collect::<Vec<_>>();
            // First we type-check the event values for sanity
            if !Token::types_check(
                &values,
                &contracts::intershard_bridge::RELAYED_EVT
                    .clone()
                    .inputs
                    .into_iter()
                    .map(|p| p.kind)
                    .collect::<Vec<_>>(),
            ) {
                warn!("`Relayed` event had unexpected number or type of parameters!");
                return None;
            }
            // Now that they are all known to match expected values, we can make liberal
            // Note that ordering is also important here.
            let Some(call) = parse_intershard_call(values) else {
                error!("IntershardCall event has unexpected or out-of-range values!");
                return None;
            };
            Some(call)
        })
        .collect())
}
