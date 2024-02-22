use anyhow::Result;
use ethabi::{Event, Log, RawLog, Token};
use tracing::warn;

use crate::{
    contracts,
    message::IntershardCall,
    state::{contract_addr, Address},
    transaction::TransactionReceipt,
};

fn filter_receipts(
    receipts: &[TransactionReceipt],
    event: Event,
    emitter: Address,
) -> Result<Vec<Log>> {
    let logs: Result<Vec<_>, _> = receipts
        .iter()
        .flat_map(|receipt| &receipt.logs)
        .filter(|log| log.address == emitter && log.topics[0] == event.signature())
        .map(|log| {
            event
                // parse_log_whole can't be used here because it doesn't seem to work
                // with dynamically-sized types (e.g. `bytes`), throwing a spurious error
                .parse_log(RawLog {
                    topics: log.topics.clone(),
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
                .map_or_else(
                    || {
                        warn!("ShardAdded event does not contain an id!");
                        None
                    },
                    |uint| Some(uint.as_u64()),
                )
        })
        .collect())
}

pub fn get_link_creation_messages(
    receipts: &[TransactionReceipt],
    our_shard_id: u64,
) -> Result<Vec<u64>> {
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
            let (names, mut values): (Vec<_>, Vec<_>) = log
                .params
                .into_iter()
                .map(|param| (param.name, param.value))
                .unzip();
            if names != ["from", "to"] {
                warn!("LinkAdded event does not contain expected (from, to) values!");
                None
            } else if values
                .pop()
                .and_then(|to| to.into_uint())
                .is_some_and(|to| to.as_u64() == our_shard_id)
            {
                values
                    .pop()
                    .and_then(|from| from.into_uint())
                    .map(|from| from.as_u64())
            } else {
                None
            }
        })
        .collect())
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
            // use of `unwrap()`.
            // Note that ordering is also important here.
            let mut values = values.into_iter();
            let destination_shard = values.next().unwrap().into_uint().unwrap().as_u64();
            Some((
                destination_shard,
                IntershardCall {
                    source_address: values.next().unwrap().into_address().unwrap(),
                    target_address: if values.next().unwrap().into_bool().unwrap() {
                        values.next();
                        None
                    } else {
                        Some(values.next().unwrap().into_address().unwrap())
                    },
                    source_chain_id: values.next().unwrap().into_uint().unwrap().as_u64(),
                    bridge_nonce: values.next().unwrap().into_uint().unwrap().as_u64(),
                    calldata: values.next().unwrap().into_bytes().unwrap(),
                    gas_limit: values.next().unwrap().into_uint().unwrap().as_u64(),
                    gas_price: values.next().unwrap().into_uint().unwrap().as_u128(),
                },
            ))
        })
        .collect())
}
