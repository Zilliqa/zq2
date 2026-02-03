pub mod api;
mod aux;
mod blockhooks;
pub mod cfg;
pub mod checkpoint;
pub mod consensus;
pub mod constants;
pub mod contracts;
pub mod credits;
pub mod crypto;
mod data_access;
pub mod db;
mod error;
mod evm;
pub mod exec;
pub mod inspector;
pub mod message;
pub mod node;
pub mod node_launcher;
pub mod p2p_node;
mod pool;
pub mod precompiles;
pub mod range_map;
pub mod schnorr;
pub mod scilla;
mod scilla_proto;
pub mod serde_util;
pub mod state;
pub mod static_hardfork_data;
pub mod sync;
pub mod test_util;
pub mod time;
pub mod transaction;
pub mod trie_storage;
pub mod zq1_proto;

pub fn available_threads() -> usize {
    std::thread::available_parallelism().unwrap().get()
}
