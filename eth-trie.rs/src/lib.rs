mod nibbles;
mod node;
mod tests;

mod db;
mod errors;
mod trie;

pub use db::{DB, MemoryDB};
pub use errors::{MemDBError, TrieError};
pub use trie::{EthTrie, Trie};

#[doc = include_str!("../README.md")]
#[cfg(doctest)]
pub struct ReadmeDoctests;
