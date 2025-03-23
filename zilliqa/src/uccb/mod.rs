// uccb: the driver for a universal bridge.
// This is styled in the same way as the node code for zq2 itself so as to (hopefully!) make it somewhat familiar.
// Fundamentally:
//
//  - Each client follows a chain (or shard) via a reference to a zq2 node.
//  - It also follows a number of other chains; currently these are external blockchains only but in future they will also (hopefully) be shards.
//  - Each client takes every legitimate event it sees, signs it and broadcasts it to all other uccb nodes.
//  - Each client maintains a cache of all the signatures it has received (within reason .. )
//  - If it is the leader, it will attempt to submit all valid txns. If it thinks it should have a signature that it doesn't have, it will attempt to rerequest it.
//
// @todo if we're asked to scan a block we don't have, we will need to go find it - we don't do this yet.
// @todo we make blocking API calls to foreign blockchains - making these nonblocking (ie. processing our own messages between them) will be "challenging".

pub mod contracts;
pub mod crypto;
pub mod external_network;
pub mod launcher;
pub mod message;
pub mod node;
pub mod provider;
pub mod scan;
pub mod signatures;
