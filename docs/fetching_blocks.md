# ZQ2 block fetching

Zilliqa 2 nodes will, in general, start from either genesis or a checkpoint.

These will both be behind the current head of the blockchain, and the node will thus want to catch up. To do so, it will attempt to request blocks from other nodes.

This operation is complicated because:

- Other nodes in the network may not be reliable - fail to reply, lie, or attempt to stop the node syncing.
- Other nodes will, in general, not have all the blocks themselves - they may be syncing, or have pruned some blocks for resource management reasons.
- We want to avoid overloading a single node with too much work.
- The syncing node wants to catch up quickly.

As a result, the code for fetching blocks to complete our view of the chain is somewhat complex.

# Active Sync

Active-sync is the process of catching up to the head of the blockchain.
This process is designed to be aggressive i.e. it tries to catch up to the head as fast as possible.

This process consists of 3 main phases:
- Phase 1, downloading headers;
- Phase 2, downloading blocks; and
- Phase 3, finishing up.

## Phase 1

During this phase, the node will download headers, from segments of the chain, in descending order from the latest block seen. This way, it only downloads valid headers by simply following the chain of parent hashes. 

Since this phase is I/O bound, the node fires multiple concurrent requests for different segments, to multiple peers. If it encounters any networking issues, it will resend the request for that segment to a subsequent peer. It checks and discards responses that are not linked by the chain of hashes and requests the same segment from a subsequent peer.

It does this until it downloads headers that link up to its own internal history, checkpoint, or genesis.

## Phase 2

During this phase, the node will download blocks in ascending order starting from the block that it has in its history. It sends the request to the same peer that provided the response in Phase 1.

Since this phase is CPU bound, the node requests one segment of the chain at a time. In order to avoid overflowing memory, it buffers only about 1,000 blocks at a time. If it encounters any networking issues, it will discard the response and repeat Phase 1 with the troublesome segment.

It does this until it has successfully downloaded all the blocks that it is aware of. This will bring it close to the head of the chain.

## Phase 3

Phase 1 and 2 may be repeated multiple times, which will bring the node close to the head of the chain but never quite reaching it. While Phase 1 and 2 are running, the node is also buffering the latest Proposals that it receives.

If the blocks that it has buffered, link up to its history, it will inject those blocks from its internal buffer. This will allow it to catch up to the head of the chain.

# Passive Sync

Passive-sync is the process of filling out the rest of the chain. This process is designed to be non-aggressive as it happens in the background.

A node that is started from a checkpoint, will run active-sync to catch up to the head. Then, it may run passive-sync to fill out the rest of the chain history going backwards.

This process consists of 2 main phases:
- Phase 4, downloading headers; and
- Phase 5, downloading blocks;

## Phase 4

This phase is similar to Phase 1 in terms of functionality. The main difference is that it starts not from the latest known block but from its oldest block in history; and it immediately switches to Phase 5 upon receiving a successful response (that links up from the starting block) for a single chain segment.

## Phase 5

This phase is similar to Phase 2 in terms of functionality. The main difference is that it does not execute the blocks but merely stores them in its database; and it then repeats Phase 4 if there is nothing else to do (as it is supposed to be running in the background).