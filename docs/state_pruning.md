# State Pruning Guide

As of `v0.21.0` the state pruning feature is available.
This feature allows users to prune the state database to reduce the size of the database and improve performance.

There are two parts of the state pruning feature:

1. Pruning the blocks; and
2. Pruning the state.

**Warning:** If you are pruning a node with a large amount of pre-existing blocks/state, it may take some time for the pruning process to complete.
It may also have a noticeable impact on the node's performance while pruning is in progress i.e. it is possible that your node will fall in-and-out of sync from time to time.
So, it is wise to restore a node from a recent checkpoint, if you want to run a pruned node.

## How to Use It

If you wish to run a pruned node, the easiest way to do it is to:

1. Restore the node from the most recent checkpoint.
   This mitigates the need to migrate any legacy keys.
2. Let the node active-sync and catch up with the head of the chain.
   This is just to ensure that the node is up-to-date.
3. Set the `db.prune_interval` configuration option to a positive integer.
   If the number is too small, you may end up storing too many (redundant) snapshots between compaction runs.
4. Restart the node.
   You can monitor the logs for the "Snapshot:" messages.
5. Recovering the SQL disk space.
   If necessary, schedule and reclaimed SQL disk space by running the `VACUUM` command.

### Configuration

To prune the blocks/state, users can use the `db.prune_interval` configuration option.
If this option is set to a positive integer, the node will retain only the most recent `db.prune_interval` blocks.
Any block older than that will be deleted from the SQL database along with its associated transactions, receipts, etc.
Also, the node will prune the state database to reduce the size of the storage.

> As part of this process, the node will _drop_ the SQL `state_trie` table.
> But, the node does not `VACUUM` to reclaim the space from the SQL database, as this process can take a long time.
> If the SQL disk space needs to be reclaimed, node operators should schedule and manually run the `VACUUM` command on the SQL database.
> This only impacts nodes that have existing state prior to `v0.18.0`.

## How it works

The state pruning feature works by exploiting the RocksDB compaction feature.
Storage will get recovered as part of its normal background compaction operation that happens periodically and incrementally.
In fact, when this feature is first turned on, you may see an initial increase in storage usage.
But over time, the storage usage will decrease after several compaction runs.

We have chosen to implement a feature that is adapted from the [User-defined Time-stamp](https://github.com/facebook/rocksdb/wiki/User-defined-Timestamp) feature of RocksDB.

- When writing data to the trie-storage in RocksDB, each key is tagged with a _timestamp_ suffix that is used to determine the order of the keys.

```
|user-key + tag|seqno|type|
|<-----internal key------>|
```

- When reading trie-storage data from RocksDB, the timestamp is taken into account to ensure that only the most _recent_ value is returned, for a specific key.

  > Instead of using the block height as the timestamp, we use the block view.
  > This is because there can only be one block per view while there could potentially be more than one block per height.
  > This ensures that the timestamp is always monotonically increasing per block.

- When the built-in compaction feature is triggered, any _stale_ keys are removed and the disk space is recovered.
  > By default RocksDB ensures that compaction is triggered at least once every 30-days; but it runs periodically (or when enough data has been written to trigger a compaction).

### Operation

1. At the next epoch, the node increments its internal timestamp _ceiling_, which will result in any new state being tagged with a higher timestamp.
2. The node will trigger a background operation to _snapshot_ all active state that should be retained, by duplicating the entire state-trie with the higher timestamp.
   This operation may take some time to complete, possibly several epochs, and the node will only allow one such operation at a time.
3. After the operation is complete, the node increments its internal timestamp _floor_; and any state with a timestamp below the _floor_ will eventually be compacted away.

### Conditions

The conditions for the _ceiling_ and the _floor_ are that:

- The _ceiling_ is always incremented i.e. new ceiling > old ceiling.
- The _floor_ is always incremented i.e. new floor > old floor.
- The _ceiling_ is always greater than the _floor_ i.e. ceiling > floor.
- The _floor_ always lags the _ceiling_ i.e. floor == old ceiling.

The snapshot operation will only be triggered if the lowest block view is greater than the current _ceiling_.
This condition ensures the safety that, the only states pruned are those that are absolutely no longer needed, since the block no longer exists in the SQL database.
This also means that the node may retain more state than it actually needs.
Considering the amount of state saved through pruning, this bit of extra state is negligible.

### Key Migration

For nodes that disable pruning, the existing keys will be auto-migrated to the new tagged-keys.
This process is done lazily, as trie-nodes are read from the database i.e. when a legacy key is encountered, it is migrated to the new tagged-key and the legacy-key is deleted by compaction.
You can enable pruning at any time without any impact on the auto-migration process.
