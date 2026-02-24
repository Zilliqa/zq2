# State Pruning Guide

As of `v0.21.0` the state pruning feature is available.
This feature allows users to prune the state database to reduce the size of the database and improve performance.

There are two parts of the state pruning feature:
1. Pruning the blocks; and
2. Pruning the state.

## How to Use It

If you wish to run a pruned node, the easiest way to do it is to:
1. Restore the node from the most recent checkpoint.
This mitigates the need to migrate any legacy keys.
Since you're going to prune anyway, the older blocks/state are unnecessary overhead.
2. Let the node active-sync and catch up with the head of the chain.
This is just to ensure that the node is up-to-date.
3. Set the `sync.prune_interval` configuration option to a positive integer.
If the number is too small, you may end up storing too many snapshots between compaction runs.
A good number is about a day's worth of blocks/state.
4. Restart the node.
You can monitor the logs for the "Snapshot:" messages.

### Configuration

To prune the blocks/state, users can use the `sync.prune_interval` configuration option.
If this option is set to a positive integer, the node will retain only the most recent `sync.prune_interval` blocks.
Any block older than that will be deleted from the SQL database.
Also, the node will prune the state database to reduce the size of the storage.

As part of this process, the node will *drop* the SQL `state_trie` table.
This only impacts nodes that have existing state prior to `v0.18.0`.
But, the node does not `VACUUM` to reclaim the space from the SQL database, as this process can take a long time.
If the SQL disk space needs to be reclaimed, node operators should schedule and manually run the `VACUUM` command on the SQL database.

## How it works

The state pruning feature works by exploiting the RocksDB compaction feature.
Storage will get recovered as part of its normal background compaction operation that happens periodically and incrementally.
In fact, when it is first turned on, you may see an initial increase in storage usage.
But over time, the storage usage will decrease after several compaction runs.

We have chosen to implement a feature that is adapted from the [User-defined Time-stamp](https://github.com/facebook/rocksdb/wiki/User-defined-Timestamp) feature of RocksDB.

- When writing data to the trie-storage in RocksDB, each key is tagged with a *timestamp* suffix that is used to determine the order of the keys.
```
|user-key + tag|seqno|type|
|<-----internal key------>|
```

- When reading trie-storage data from RocksDB, the timestamp is taken into account to ensure that only the most *recent* value is returned, for a specific key.
> Instead of using the block height as the timestamp, we use the block view instead.
This is because there can only be one block per view while there could potentially be more than one block per height.
This ensures that the timestamp is always monotonically increasing per block.
 
- When the built-in compaction feature is triggered, any *stale* keys are removed and the disk space is recovered.
> By default RocksDB will ensure that compaction is triggered at least once every 30-days; but you can configure this behaviour by setting the `db.rocksdb_compaction_period` option.

### Operation

1. At each epoch, the node increments its internal timestamp *ceiling*, which will result in any new state being tagged with a higher timestamp.
2. The node will trigger a background operation to *snapshot* all active state that should be retained, by duplicating the entire state-trie with the higher timestamp.
This operation may take some time to complete, possibly several epochs, and the node will only allow one such operation at a time.
3. After the operation is complete, the node increments its internal timestamp *floor*; and any state with a timestamp below the *floor* will eventually be compacted away.

### Conditions

The conditions for the *ceiling* and the *floor* are that:
- The *ceiling* is always incremented i.e. new ceiling > old ceiling.
- The *floor* is always incremented i.e. new floor > old floor.
- The *ceiling* is always greater than the *floor* i.e. ceiling > floor.
- The *floor* always lags the *ceiling* i.e. floor == old ceiling.

The snapshot operation will only be triggered if the lowest block view is greater than the current *ceiling*.
This condition ensures the safety that, the only states pruned are those that are absolutely no longer needed, since the block no longer exists in the SQL database.
This also means that the node may retain more state than it actually needs.
Considering the amount of state saved through pruning, this bit of extra state is negligible.

### Key Migration

For nodes that disable pruning, the existing keys need to be migrated to the new tagged-keys.
This process is done lazily, as nodes are being read from time to time.
Whenever a legacy-key node is read from the database, the key is migrated to the new tagged-key format and deleted by compaction.
