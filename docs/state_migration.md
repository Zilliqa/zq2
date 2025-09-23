# State Migration Guide

With version `v0.19.0` the block chain *State* is now stored in RocksDB.

The entire *State* is now structured in a hierarchy:
- L1: volatile in-memory cache.
- L2: on-disk RocksDB database.
- L3: existing SQLite database.

An ad-hoc *lazy* migration is performed in the background whenever a state is missing in RocksDB and found in the SQLite database i.e. missing from L2 and found in L3.

This guide explains how to migrate the previous state into RocksDB, by replaying the blocks and writing the relevant state to RocksDB.
This exploits the [State Sync](docs/fetching_blocks.md) process.

## Migration Steps

1. Stop the node.
2. Restore the state from a previous checkpoint.
3. Configure the node to perform state-sync/state-migration.
4. Restart the node.
5. Verify that the state-sync/state-migration completed successfully.

In short, the state migration process exploits the state-sync feature to migrate the state using a previous checkpoint as a starting point.

### Selecting a Previous Checkpoint

**It is important that you choose the same checkpoint that was previously used to start your node.**

If you used the *switchover* checkpoint to start your node, then you should use that to perform the state migration.
Otherwise, use whichever checkpoint that you used previously.

If you have forgotten which checkpoint you used, call the `admin_blockRange` RPC method on your admin port (default: 4202) to retrieve the range of blocks available. The `start` field of the response will give you a hint of which checkpoint to use.

### Converting a Previous Checkpoint

Since `v0.19.0` has also introduced a new checkpoint format, you may need to convert your previous checkpoint to the new format before performing the state migration.
To do this, refer to the `zilliqa/src/bin/convert-ckpt.rs` file for instructions.

### Starting the State Migration

Before starting the state migration, ensure that you have selected the correct checkpoint and performed any necessary conversions.

```toml
[[nodes]]
load_checkpoint.hash = "14ec8508b34b93fe35d07d885acac51edef2c7ac6660e2f20d97e1cee4fa704c"
load_checkpoint.file = "/data/014169600.ckpt"
db.state_sync = true
```

### Continuing the State Migration

If state migration was interrupted before completion, you can resume it by removing the `load_checkpoint` configuration from your `zilliqa.toml` file but also ensure that the `db.state_sync` configuration is set to `true`.

```toml
[[nodes]]
#load_checkpoint.hash = "14ec8508b34b93fe35d07d885acac51edef2c7ac6660e2f20d97e1cee4fa704c"
#load_checkpoint.file = "/data/014169600.ckpt"
db.state_sync = true
```

*If you forget to do this, the state migration will simply be restarted from the checkpoint.*

### Finishing Up

Once the state migration is complete, you can remove the `load_checkpoint` and `state_sync` configurations from your `zilliqa.toml` file.
Otherwise, it will restart the entire process from the checkpoint, upon a restart.

```toml
[[nodes]]
#load_checkpoint.hash = "14ec8508b34b93fe35d07d885acac51edef2c7ac6660e2f20d97e1cee4fa704c"
#load_checkpoint.file = "/data/014169600.ckpt"
#db.state_sync = true
```

You should also rename the `state_trie` table to `state_trie_backup` as a backup.
This will cause any *lazy* migration to fail - allowing you to catch any errors.

```sql
ALTER TABLE state_trie RENAME TO state_trie_backup;
```

### Migration Status

You can periodically check the status of the migration process by querying the `admin_syncing` RPC endpoint.
The `migrate_at` field shows you the progress of the migration process.
Any value other than `0xFFFFFFFFFFFFFFFF` indicates a state migration in progress.
The block number should gradually progress over time, as blocks are replayed.

```json
{
  "jsonrpc": "2.0",
  "id": "1",
  "result": {
    "cutover_at": "0xe37f87",
    "migrate_at": "0xada5d6",
    "block_range": {
      "start": 0,
      "end": 15282747
    }
  }
}
```

You may also periodically inspect the disk space used by the `state.rocksdb` sub-directory.
It should grow significantly over time, due to state migration.

### Cleanup

The `state_trie_backup` table is kept around as a backup, in case you need to revert it if any prior states are found to be missing.
Once you're satisfied with it, you can delete the table and free up the disk space.

```sql
DROP TABLE state_trie_backup;
VACUUM;
```

*Note: Vacuuming is a time-consuming operation.
If you drop the table without vacuuming, the disk space will not be recovered; but the deleted pages will be reused for future inserts/updates.
If you vacuum the database, the entire database will be compacted.*
