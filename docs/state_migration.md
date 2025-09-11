# State Migration Guide

With version `v0.19.0` the block chain *State* is now stored in RocksDB.
This guide explains how to migrate your state from the previous storage format to RocksDB.

## Migration Steps

1. Stop the node.
2. Restore the state from a previous checkpoint.
3. Configure the node to perform state-sync.
4. Restart the node.
5. Verify that the state-sync completed successfully.

In short, the state migration process exploits the state-sync feature to migrate the state using a previous checkpoint as a starting point.

### Selecting a Previous Checkpoint

**It is important that you choose the same checkpoint that was previously used to start your node.**

If you used the *switchover* checkpoint to start your node, then you should use that to perform the state migration. Otherwise, use whichever checkpoint that you used previously.

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

### Finishing Up

Once the state migration is complete, you can remove the `load_checkpoint` and `state_sync` configurations from your `zilliqa.toml` file.
Otherwise, it will restart the entire process again, upon a restart.

```toml
[[nodes]]
#load_checkpoint.hash = "14ec8508b34b93fe35d07d885acac51edef2c7ac6660e2f20d97e1cee4fa704c"
#load_checkpoint.file = "/data/014169600.ckpt"
#db.state_sync = true
```

### Cleanup

The node will automatically rename the `state_trie` table to `state_trie_backup`, upon finishing the state-migration process.

This table is kept around as a backup, in case you need to revert it if any prior states are found to be missing.
Once you're done with it, you can delete the table and free up the disk space.

```sql
DROP TABLE state_trie_backup;
VACUUM;
```
