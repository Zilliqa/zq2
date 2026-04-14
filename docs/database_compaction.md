# Database Compaction

The data in a node is stored in both a SQLite and RocksDB database.
- The SQLite database does **not** perform automatic compaction. So, each write to the database e.g. INSERT, UPDATE, DELETE, ends up consuming more and more disk space over time.
- While RocksDB database performs periodic background compaction, it is spread out over the span of 30-days. So, each write to the database consumes disk space until the background compaction is triggered to recover it.

In either case, the disk space consumed by the database will only grow.
Manually performing a compaction as periodic maintenance, can help to recover disk space and improve performance.

## Manual Compaction

To manually compact the SQLite database:
```
# sqlite3 /data/32769/db.sqlite3 "VACUUM;"
```

To manually compact the RocksDB database:
```
# ldb --db=/data/32769/state.rocksdb/ compact
```

## Downtime Mitigation

In either case, the entire database is locked and cannot be used during the compaction operation; and each compaction will take many **hours** to complete.

To help mitigate the extended downtime, it is recommended to perform the compaction on a replica of the database.

1. Shutdown the running node, to flush data to disk.
2. Make a replica of the database directory e.g. `/data` to `/data2`.
3. Restart the node and leave it running.
4. Perform a compaction of the database in `/data2`.
5. Modify the `config.toml` configuration to point `data_dir` to the new `/data2` directory.
6. Restart the node with the new configuration.

While this means that the restarted node will be lagging behind the head of the chain, it should be able to sync up quickly.

*If you are running a validator node, you may want to run a normal node with separate keys using the `/data2` directory until it is fully synced, before swapping the keys.*

## Alternate Methods

If you do not need to preserve the entire history, an alternative is to periodically restore a node from a recent checkpoint.
A checkpoint is taken every 86,400 blocks and published on https://checkpoints.zq2-mainnet.zilliqa.com/
By periodically restoring a node from a recent checkpoint, you minimise the database fragmentation and minimise downtime.
