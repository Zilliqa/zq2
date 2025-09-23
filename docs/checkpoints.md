# State checkpoints
If enabled in the config, every _epoch length * checkpoint interval_ blocks, the node will export a state checkpoint in its datadir. This snapshot can then be imported into a brand new node to serve as a checkpoint from which to start syncing (rather than using genesis), fast-tracking the sync.

## Configuration
 * `do_checkpoints`, *boolean (default `false`)*: If `true`, enables exporting the checkpoint files. If false, checkpoints will not be created.
 * `consensus.epochs_per_checkpoint`, *u64 (default 24)*: If `do_checkpoints` is true, determines the frequency (in epochs) at which checkpoints will be exported. This is a consensus property and should correspond to the frequency of published weak subjectivity checkpoints to ensure users have a convenient way to verify the checkpoint if they choose to use one from this node (however this is not currently enforced).
 * `load_checkpoint`, *struct, optional (default `None`)*: If provided, on startup, the node will attempt to load the given checkpoint and start syncing from it. The node will fail to start if this is set and the database in the current datadir is non-empty. This is intended to be used only for new nodes.
   * `load_checkpoint.file`, *filepath*: The file to read the checkpoint from
   * `load_checkpoint.hash`, *string*: The hex-encoded hash of the checkpoint block. This value is assumed to be trusted; the checkpoint contents are verified against this hash.

## Sharing checkpoints
At this time, there is no built-in mechanism for making checkpoints available to other nodes.
 * For nodes generating checkpoint, it is the operator's responsibility to then make them available for download.
 * For new nodes wishing to sync from a checkpoint, it is the operator's responsibility to download the file and then use the `load_checkpoint` configuration parameter to point the node to the local file.

## Directory
Checkpoint files are saved inside the node's data directory, at the path `/checkpoints/{block_height}`.

Currently, old checkpoints are kept indefinitely. It is the node operator's responsibility to prune un-needed old checkpoints to save on disk space.

If the node does not have a data directory (i.e. is running on an ephemeral in-memory database), no checkpoints will be exported, regardless of the `do_checkpoints` parameter.

## Checkpoint file format
The new CKPT file format is a ZIP64 archive.
It is a more efficient format than the previous one.
It contains the following files:

- **metadata.json**: containing metadata about the checkpoint.
- **block.bincode**: bincode serialized data of the checkpoint block.
- **transactions.bincode**: bincode serialized data of the checkpoint block's transactions.
- **parent.bincode**: bincode serialized data of the parent block.
- **state.bincode**: bincode serialized data of the parent block's state.
- **history.bincode**: bincode serialized data of the missed view history required to determine the leader of the views from the parent block onward.

The state consists of a patricia-merkle-trie of accounts, and each account additionally stores the state root hash of a sub-trie for its storage. We loop through each account concatenating its key, its `Account` and its storage trie's keys and values. There may be zero or more accounts in the state (though in practice, even at genesis it is not usually possible to generate a state with zero accounts).

The format of each element currently is tightly coupled to the state implementation (in `zilliqa/src/state.rs`). The account structure is bincode-serialized; the keys for every node are also defined by the implementation in `State`. For example, an account node's key is a keccak256 hash of the account address; an EVM storage entry's key is the keccak256 of the concatetation of the corresponding account's address and its 256 bit EVM storage index. Keys for scilla storage nodes are slightly more complex.

## CLI tools
The standard `unzip` and `7z` tools can be used to inspect the archive itself e.g.

```sh
$ file 001641600.ckpt
001641600.ckpt: Zip archive data, at least v4.5 to extract, compression method=Zstd

$ unzip -l 001641600.ckpt
Archive:  001641600.ckpt
ZILCHKPT/2.0
  Length      Date    Time    Name
---------  ---------- -----   ----
      444  1980-01-01 00:00   block.bincode
      444  1980-01-01 00:00   parent.bincode
        1  1980-01-01 00:00   transactions.bincode
  7016454  1980-01-01 00:00   state.bincode
    23789  1980-01-01 00:00   history.bincode
      191  1980-01-01 00:00   metadata.json
---------                     -------
  7017534                     6 files
```

The files are ZSTD compressed, which may not be supported on all CLI tools.
So, the `bsdtar` tool can be used to extract the files for inspection.

```sh
### Install bsdtar
sudo apt install libarchive-tools

### rename to zip
mv 001641600.ckpt 001641600.ckpt.zip

### Extract with bsdtar
bsdtar -xf 001641600.ckpt.zip
```
