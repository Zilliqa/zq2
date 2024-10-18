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
The version 3 checkpoint file is an lz4 compressed byte-array representing the concaternation of:

- A 21-byte header containing:
  * 8 magic bytes corresponding to the ASCII string `ZILCHKPT`
  * 4 bytes containing the big-endian 32-bit checkpoint version number
  * 8 bytes containing the big-endian 64-bit chain ID that the checkpoint corresponds to.
  * The 21st byte is an ASCII newline.
- A serialisation of the block data, 
- A serialisation of the block's transactions
- A serialisation of the parent block
- A serialisation of the state trie of the *parent* block


### Version `3`

After the header we have the checkpoint block itself, then its transactions, then its parent block. Blocks and transactions are currently encoded using `bincode` and the default serialization format - refer to `zilliqa/src/message.rs`.

All subsequent lines contain serialised state data of the parent block. We pass the state trie of the parent rather than the checkpoint block itself to ensure that all state data for the checkpointed block is available, including that which requires a lookup to the parent state trie such as the commitee and author. 

As some background, the state consists of a patricia merkle trie of accounts, and each account additionally stores the state root hash of a sub-trie for its storage. We loop through each account concaternating its key, its `Account` and its storage trie's keys and values. There may be zero or more accounts in the state (though in practice, even at genesis it is not usually possible to generate a state with zero accounts).

The format of each element currently is tightly coupled to the state implementation (in `zilliqa/src/state.rs`). The account structure is bincode-serialized; the keys for every node are also defined by the implementation in `State`. For example, an account node's key is a keccak256 hash of the account address; an EVM storage entry's key is the keccak256 of the concatetation of the corresponding account's address and its 256 bit EVM storage index. Keys for scilla storage nodes are slightly more complex.
