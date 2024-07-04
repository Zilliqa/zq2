# State checkpoints
If enabled in the config, every _epoch length * checkpoint interval_ blocks, the node will export a state checkpoint in its datadir. This snapshot can then be imported into a brand new node to serve as a checkpoint from which to start syncing (rather than using genesis), fast-tracking the sync.

## Configuration
 * `do_checkpoints`, *boolean (default `false`)*: If `true`, enables exporting the checkpoint files. If false, checkpoints will not be created.
 * `consensus.epochs_per_checkpoint`, *u64 (default 24)*: If `do_checkpoints` is true, determines the frequency (in epochs) at which checkpoints will be exported. This is a consensus property and will eventually be obtained on-chain rather than being configurable.
 * `load_checkpoint`, *struct, optional (default `None`)*: If provided, on startup, the node will attempt to load the given checkpoint and start syncing from it. Fails if the node has a non-empty database, i.e. intended to be used only for brand new nodes without existing data.
   * `load_checkpoint.file`, *filepath*: The file to read the checkpoint from
   * `load_checkpoint.hash`, *string*: The hex-encoded hash of the checkpoint block. This value is assumed to be trusted; the checkpoint contents are verified against this hash.

## Directory
Checkpoint files are saved inside the node's data directory, at the path `/checkpoints/{block_height}`.

If the node does not have a data directory (i.e. is running on an ephemeral in-memory database), no checkpoints will be exported, regardless of the `do_checkpoints` parameter.

Currently, old checkpoints are _not_ kept. Once a new checkpoint file is successfully created, any other files in the directory are deleted.

## Checkpoint file format
TBA
Currently uses a text file format roughly as follows:
line 1 - the checkpoint block
line 2 - the parent block, allowing the node to establish a chain of 2 blocks for finalizing future blocks
line 3 - the shard ID, for sanity checking
all subsequent lines - the serialized state at the checkpoint block. The state consists of account tries, serialized at one account per line, in the format: `{database_hash}:{serialized_account}` followed by a `;` followed by every node in the account's storage in the format `{storage_key}:{storage_value}` separated by `,`

Before the PR is merged, a version number will be added, and the format might move to binary
