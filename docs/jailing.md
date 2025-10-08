# Jailing
Jailing is a penalty imposed on validators for liveness violations, i.e. for missing blocks that cause timeouts and consequently, slower block production, longer unbonding period and lower staking APR. Missing blocks can be detected retrospectively based on the view numbers recorded in the blockchain. If there is a gap between the view number of a block and its parent, all views within that range except for the first one are defined as missing. The first view produced a block, but it was forked due to the block missing in the next view.

Once a number of views defined by `LAG_BEHIND_CURRENT_VIEW` has elapsed after a view `F` was finalized, every node that reaches view `V = F + LAG_BEHIND_CURRENT_VIEW` must have committed the block proposed in view `F` and its ancestors. At this point we can take a look back at `MISSED_VIEW_WINDOW` views behind the finalized view `F` and count which leader failed in how many views. If the leader currently selected for next view failed at least `MISSED_VIEW_THRESHOLD` times, the randomized leader selection is repeated until we find a suitable leader or there is only one candidate left. Jailed validators are excluded from block production by being replaced when it's their turn to propose a block, but they can still participate in block validation and voting, allowing them to earn at least the cosigner reward while they are jailed.

## Configuration
* `max_missed_view_age`, *u64 (default `MISSED_VIEW_WINDOW`)* determines how many views older than the most recent finalized view minus `LAG_BEHIND_CURRENT_VIEW` are kept in the missed view history of the node. It is set to very large number `1000000000000` for public API nodes, enabling them to keep the whole missed view history and thus retrieve the leader of any past view in the future.

## Limitations
Restarting a node with an increased `max_missed_view_age` in its config file has no affect on where its missed view history starts, which is denoted by the `min_view` property returned by the `admin_missedViews` RPC call described below. Increasing `max_missed_view_age` will only allow the node to retain a longer history as it grows over time. If the node has already been running and is then restarted with a checkpoint older than the one it was initially synced from, the start of its missed view history will not change. You must use the `admin_importViewHistory` RPC method described below to complete the missed view history with older views that were pruned due to a missing or low `max_missed_view_age` setting in the config file.

Jailing changes the maximum lookahead i.e. how many view in the future the leader can be determined in advance. This is not an issue, on the contrary, it actually helps mitigate attacks against validators that require prior knowledge of when they are going to become the leader. 

## Activation
Jailing will become active through a hardfork at the block height specified in the respective network's configuration where `validator_jailing` is set to `true`. From a certain block number onward all checkpoints will contain a missed view history. The switchover checkpoint will be re-generated too, so that new archive nodes can have the full missed view history from the beginning on, allowing them to retrieve the leader of any past view. Existing nodes does not have to be re-synced from another checkpoint that contains missed views. After upgrading to the version that will activate jailing, they only have to import the missed view history using the `admin_importViewHistory` RPC method described in the next section.

## API methods
There are two new API methods related to jailing. The `admin_missedViews` RPC method returns the missed views that determine the leader of the view specified as argument.

The `admin_importViewHistory` RPC method reads the missed views from a checkpoint file and merges them with the missed view history of the node. There must be no gap between the node's missed view history and the missed views imported from the checkpoint file.

Jailing also alters the behavior of the `admin_getLeaders` RPC method. It will return the leaders only for the views it has the necessary missed view history for.