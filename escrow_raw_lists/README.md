# Escrow lodge lists

Consensus-critical lodge lists for the mintable escrow (`zilliqa/src/escrow_raw_input.rs`). Same
treatment as `blocked_recipients/`, different schedule and directory: a fork's `escrow_lodge_file`
+ `escrow_lodge_start_height` names a file here, baked into the Docker image at
`/escrow_raw_lists`, where nodes read it via the `escrow_raw_lists_dir` config option (falling
back to `data_dir`).

Every node on a network must run byte-identical files: nothing in the node verifies their content,
so a divergent copy surfaces only as a state-root mismatch mid-schedule. Never modify a file after
a fork referencing it has shipped; a new list means a new numbered file and a new fork.

Each file holds `(user, amount)` entries grouped into regions by source ZRC2 contract. From the
start height each block lodges 100 entries into the mintable escrow contract via a system call to
`lodge(source, users, amounts)`; the contract assigns rather than accumulates, so a (user, source)
pair must appear at most once per file. Lodging needs no pair: a source's balances become claimable
once the admin whitelists it against an EVM target with `whitelist(source, target)`, before or after
the schedule reaches it.

A full 100-entry batch costs ~2.6M gas (~25.7k per entry, all fresh storage slots). `State::escrow_lodge`
never puts more than 100 entries in one EVM call regardless of input, and a node refuses to start if
`100 × LODGE_GAS_PER_ENTRY` (60k, about 2x the measured cost) exceeds `eth_block_gas_limit`.

Generated with `generate-escrow-raw-input` (`zilliqa/src/bin/`) from per-token holder CSVs whose
header names an address column and an amount column (base units):

```sh
cargo build -p zilliqa --bin generate-escrow-raw-input
./target/debug/generate-escrow-raw-input --out escrow_raw_lists/escrow_lodge_001.bin \
  holders/gzil.csv=0x<gZIL ZRC2> holders/xsgd.csv=0x<XSGD ZRC2>
```

No lodge file has been generated yet.
