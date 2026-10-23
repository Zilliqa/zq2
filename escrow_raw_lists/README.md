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

## Files

| File | Sources (regions, in order) | Entries | Lodge blocks | sha256 |
|---|---|---|---|---|
| `escrow_lodge_001.bin` | gZIL `0xA845c1034cD077bd8D32bE0447239c7e4BE6CB21` (66,748 holders), XSGD proxy `0x173CA6770aA56eb00511Dac8e6E13B3D7f16A5a5` (4,263 holders) | 71,011 | 711 | `447a2ce01b39d5e539de383835ef9c2514bf3cd9920ae771c235efaa389c9719` |

`escrow_lodge_001.bin` holds every non-zero mainnet balance of both tokens at its original address,
1:1 in base units (gZIL 15 decimals, XSGD 6), largest holders first, from state dumps taken at
block 38,700,260 (balances unchanged since). Contract holders and exchange addresses on the
blocked-recipient lists are included as-is. Built with:

```sh
./target/debug/generate-escrow-raw-input --out escrow_raw_lists/escrow_lodge_001.bin \
  exchanges/mintable/analysis/gzil_holders.csv=0xA845c1034cD077bd8D32bE0447239c7e4BE6CB21 \
  exchanges/mintable/analysis/xsgd_holders.csv=0x173CA6770aA56eb00511Dac8e6E13B3D7f16A5a5
```
