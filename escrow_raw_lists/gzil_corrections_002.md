# gZIL escrow balance correction

Seven gZIL escrow balances need correction because interop transfers continued after the
38,700,260 snapshot used by `escrow_lodge_001.bin`. The transfer receipts and current Scilla state
agree; the migration input is stale. The mainnet chain spec disabled gZIL interop at block
39,242,024, after the last affected transfer at 38,911,622.

The fix uses a new `escrow_lodge_002.bin` schedule. The mintable escrow's system-only `lodge()`
assigns the supplied balance, including zero. Seven assignments complete in one block. The
shipped input file and its original activation remain unchanged; XSGD is unaffected.

## Verified balances

Reads from [the mainnet RPC](https://api.zilliqa.com/) on 2026-11-16 confirmed these values.
The captured block-number response was 40,539,760. Scilla substate reads use finalized state;
Ethereum calls used `latest`. gZIL was frozen throughout the reads. All amounts below are gZIL,
with its full 15-decimal precision; the CSV and binary store integer base units.

| Holder | Original escrow | Corrected escrow | Change |
|---|---:|---:|---:|
| `0x3b44452249b1804760ab3a3332d3a87e15323eff` | 0.000000000000000 | 191.000000000000000 | +191.000000000000000 |
| `0x46801b8b50efe985bd21dbe3fe3d37b405ce9582` | 400.977351928987791 | 720.977351928987791 | +320.000000000000000 |
| `0x63ef61df68918229f8ea444ef99715fd7fcf0777` | 5.000000000000000 | 0.000000000000000 | -5.000000000000000 |
| `0xe3aa66398a629d20323ff79c5af4db30f3d7e374` | 0.257985453713872 | 0.537578926039698 | +0.279593472325826 |
| `0xe8091d4f68c9e3cb4a7066fc120bfe999c3afdca` | 186.280593472325826 | 0.000000000000000 | -186.280593472325826 |
| `0xedfbf2d39afb3039f5aa997061e7dcbffd06de10` | 0.000000000000000 | 0.001000000000000 | +0.001000000000000 |
| `0xfec8d1a61bcc552cf662ad94f14bb750c974315c` | 358.138139828460786 | 38.138139828460786 | -320.000000000000000 |

The original five-holder report omitted the 191 gZIL recipient and the 0.001 gZIL recipient.
Including both keeps the correction's net change at zero. Total lodged gZIL remains
559,970.095540854058769, equal to the token's `total_supply`.

## Transfer evidence

Candidate discovery scanned canonical receipts in the existing local mainnet snapshot through
block 40,225,546, selecting logs containing the gZIL address between snapshot and shutdown.
All 18 candidates were then fetched independently from `api.zilliqa.com` with
`eth_getTransactionReceipt`. These contain 11 gZIL transfer events and four allowance events;
three candidates mention gZIL without emitting a gZIL event.

`GetTransaction` returned an empty Scilla `event_logs` array for these EVM transactions.
Their Ethereum receipts expose the interop events as ABI-encoded JSON strings. Decoding those
events gives the following transfers, which exactly reconcile the live balances:

| Block | Sender → recipient (address prefixes) | gZIL | Transaction hash |
|---:|---|---:|---|
| 38,723,545 | `e3aa6639` → `edfbf2d3` | 0.001 | `7270989bac878dbfcdee40401c61abd6b25968a8ac7c3eeaf97a62d9bb318b20` |
| 38,724,773 | `edfbf2d3` → `99bbe3b4` | 0.000128992726857 | `a3c0405f711fc765d475099db5dcd83a93731e79c40dc3dfb99034683e601a70` |
| 38,745,312 | `63ef61df` → `e3aa6639` | 5 | `b9e0739f2080e57c61fde4b6b327eb6a7025a2b9ecbb6e1c741d9e21d88ba3e2` |
| 38,747,896 | `99bbe3b4` → `edfbf2d3` | 0.000128992726857 | `0191be3d180b399775d53a9fb8a20587087378522d6e669ae12f4b881eda51c1` |
| 38,762,419 | `e8091d4f` → `e3aa6639` | 10 | `a4b9f0b196a698c703cad64ef1090bdd237fa543198136c8999e6bbb9fe1495b` |
| 38,762,436 | `e8091d4f` → `e3aa6639` | 44.070148368081456 | `75fd6524aedc7b06ebd75a45f31ddf8951b3226d9405b093027f1708ea48ff7a` |
| 38,762,450 | `e8091d4f` → `e3aa6639` | 132.210445104244370 | `c1defd75575fea7f25d4cd7649524654ee45e175403858c0470b6248611f2a65` |
| 38,790,391 | `e3aa6639` → `3b444522` | 150 | `97ab5ee6e5aa045dc707afcd9dc9d8d9d63c2193d918bf0b04eca45cea6021cc` |
| 38,790,476 | `e3aa6639` → `3b444522` | 41 | `553200165a9a3c2abe0fca0f312b2bb894a167b62750a0543adb83a3b17f8f0f` |
| 38,911,579 | `fec8d1a6` → `46801b8b` | 20 | `7134aecd73d5ef88df6673d1b0a2947b8b9ed2f48533f1fd83b5a198c5a45840` |
| 38,911,622 | `fec8d1a6` → `46801b8b` | 300 | `f45b5bb80d3779e30d7df39a7209191d1fe48a29131648408e129689a98f678d` |

The intermediate holder `0x99bbe3b4f9d82e0122fd072223c4fd0cbcdb5590` has a zero net change and
zero current balance, so it needs no correction. The saved
[RPC evidence](gzil_corrections_002.evidence.json) includes its balance as well as all seven
affected holders, their existing escrow balances, the gZIL whitelist status, and total supply.
Full-map public RPC reads timed out; coverage comes from the receipt scan and participant
balance reconciliation.

## Release activation and verification

Mainnet activation is **999999998, a placeholder**. Replace both schedule heights before rollout,
after the original schedule's final block (39,248,994) and before any `sunset_zq2` activation.
The Dockerfile already packages all files in `escrow_raw_lists/`.

At verification, gZIL was unwhitelisted and every affected escrow balance still equaled the
original input. Recheck this before activation: assigning the original full balance after a claim
would allow a second claim. If those conditions change, review the correction before rollout.

From the repository root:

```sh
python3 escrow_raw_lists/verify_gzil_correction.py        # saved evidence, CSV and binary
python3 escrow_raw_lists/verify_gzil_correction.py --live # repeat API verification
```

The verifier reconstructs balances from receipts, checks the shipped file's checksum, compares
CSV and binary entries, verifies current Scilla and escrow amounts, and checks total supply.
