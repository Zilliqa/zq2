# Blocked-recipient lists

Consensus-critical account lists for the staged freeze-and-sweep
(`zilliqa/src/blocked_recipients.rs`). Each file is named by a fork in the chain specs
(`blocked_recipients_file` + `blocked_recipients_start_height` for the first list,
`blocked_recipients_file_v2` + `blocked_recipients_start_height_v2` for the second) and baked into
the Docker image at `/blocked_recipients`, where nodes read it via the `blocked_recipients_dir`
config option. The two pairs are independent schedules: each is swept by its own fork fields, both
are opened at startup, and a block inside both schedules sweeps the first list's batch before the
second's.

Every node on a network must run byte-identical files: nothing in the node verifies their content,
so a divergent copy surfaces only as a state-root mismatch mid-schedule. Never modify a file after
a fork referencing it has shipped; a new list means a new numbered file and a new fork.

Generated with `generate-blocked-recipients` (`zilliqa/src/bin/`) from per-exchange CSVs, one
destination per source file. The tool re-reads its output through the node's own parser and
verifies every (address, destination) pair before reporting success.

| File | Addresses | Regions | Sweep blocks | sha256 |
|---|---|---|---|---|
| `blocked_recipients_001.bin` | 1,460,781 | 14 | 14,608 | `b020631500d74b6df549e3b0f8a2140a6956001acf6bf6b171d3b319f37c7666` |
| `blocked_recipients_002.bin` | 508,861 | 16 | 5,089 | `c7562003bc14fd1474d76f300cf73d8d3d3d292e98c5ea299682e2965e6c56d7` |
| `blocked_recipients_003.bin` | 100,831 | 4 | 1,009 | `84db5851922ab2e474d5930efcfe7a2ae463cddcb9b5d13481e1c44e76118f71` |
| `blocked_recipients_004.bin` | 3,420 | 3 | 35 | `4e676bc245ca37a5e6f08099b428cbad0a99daa54082e990afe377b5d9af507a` |

`blocked_recipients_001.bin` sweeps, in order: the devnet test pair, Binance US (`binance-us.csv`
— this list was originally misfiled as `binance.csv`; global Binance is a disjoint set), Bitvavo,
CoinSwitch, Indodax, Korbit, KuCoin (`kucoin1.csv` then `kucoin2.csv`, which share a destination
and so fold into one region — `kucoin2.csv` contributes no new addresses at all), Bitrue,
Binance, MEXC, Coinspot, OKCoin, Coinhako, WhiteBIT.

Preprocessing decisions baked into the CSVs: Coinhako's submission included the bech32 form of
its own destination (`zil1ue465zmpyqp67vyd0rcxdw7mnf0qplmv2rs4sm`), removed because a swept
destination would make the outcome order-dependent (the generator aborts on it); MEXC supplied
its destination in lowercase, canonicalised here to its EIP-55 form.

> **`exchanges/devnet-test.csv` holds one artificial address**, deliberately placed first so it
> is swept in the schedule's very first block, to observe the freeze end-to-end on devnet:
> `zil1ascnfxmlzl4z3l6ecavxcae5hc37gdzr23enz0` → `0x89ae98e4140f04236c6Af4bBB25B3a892DBEba88`.
> Decision 2026-08-21: it stays in the list on **all** networks, testnet and mainnet included —
> the address is artificial with no known owner, so freezing and sweeping it there is a
> zero-balance no-op, and keeping it makes the file identical everywhere.

Regenerate with:

```sh
cargo build -p zilliqa --bin generate-blocked-recipients
./target/debug/generate-blocked-recipients --out blocked_recipients/blocked_recipients_001.bin \
  exchanges/devnet-test.csv=0x89ae98e4140f04236c6Af4bBB25B3a892DBEba88 \
  exchanges/binance-us.csv=0x48df1c337F04649687557608f7f2E65aeA93754C \
  exchanges/bitvavo.csv=0xb0A3A2B60E969AFD26561429Aa4c1444C57E4411 \
  exchanges/coinswitch.csv=0x84653C310cEFb75593A16C2e794Ca21fED8a68e7 \
  exchanges/indodax.csv=0x91Dca37856240E5e1906222ec79278b16420Dc92 \
  exchanges/korbit.csv=0xd6e0F7dA4480b3AD7A2C8b31bc5a19325355CA15 \
  exchanges/kucoin1.csv=0x682be515327794C68BdB622A21D324aeeb5eB7f7 \
  exchanges/kucoin2.csv=0x682be515327794C68BdB622A21D324aeeb5eB7f7 \
  exchanges/bitrue.csv=0x6cc8dCbCA746a6E4Fdefb98E1d0DF903b107fd21 \
  exchanges/binance.csv=0xF977814e90dA44bFA03b6295A0616a897441aceC \
  exchanges/mexc.csv=0x4224eD9447292b765A31c65866A15EF70b9fA655 \
  exchanges/coinspot.csv=0xf35A6bD6E0459A4B53A27862c51A2A7292b383d1 \
  exchanges/okcoin.csv=0x2a45907f94df93388801AE72fE810eac75926a1d \
  exchanges/coinhako.csv=0xE66BAa0B612003AF308D78f066Bbdb9a5e00fF6c \
  exchanges/whitebit.csv=0x9d493B52D04DdD28E79E25D57A7f8DB123A73937
```

The order is **append-only**, not alphabetical: sources added later go at the end. Dedup is
first-occurrence, so appending keeps every pre-existing address at its original index and
destination, and an address a late source shares with an earlier exchange keeps that exchange's
destination rather than being diverted. (There is no such overlap today — the generator would
abort on one rather than choose.) The current file is a strict prefix-extension of the previous
634,637-address build: identical addresses, indices and regions, with six regions appended.

## `blocked_recipients_002.bin` — second hard-fork additions

Named by the `_v2` fork pair at placeholder height `99999999` in `zq2-mainnet.toml`,
`zq2-testnet.toml` and `z2/src/chain.rs`. It holds **only** the second-fork additions; none of its
addresses appears in `blocked_recipients_001.bin`, and no destination of either file appears in
either list.

Sweeps, in submission order: Bitget, CEX.IO (three regions, one destination per address, as
supplied), Bitkub (no destination supplied; swept to the zero address by decision of 2026-09-04,
knowingly burning the ≈1,107 ZIL those addresses held at block 34964116), Paribu, Crypto.com, Gate, Gopax (three regions: one funded address each to its own
destination, then 957 zero-balance addresses to the zero address as a placeholder), LBank, OKX,
Coinone, CoinEx, Huobi.

Preprocessing decisions baked into the CSVs: Bitget, CEX.IO, Paribu, LBank, OKX, CoinEx (supplied separately from its
address list), Huobi and Gopax's first destination were supplied in lowercase and canonicalised to EIP-55 (Huobi's sheet carries the
destination on its first data row only); Crypto.com's destination was
supplied with an invalid EIP-55 casing and is used in its correctly checksummed form
`0x3AD306B66F9A98f63bCed92F5E08423AaEA6b3C9` (same hex digits, confirmed 2026-09-04); the devnet
test pair is not repeated (already frozen by `001`); duplicate lines in OKX (10) and Coinone (160)
collapse to the first occurrence.

```sh
./target/debug/generate-blocked-recipients --out blocked_recipients/blocked_recipients_002.bin \
  exchanges/bitget.csv=0x1AB4973a48dc892Cd9971ECE8e01DcC7688f8F23 \
  exchanges/cexio-1.csv=0x32f932c2a6E65575bB048B21bb3Ad284db99c555 \
  exchanges/cexio-2.csv=0x31E5DAD29f6b391864E9d6e95E1b389a5122d8B3 \
  exchanges/cexio-3.csv=0x8aAFDd92e0D7AfEd22DfF5Ce3D04631E905932cc \
  exchanges/bitkub.csv=0x0000000000000000000000000000000000000000 \
  exchanges/paribu.csv=0xc80Afd311c9626528De66D86814770361Fe92416 \
  exchanges/cryptocom.csv=0x3AD306B66F9A98f63bCed92F5E08423AaEA6b3C9 \
  exchanges/gate.csv=0x0D0707963952f2fBA59dD06f2b425ace40b492Fe \
  exchanges/gopax1.csv=0x5b2B20ae1545E0959d1dd588f30522945A7cBae9 \
  exchanges/gopax2.csv=0x56e3a93a37a630d3dB08c49C0f91F786ff1a5D8E \
  exchanges/gopax3.csv=0x0000000000000000000000000000000000000000 \
  exchanges/lbank.csv=0xDdDC2e17FDA0E7610C7975B0CaCD4A5A7dfC5581 \
  exchanges/okx.csv=0x84e4999a3D11aaE356677928526Ae5BcE734A109 \
  exchanges/coinone.csv=0x8FA75DF407Bb3C1F5F4e342E3eC51f0f6F022DA6 \
  exchanges/coinex.csv=0xBD9caD312C96A288Eb7ceC8b28ea5390AffA5E2B \
  exchanges/huobi.csv=0x3054D66D8b6d1cEdc2aA82Ca865dC6d3C2f2CD6E
```

## `blocked_recipients_003.bin` — third hard-fork additions

Named by the `_v3` fork pair. It holds **only** the third-batch additions; none of its addresses appears in
`blocked_recipients_001.bin` or `blocked_recipients_002.bin`, and no destination of any file
appears in any list.

Sweeps, in submission order (raw file dates): Bybit (817 addresses), Uphold (5), Bithumb
(100,007), then a two-address addendum (`addendum-003.csv`, added 2026-09-22, source not yet
named) swept to `0xAAF33a7e4756D097B2158551a25374Daf600c49D`. One destination per region.

Preprocessing decisions baked into the CSVs: Bithumb's destination was supplied in lowercase and
canonicalised to its EIP-55 form `0x46e21fa3A6B5d2ec25dd756d445891e3ef9FbB51`; Bybit's and
Uphold's were supplied correctly checksummed. The raw lists contained no duplicate lines, no
overlaps with each other or with the earlier files, and no hex-encoded source addresses
(bech32 throughout); Bybit's sheet ends in 199 fully blank rows, ignored.

```sh
./target/debug/generate-blocked-recipients --out blocked_recipients/blocked_recipients_003.bin \
  exchanges/bybit.csv=0x0F309D25cF6B170fcFEF83aE3B30aF8918A7e02A \
  exchanges/uphold.csv=0x1A9D699aeE3a56ca49d0CC3b542aE3A37885A3e1 \
  exchanges/bithumb.csv=0x46e21fa3A6B5d2ec25dd756d445891e3ef9FbB51 \
  exchanges/addendum-003.csv=0xAAF33a7e4756D097B2158551a25374Daf600c49D
```

The source CSVs live in `exchanges/`, which is **not** committed.

## `blocked_recipients_004.bin` — fourth hard-fork additions

Named by the `_v4` fork pair (`blocked_recipients_start_height_v4` /
`blocked_recipients_file_v4`), scheduled at the placeholder height 999999999 on every network.
It holds **only** the fourth-batch additions; none of its addresses appears in files 001–003,
and no destination of any file appears in any list.

Sweeps, in submission order (raw file dates): XT (3,396 addresses, file dated 2026-10-12) to
`0xDB3DED7731C781224EC292E2163D9554c094fD7c`, then Gopax's additional legacy addresses (file dated
2026-10-19): 23 to Gopax's existing wallet `0x5b2B20ae1545E0959d1dd588f30522945A7cBae9` (the same
destination as `gopax1.csv` in 002), and one, `zil1s7u5puac7gwnsctq5ts7d3u56066rfrezg5p0t`
(36,389,918.5 ZIL according to the sheet), to its own destination
`0x5B6fe4A6069f5BfD70f6209e0c695cEf917e4D1D`, exactly as supplied. Confirm that destination with
Gopax before activation.

Preprocessing decisions baked into the CSVs: XT's destination appears only on the first data row
and applies to the whole file, as for Paribu and Huobi in 002; its trailing `TOTAL` row is not an
address and is ignored. All three destinations were supplied in lowercase and canonicalised to
EIP-55. The raw lists contained no duplicate lines, no overlap with each other or with the
earlier files, and bech32 source addresses throughout. Balances in the sheets were not checked.

```sh
./target/debug/generate-blocked-recipients --out blocked_recipients/blocked_recipients_004.bin \
  exchanges/xt.csv=0xDB3DED7731C781224EC292E2163D9554c094fD7c \
  exchanges/gopax4-1.csv=0x5b2B20ae1545E0959d1dd588f30522945A7cBae9 \
  exchanges/gopax4-2.csv=0x5B6fe4A6069f5BfD70f6209e0c695cEf917e4D1D
```

Escrow lodge lists follow the same rules but live in their own directory: see
`escrow_raw_lists/README.md`.

## `staked_zils_001.bin`: ZQ1 staking payout (mainnet)

This is not a blocked-recipient list. It's the staked-ZIL payout file that mainnet's `invalidate_zq1_staking_contract` fork names through `staked_zils_file`. Its format is `u64 count`, followed by entries of source (20 bytes), destination (20 bytes) and amount (`u128` LE, in 10^-18 ZIL). From the fork height, each block pays out 100 entries. A payout moves the entry's amount plus the source's wallet balance, then zeroes the source and freezes it (nonce MAX). Once the last entry is paid, the SSNList contract `0xA7c67d49C82c7DC1B73d231640B2E4d0661D37C1` is emptied and its balance burned.

| File | Entries | Payout blocks | Total | sha256 |
|---|---|---|---|---|
| `staked_zils_001.bin` | 95,720 | 958 | 1,388,495,350.241477 ZIL | `f7431f69e9488602af1c9be35bfe404aacc9590354058dae90a3679589322d18` |

What each source is owed comes from `exchanges/staked_zil.json` (the SSNList state; staking is frozen):

- the stake, Σ `deposit_amt_deleg`: 1,062,744,399.38 ZIL;
- unstaked but not yet withdrawn ZIL, Σ `withdrawal_pending`: 137,682,759.68 ZIL;
- unclaimed rewards, from the exact `CalcStakeRewards` replay: 173,383,988.65 ZIL;
- each validator's `comm_rewards`, paid to its `rec_addr`: 14,684,202.53 ZIL.

The total is 13,425.20 ZIL more than the contract's balance, a rounding effect of the reward replay. Open swap requests are ignored, so the requester is paid. Contract delegators (507, about 40.2M ZIL, including Avely's stZIL holder `0xa083…83ef`) are included even though they can't claim.

Destinations:

| Source | Destination |
|---|---|
| `zil1n9tds2n7wuwxdqt5hmlpv78683c98pa9cqayd6` (`0x9956…87a5`, 70,000,000 ZIL staked) | `0xf35A6bD6E0459A4B53A27862c51A2A7292b383d1`, direct |
| `zil1mmcz334ghshlvphedszev63amnkl6xge9gfrz4` (`0xdef0…1919`, no stake; amount 0, so only its wallet ZIL moves) | `0x6cc8dCbCA746a6E4Fdefb98E1d0DF903b107fd21`, direct |
| everyone else (95,718 sources) | old escrow `0x00000000005a494c31455343524f5750524f5859`, via `lodge()`; claimable by ZK proof |

Built with:

```sh
python3 exchanges/staked-zil-analysis/scripts/build_staked_zils_csv.py
./target/debug/generate-staked-zils --out blocked_recipients/staked_zils_001.bin \
  exchanges/staked-zil-analysis/staked_zils_001.csv
```
