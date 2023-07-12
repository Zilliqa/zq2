## eth-trie

[![Latest Version](https://img.shields.io/crates/v/eth_trie.svg)](https://crates.io/crates/eth_trie)
[![](https://img.shields.io/hexpm/l/plug.svg)](https://github.com/carver/eth-trie.rs/blob/master/LICENSE)
[![CircleCI](https://circleci.com/gh/carver/eth-trie.rs/tree/master.svg?style=svg)](https://circleci.com/gh/carver/eth-trie.rs/tree/master)

Rust implementation of the Merkle-Patricia Trie, used by Ethereum.

The implementation is forked from [CITA-trie](https://github.com/citahub/cita-trie), which was
strongly inspired by [go-ethereum trie](https://github.com/ethereum/go-ethereum/tree/master/trie).

## Features

- Modified Patricia Tree, as used by Ethereum
- Custom storage interface

## Example

```rust
use std::sync::Arc;

use eth_trie::MemoryDB;
use eth_trie::{EthTrie, Trie, TrieError};

fn main() -> Result<(), TrieError> {
    let memdb = Arc::new(MemoryDB::new(true));

    let key = b"test-key";
    let value = b"test-value";

    let root = {
        let mut trie = EthTrie::new(memdb.clone());
        trie.insert(key, value)?;

        let v = trie.get(key)?;
        assert_eq!(Some(value.to_vec()), v);
        trie.root_hash()?
    };
    assert_eq!(root.as_bytes(), b"\x0ee/\xd2Y,\x8aS}\xcf|0\x85L\xb2\x87\xea\xabt\x0c\x16\xd9G\x0c\xa3\xe0S\xf4\x9b}\xe3g");

    let mut trie = EthTrie::new(memdb).at_root(root);

    let exists = trie.contains(key)?;
    assert_eq!(exists, true);

    let removed = trie.remove(key)?;
    assert_eq!(removed, true);

    // Back to the empty key after removing the only key
    let new_root = trie.root_hash()?;
    assert_eq!(new_root.as_bytes(), b"V\xe8\x1f\x17\x1b\xccU\xa6\xff\x83E\xe6\x92\xc0\xf8n[H\xe0\x1b\x99l\xad\xc0\x01b/\xb5\xe3c\xb4!");

    Ok(())
}

```

## Benchmark

```sh
cargo bench

Gnuplot not found, disabling plotting
insert one              time:   [1.6564 us 1.7287 us 1.7955 us]
                        change: [-2.2715% +1.5151% +5.1789%] (p = 0.42 > 0.05)
                        No change in performance detected.

insert 1k               time:   [1.1620 ms 1.1763 ms 1.1942 ms]
                        change: [-2.3339% +0.7190% +3.7809%] (p = 0.65 > 0.05)
                        No change in performance detected.
Found 16 outliers among 100 measurements (16.00%)
  9 (9.00%) high mild
  7 (7.00%) high severe

insert 10k              time:   [13.491 ms 13.677 ms 13.891 ms]
                        change: [-5.3670% -1.2847% +2.8328%] (p = 0.54 > 0.05)
                        No change in performance detected.
Found 10 outliers among 100 measurements (10.00%)
  9 (9.00%) high mild
  1 (1.00%) high severe

get based 10k           time:   [1.0707 us 1.0965 us 1.1270 us]
                        change: [-10.331% -6.5107% -2.6793%] (p = 0.00 < 0.05)
                        Performance has improved.
Found 11 outliers among 100 measurements (11.00%)
  11 (11.00%) high mild

remove 1k               time:   [538.54 us 545.18 us 553.96 us]
                        change: [-7.3508% -0.7110% +7.0860%] (p = 0.86 > 0.05)
                        No change in performance detected.
Found 12 outliers among 100 measurements (12.00%)
  5 (5.00%) high mild
  7 (7.00%) high severe

remove 10k              time:   [5.7277 ms 5.7780 ms 5.8367 ms]
                        change: [-18.778% -5.4831% +10.503%] (p = 0.51 > 0.05)
                        No change in performance detected.
Found 11 outliers among 100 measurements (11.00%)
  1 (1.00%) high mild
  10 (10.00%) high severe
```

### Custom hash algorithm
See: https://crates.io/crates/hasher

### Custom storage

[Refer](https://github.com/carver/eth-trie.rs/blob/master/src/db.rs)
