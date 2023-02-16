# Zilliqa 2.0 - The next evolution of Zilliqa

## Running a Node

Currently, the network topology is hardcoded at startup time.
You need to specify the committee in a command line parameter in the format `<public key>:<libp2p public key>:<weight>,...`.

You also need to pass a private key in a command line parameter.
This will be interpreted as both a BLS private key and a libp2p secp256k1 private key (of course the corresponding public keys will be different).

### Example invocations for a network with 4 nodes

```
export COMMITTEE="a058e1af125a827c401cb30a0688d5fb649bbe385bbe5635d71ad7b0444936f88fb0b016bd89c81fe7f97285854e4e4d:0802122103132343015712d05a49ae7c5132ca6315f9c583b9ad6a2f82d2e54d57587f11f7:100,91012d7a6c689afb1d7a6d4b346fba963a042d61e42b516a2166ed35859cb5af398ad6ed624a67a4390f39a9903a01e8:0802122102d197b62317b04aab394d5d0bc199e7160198dfe986919d719bb2acd966ed0565:100,b0f5fbabed5a7bcc58e24f7730a3acec73119c48e9de5f951eebb3f282ce6697ef4e3301bdf1cc5e45a7133e59c8fad1:0802122102e890aaa17838142a61479033d0b75bf4b41d6db5637b29ef55658f3ae1bc7458:100,acade6d558ecc020d7189b2d2497a0f857b0c73152d1645c2cc8b16dc06f1868613dc26130131b41f811ca8fdb3f9ba6:0802122102003edef986e6364a7985708008ff65b09424ee6cb181bd742b02a0da5b6bc655:100"

cargo run -- 0 $COMMITTEE db670cbff28f4b15297d03fafdab8f5303d68b7591bd59e31eaef215dd0f246a
cargo run -- 1 $COMMITTEE 62070b1a3b5b30236e43b4f1bfd617e1af7474635558314d46127a708b9d302e
cargo run -- 2 $COMMITTEE 56d7a450d75c6ba2706ef71da6ca80143ec4971add9c44d7d129a12fa7d3a364
cargo run -- 3 $COMMITTEE 65d7f4da9bedc8fb79cbf6722342960bbdfb9759bc0d9e3fb4989e831ccbc227
```
