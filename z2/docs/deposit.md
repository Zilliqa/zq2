# z2 deposit

The `z2 deposit` command deposits ZIL tokens to the deposit smart contract to promote a node as a validator.


```bash
z2 deposit \
  --chain <CHAIN_NAME> \
  --public-key <BLS_PUBLIC_KEY> \
  --peer-id <PEER_ID> \
  --wallet <PRIVATE_KEY_OF_VALIDATOR> \
  --amount <AMOUNT_IN_ZIL> \
  --reward-address <REWARD_ADDRESS_OF_VALIDATOR>


Usage: z2 deposit --chain <CHAIN_NAME> --public-key <BLS_PUBLIC_KEY> --peer-id <PEER_ID> --wallet <PRIVATE_KEY_OF_VALIDATOR> --amount <AMOUNT_IN_ZIL> --reward-address <REWARD_ADDRESS_OF_VALIDATOR>
```
### Parameters
* `--chain <CHAIN_NAME>`: The name of the chain. Possible values are zq2-devnet, zq2-prototestnet, zq2-protomainnet, zq2-testnet, zq2-mainnet.
* `--public-key <BLS_PUBLIC_KEY>`: The BLS public key of the validator node.
* `--peer-id <PEER_ID>`: The peer ID of the validator node.
* `--wallet <PRIVATE_KEY_OF_VALIDATOR>`: The private key of the validator node.
* `--amount <AMOUNT_IN_MILLION_ZIL>`: The amount in ZIL to deposit. The valid range is from 10 million to 255 million ZIL, allowing a deposit of up to 255 million ZIL.
* `--reward-address <REWARD_ADDRESS>`: The address where rewards will be received.

### Generating Required Values
To generate the public_key and peer-id, use the following command inside the zq2 GitHub directory:
```bash
$ echo '{"secret_key":"85df22702faf5b843b72bc8ff1cf5858f89228527ac548f1e03ad715c80d45c1"}' | cargo run --bin convert-key
    Finished `dev` profile [unoptimized + debuginfo] target(s) in 0.66s
     Running `target/debug/convert-key`
{"address":"0xb606148a62e1c010a9808bc3dfde6d1522349989","peer_id":"12D3KooWFWJA4UdQxBVp9LndNzQgyAv8baSRoLuXi2tLu8pTMqtu","public_key":"ab82e738f757a270e0e8a0d9e90b8bad98f5d8cb436b053e12b85a2567ff15fe1f274d827724c269bf03d1w328750f92"}
```

### Run z2 deposit

#### Sample run


```bash
  z2 deposit --chain zq2-prototestnet --peer-id  12D3KooWJiR42GkGPKTUxxxxx --public-key 9357841b3d8135d55aa8d2ece84de720cafd9c1c055b4e46dxxxx \
  --wallet 10bcce301da16xxxx --reward-address 0x3e422c617eB2880F7Axxxxx \
  --amount 100
```
