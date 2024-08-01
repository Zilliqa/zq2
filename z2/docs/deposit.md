# z2 deposit

The `z2 deposit` command deposits ZIL tokens to the deposit smart contract to promote a node as a validator.


```bash
z2 deposit \
  --chain <CHAIN_NAME> \
  --public-key <BLS_PUBLIC_KEY> \
  --peer-id <PEER_ID> \
  --private-key <PRIVATE_KEY_OF_VALIDATOR> \
  --amount <AMOUNT_IN_ZIL> \
  --reward-address <REWARD_ADDRESS_OF_VALIDATOR> \
  --pop-signature <BLS_POP_SIGNATURE>

Usage: z2 deposit --chain <CHAIN_NAME> --public-key <BLS_PUBLIC_KEY> --peer-id <PEER_ID> --private-key <PRIVATE_KEY_OF_VALIDATOR> --amount <AMOUNT_IN_ZIL> --reward-address <REWARD_ADDRESS_OF_VALIDATOR> --pop-signature <BLS_POP_SIGNATURE>
```
## Parameters
* `--chain <CHAIN_NAME>`: The name of the chain. Possible values are zq2-devnet, zq2-prototestnet, zq2-protomainnet, zq2-testnet, zq2-mainnet.
* `--public-key <BLS_PUBLIC_KEY>`: The BLS public key of the validator node.
* `--peer-id <PEER_ID>`: The peer ID of the validator node.
* `--private-key <PRIVATE_KEY_OF_VALIDATOR>`: The private key of the validator node.
* `--amount <AMOUNT_IN_MILLION_ZIL>`: The amount in ZIL to deposit. The valid range is from 10 million to 255 million ZIL, allowing a deposit of up to 255 million ZIL.
* `--reward-address <REWARD_ADDRESS>`: Specifies the address to receive rewards. You can generate a new wallet address to receive the rewards.
* `--pop-signature <BLS_POP_SIGNATURE>`: The BLS proof-of-possession signature of the validator node.

### Generating Required Values
To generate the `public-key`, `pop-signature` and `peer-id`, use the following command inside the zq2 folder. Please pass `PRIVATE_KEY_OF_VALIDATOR` to the command input.
```bash
echo '{"secret_key":"<PRIVATE_KEY_OF_VALIDATOR>"}' | cargo run --bin convert-key
```
#### Sample run
```bash
$ echo '{"secret_key":"96252e38af375be21d9eb30a6b88abc3836acecaeb2240731fb42e0299e14419"}' | cargo run --bin convert-key
    Finished `dev` profile [unoptimized + debuginfo] target(s) in 0.67s
     Running `target/debug/convert-key`
{"address":"0x3946f9872247af2eb4fe44c81c463e801925b8d4","bls_pop_signature":"90dbc73ac9f40b75acd8279a50447f5f4e61c377f4147d1dc4b6f139b84d5c48180aae67c76db3abc4c205e4c48df5160a88ae1b84ed4869c9660458d7feb5100ccc499dbd4f2131b5a90e34261ae6ea9246abf8c32b75b1f16e63a66eec2214","bls_public_key":"825124961d51c99816848875fa505b75f2e62e69937fe9bfa5fa97711845abd667f05bdc3756f7dba6b7e9e0467a3804","peer_id":"12D3KooWGu8PBoj6vMPafnhA2P7sLumSV1NhQJZ2W2AGiBgc5ATW","tx_pubkey":{"Ecdsa":["3056301006072A8648CE3D020106052B8104000A03420004B7C457DC36C75EADA5675629F1CE0FA93534FB76ADFC49840CC050AE2995FC87764AEB8975D049D19FDA6BFF2B3FF51608034A3FC6708F476A0C9306BA5CBE14",true]}}
```

### Run z2 deposit

#### Sample run


```bash
  z2 deposit --chain zq2-prototestnet \
  --peer-id  12D3KooWGu8PBoj6vMPafnhA2P7sLumSV1NhQJZ2W2AGiBgc5ATW \
  --private-key 96252e38af375be21d9eb30a6b88abc3836acecaeb2240731fb42e0299e14419 \
  --reward-address 0xe29a3e99a6997B1571DA24d6517e7b3acaFB5d9e \
  --amount 100 \
  --public-key 825124961d51c99816848875fa505b75f2e62e69937fe9bfa5fa97711845abd667f05bdc3756f7dba6b7e9e0467a3804 \
  --pop-signature  90dbc73ac9f40b75acd8279a50447f5f4e61c377f4147d1dc4b6f139b84d5c48180aae67c76db3abc4c205e4c48df5160a88ae1b84ed4869c9660458d7feb5100ccc499dbd4f2131b5a90e34261ae6ea9246abf8c32b75b1f16e63a66eec2214 
```
