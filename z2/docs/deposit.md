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
## Parameters
* `--chain <CHAIN_NAME>`: The name of the chain. Possible values are zq2-devnet, zq2-prototestnet, zq2-protomainnet, zq2-testnet, zq2-mainnet.
* `--public-key <BLS_PUBLIC_KEY>`: The BLS public key of the validator node.
* `--peer-id <PEER_ID>`: The peer ID of the validator node.
* `--wallet <PRIVATE_KEY_OF_VALIDATOR>`: The private key of the validator node.
* `--amount <AMOUNT_IN_MILLION_ZIL>`: The amount in ZIL to deposit. The valid range is from 10 million to 255 million ZIL, allowing a deposit of up to 255 million ZIL.
* `--reward-address <REWARD_ADDRESS>`: The address where rewards will be received. You can generate a new reward wallet address.

### Generating Required Values
To generate the `public_key` and `peer-id`, use the following command inside the zq2 folder. Please pass `PRIVATE_KEY_OF_VALIDATOR` to the command input.
```bash
echo '{"secret_key":"<PRIVATE_KEY_OF_VALIDATOR>"}' | cargo run --bin convert-key
```
#### Sample run
```bash
$ echo '{"secret_key":"96252e38af375be21d9eb30a6b88abc3836acecaeb2240731fb42e0299e14419"}' | cargo run --bin convert-key
    Finished `dev` profile [unoptimized + debuginfo] target(s) in 0.67s
     Running `target/debug/convert-key`
{"address":"0x3946f9872247af2eb4fe44c81c463e801925b8d4","peer_id":"12D3KooWGu8PBoj6vMPafnhA2P7sLumSV1NhQJZ2W2AGiBgc5ATW","public_key":"825124961d51c99816848875fa505b75f2e62e69937fe9bfa5fa97711845abd667f05bdc3756f7dba6b7e9e0467a3804"}
```

### Run z2 deposit

#### Sample run


```bash
  z2 deposit --chain zq2-prototestnet --peer-id  12D3KooWGu8PBoj6vMPafnhA2P7sLumSV1NhQJZ2W2AGiBgc5ATW --public-key 825124961d51c99816848875fa505b75f2e62e69937fe9bfa5fa97711845abd667f05bdc3756f7dba6b7e9e0467a3804 \
  --wallet 96252e38af375be21d9eb30a6b88abc3836acecaeb2240731fb42e0299e14419 --reward-address 0xe29a3e99a6997B1571DA24d6517e7b3acaFB5d9e \
  --amount 100
```
Please note that the `--wallet` field should contain the private key of the validator node with the funds to stake. You can generate a new reward address to receive the validator rewards and supply it in `--reward-address` parameter.
