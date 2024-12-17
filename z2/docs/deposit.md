# z2 deposit

The `z2 deposit` command deposits ZIL tokens to the deposit smart contract to promote a node as a validator.


```bash
z2 deposit \
  --chain <CHAIN_NAME> \
  --public-key <BLS_PUBLIC_KEY> \
  --peer-id <PEER_ID> \
  --private-key <PRIVATE_KEY_OF_WALLET_WITH_MIN_10_MIL_FUND> \
  --amount <AMOUNT_IN_ZIL> \
  --reward-address <REWARD_ADDRESS_OF_VALIDATOR> \
  --signing-address <SIGNING_ADDRESS_OF_VALIDATOR> \
  --deposit-auth-signature <DEPOSIT_AUTH_SIGNATURE>

Usage: z2 deposit --chain <CHAIN_NAME> --public-key <BLS_PUBLIC_KEY> --peer-id <PEER_ID> --private-key <PRIVATE_KEY_OF_WALLET_WITH_MIN_10_MIL_FUND> --amount <AMOUNT_IN_ZIL> --reward-address <REWARD_ADDRESS_OF_VALIDATOR> --signing-address <SIGNING_ADDRESS_OF_VALIDATOR> --deposit-auth-signature <DEPOSIT_AUTH_SIGNATURE>
```
## Parameters
* `--chain <CHAIN_NAME>`: The name of the chain. Possible values are zq2-devnet, zq2-prototestnet, zq2-protomainnet, zq2-testnet, zq2-mainnet.
* `--public-key <BLS_PUBLIC_KEY>`: The BLS public key of the validator node.
* `--peer-id <PEER_ID>`: The peer ID of the validator node.
* `--private-key <PRIVATE_KEY_OF_WALLET_WITH_MIN_10_MIL_FUND>`: The private key of the wallet that has a minimum stake amount of 10 million.
* `--amount <AMOUNT_IN_MILLION_ZIL>`: The amount in ZIL to deposit. The valid range is from 10 million to 255 million ZIL, allowing a deposit of up to 255 million ZIL.
* `--reward-address <REWARD_ADDRESS>`: Specifies the address to receive rewards. You can generate a new wallet address to receive the rewards.
* `--signing-address <SIGNING_ADDRESS>`: Specifies the address which signs cross-chain events.
* `--deposit-auth-signature <DEPOSIT_AUTH_SIGNATURE>`: The BLS proof-of-possession signature of the validator node.

**Note**: The `--private-key` parameter should be the private key of a wallet that has secured a minimum stake amount of 10 million ZILs.

### Generating Required Values
To generate the `public-key`, `deposit-auth-signature` and `peer-id`, use the following command inside the zq2 folder. Please pass `PRIVATE_KEY_OF_VALIDATOR` and `CHAIN_ID` to the command input. 

By default this tool signs over the address derived from the given secret key to generate the `deposit-auth-signature`, you may want to override this for example if deploying via a Deleagtion contract. To override pass in `"address": "<CONTROL_ADDRESS>"`.

```bash
echo '{"secret_key":"<PRIVATE_KEY_OF_VALIDATOR>", "chain_id": <CHAIN_ID>}' | cargo run --bin convert-key
```
#### Sample run
```bash
$ echo '{"secret_key":"96252e38af375be21d9eb30a6b88abc3836acecaeb2240731fb42e0299e14419", "chain_id": 33469}' | cargo run --bin convert-key
    Finished `dev` profile [unoptimized + debuginfo] target(s) in 0.67s
     Running `target/debug/convert-key`
{"address":"0x3946f9872247af2eb4fe44c81c463e801925b8d4","deposit_auth_signature":"a53efd8bad058e4e551b7e9681613a278b782acfe05fb98d536bc95029278704adbb85891cdc7fa384ab7d5008fdd42c0ea70404ab4ec07bcf5e738c92b2be88debdc33014852ead1d9976fcbf7760043615ba74f36181fc87db21f8f8997a44","bls_public_key":"825124961d51c99816848875fa505b75f2e62e69937fe9bfa5fa97711845abd667f05bdc3756f7dba6b7e9e0467a3804","peer_id":"12D3KooWGu8PBoj6vMPafnhA2P7sLumSV1NhQJZ2W2AGiBgc5ATW","tx_pubkey":{"Ecdsa":["3056301006072A8648CE3D020106052B8104000A03420004B7C457DC36C75EADA5675629F1CE0FA93534FB76ADFC49840CC050AE2995FC87764AEB8975D049D19FDA6BFF2B3FF51608034A3FC6708F476A0C9306BA5CBE14",true]}}

```

### Run z2 deposit

#### Sample run


```bash
  z2 deposit --chain zq2-prototestnet \
  --peer-id  12D3KooWGu8PBoj6vMPafnhA2P7sLumSV1NhQJZ2W2AGiBgc5ATW \
  --private-key 96252e38af375be21d9eb30a6b88abc3836acecaeb2240731fb42e0299e14419 \
  --reward-address 0x3946f9872247af2eb4fe44c81c463e801925b8d4 \
  --signing-address 0x3946f9872247af2eb4fe44c81c463e801925b8d4 \
  --amount 100 \
  --public-key 825124961d51c99816848875fa505b75f2e62e69937fe9bfa5fa97711845abd667f05bdc3756f7dba6b7e9e0467a3804 \
  --deposit-auth-signature  b12ab1e18e2393f165c083f9685f708aa7a1578d2685e18f4f19d950ad27c10c8dd0cf4cb637b7b215687afe861906ec064a7d89acbba718e6590cfd3baebe06bc7779028207909fff9c9c3db34f0ce812969e37d252907f9496e50bd725bb5e 
```