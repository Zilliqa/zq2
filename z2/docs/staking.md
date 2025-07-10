# z2 deposit

The `z2 deposit` command deposits ZIL tokens to the deposit smart contract to promote a node as a validator.


```bash
z2 deposit \
  --chain <CHAIN_NAME> \
  --private-key <PRIVATE_KEY> \
  --public-key <PUBLIC_KEY> \
  --peer-id <PEER_ID> \
  --deposit-auth-signature <DEPOSIT_AUTH_SIGNATURE> \
  --amount <AMOUNT> \
  --reward-address <REWARD_ADDRESS> \
  --signing-address <SIGNING_ADDRESS>


Usage: z2 deposit --chain <CHAIN_NAME> --private-key <PRIVATE_KEY_OF_WALLET_WITH_MIN_10_MIL_FUND> --public-key <BLS_PUBLIC_KEY> --peer-id <PEER_ID> --deposit-auth-signature <DEPOSIT_AUTH_SIGNATURE> --amount <AMOUNT_IN_MILLION_OF_ZIL> --reward-address <REWARD_ADDRESS_OF_VALIDATOR> --signing-address <SIGNING_ADDRESS_OF_VALIDATOR> 
```
## Parameters
* `--chain <CHAIN_NAME>`: The name of the chain. Possible values are zq2-devnet, zq2-testnet, zq2-mainnet.
* `--private-key <PRIVATE_KEY_OF_WALLET_WITH_MIN_10_MIL_FUND>`: The private key of the wallet that has a minimum stake amount of 10 million.
* `--public-key <BLS_PUBLIC_KEY>`: The BLS public key of the validator node.
* `--peer-id <PEER_ID>`: The peer ID of the validator node.
* `--deposit-auth-signature <DEPOSIT_AUTH_SIGNATURE>`: BLS signature of the validator node signing over control address and chain Id.
* `--amount <AMOUNT_IN_MILLION_ZIL>`: The amount in millions of ZIL to deposit. The valid range is from 10 million to 255 million ZIL, allowing a deposit of up to 255 million ZIL.
* `--reward-address <REWARD_ADDRESS>`: Specifies the address to receive rewards. You can generate a new wallet address to receive the rewards.
* `--signing-address <SIGNING_ADDRESS>`: Specifies the address which signs cross-chain events.

**Note**: The `--private-key` parameter should be the private key of a wallet that has secured a minimum stake amount of 10 million ZILs.

### Generating Required Values
To generate the `public-key`, `deposit-auth-signature` and `peer-id`, use the following command inside the zq2 folder. Please pass `PRIVATE_KEY_OF_VALIDATOR` and `CHAIN_ID` to the command input. 


```bash
echo '{"secret_key":"<PRIVATE_KEY_OF_VALIDATOR>", "chain_id": <CHAIN_ID>}' | cargo run --bin convert-key
```

By default this tool signs over the address derived from the given secret key to generate the `deposit-auth-signature`, you may want to override this for example if deploying via a Delegation contract. To override pass in `"control_address": "<CONTROL_ADDRESS>"`.


#### Sample run
```bash
$ echo '{"secret_key":"96252e38af375be21d9eb30a6b88abc3836acecaeb2240731fb42e0299e14419", "chain_id": 33469}' | cargo run --bin convert-key
    Finished `dev` profile [unoptimized + debuginfo] target(s) in 0.67s
     Running `target/debug/convert-key`
{"bls_public_key":"825124961d51c99816848875fa505b75f2e62e69937fe9bfa5fa97711845abd667f05bdc3756f7dba6b7e9e0467a3804","control_address":"0x3946f9872247af2eb4fe44c81c463e801925b8d4","deposit_auth_signature":"a53efd8bad058e4e551b7e9681613a278b782acfe05fb98d536bc95029278704adbb85891cdc7fa384ab7d5008fdd42c0ea70404ab4ec07bcf5e738c92b2be88debdc33014852ead1d9976fcbf7760043615ba74f36181fc87db21f8f8997a44","peer_id":"12D3KooWGu8PBoj6vMPafnhA2P7sLumSV1NhQJZ2W2AGiBgc5ATW","tx_pubkey":{"Ecdsa":["3056301006072A8648CE3D020106052B8104000A03420004B7C457DC36C75EADA5675629F1CE0FA93534FB76ADFC49840CC050AE2995FC87764AEB8975D049D19FDA6BFF2B3FF51608034A3FC6708F476A0C9306BA5CBE14",true]}}
```

Or with delegation contract control address:

```bash
$ echo '{"secret_key":"96252e38af375be21d9eb30a6b88abc3836acecaeb2240731fb42e0299e14419", "chain_id": 33469, "control_address": "0x3946f9872247af2eb4fe44c81c463e801925b8d4"}' | cargo run --bin convert-key
    Finished `dev` profile [unoptimized + debuginfo] target(s) in 0.67s
     Running `target/debug/convert-key`
{"bls_public_key":"825124961d51c99816848875fa505b75f2e62e69937fe9bfa5fa97711845abd667f05bdc3756f7dba6b7e9e0467a3804","peer_id":"12D3KooWGu8PBoj6vMPafnhA2P7sLumSV1NhQJZ2W2AGiBgc5ATW","tx_pubkey":{"Ecdsa":["3056301006072A8648CE3D020106052B8104000A03420004B7C457DC36C75EADA5675629F1CE0FA93534FB76ADFC49840CC050AE2995FC87764AEB8975D049D19FDA6BFF2B3FF51608034A3FC6708F476A0C9306BA5CBE14",true]},"control_address":"0x3946f9872247af2eb4fe44c81c463e801925b8d4","deposit_auth_signature":"a53efd8bad058e4e551b7e9681613a278b782acfe05fb98d536bc95029278704adbb85891cdc7fa384ab7d5008fdd42c0ea70404ab4ec07bcf5e738c92b2be88debdc33014852ead1d9976fcbf7760043615ba74f36181fc87db21f8f8997a44"}


```

### Run z2 deposit

#### Sample run
```bash
  z2 deposit --chain zq2-testnet \
  --peer-id  12D3KooWGu8PBoj6vMPafnhA2P7sLumSV1NhQJZ2W2AGiBgc5ATW \
  --private-key 96252e38af375be21d9eb30a6b88abc3836acecaeb2240731fb42e0299e14419 \
  --reward-address 0xe29a3e99a6997B1571DA24d6517e7b3acaFB5d9e \
  --signing-address 0x3946f9872247af2eb4fe44c81c463e801925b8d4 \
  --amount 10 \
  --public-key 825124961d51c99816848875fa505b75f2e62e69937fe9bfa5fa97711845abd667f05bdc3756f7dba6b7e9e0467a3804 \
  --deposit-auth-signature  b4770471f1b6b798b3a5cf19b6f574724777f2fbf7b7f520e75fc8461cafcfd84114316fe2aeaf35b52b9ca519310f8c0bf5cd941426e4a78cc7e10c6da80f245a9ddadc42de3f8a35db42d633b2b03847b33883f702eb13c332988d34d68d90 
```


# z2 deposit top up
Top up a Staker with more ZIL.

```bash
z2 deposit-top-up \
  --chain <CHAIN_NAME>
  --private-key <PRIVATE_KEY>
  --public-key <PUBLIC_KEY>
  --amount <AMOUNT>

Usage: z2 deposit-top-up --chain <CHAIN_NAME> --private-key <PRIVATE_KEY_OF_WALLET> --public-key <BLS_PUBLIC_KEY> --amount <AMOUNT_IN_MILLION_OF_ZIL>
```

## Parameters
* `--chain <CHAIN_NAME>`: The name of the chain. Possible values are zq2-devnet, zq2-testnet, zq2-mainnet.
* `--private-key <PRIVATE_KEY_OF_WALLET>`: The private key of the wallet.
* `--public-key <BLS_PUBLIC_KEY>`: The BLS public key of the validator node.
* `--amount <AMOUNT_IN_MILLION_OF_ZIL>`: The amount in millions of ZILs to top up.

#### Sample run
```bash
z2 deposit-top-up --chain zq2-testnet \
  --private-key 96252e38af375be21d9eb30a6b88abc3836acecaeb2240731fb42e0299e14419 \
  --public-key 825124961d51c99816848875fa505b75f2e62e69937fe9bfa5fa97711845abd667f05bdc3756f7dba6b7e9e0467a3804 \
  --amount 10
```


# z2 unstake
Unstake ZIL from Staker.

```bash
z2 unstake \
  --chain <CHAIN_NAME>
  --private-key <PRIVATE_KEY>
  --public-key <PUBLIC_KEY>
  --amount <AMOUNT>

Usage: z2 deposit-top-up --chain <CHAIN_NAME> --private-key <PRIVATE_KEY_OF_WALLET> --public-key <BLS_PUBLIC_KEY> --amount <AMOUNT_IN_MILLION_OF_ZIL>
```

## Parameters
* `--chain <CHAIN_NAME>`: The name of the chain. Possible values are zq2-devnet, zq2-testnet, zq2-mainnet.
* `--private-key <PRIVATE_KEY_OF_WALLET>`: The private key of the wallet.
* `--public-key <BLS_PUBLIC_KEY>`: The BLS public key of the validator node.
* `--amount <AMOUNT_IN_MILLION_OF_ZIL>`: The amount in millions of ZILs to unstake.

#### Sample run
```bash
z2 unstake --chain zq2-testnet \
  --private-key 96252e38af375be21d9eb30a6b88abc3836acecaeb2240731fb42e0299e14419 \
  --public-key 825124961d51c99816848875fa505b75f2e62e69937fe9bfa5fa97711845abd667f05bdc3756f7dba6b7e9e0467a3804 \
  --amount 10
```


# z2 withdraw
Withdraw unstaked ZIL from deposit contract.

```bash
z2 withdraw \
  --chain <CHAIN_NAME>
  --private-key <PRIVATE_KEY>
  --public-key <PUBLIC_KEY>
  --count <COUNT>

Usage: z2 deposit-top-up --chain <CHAIN_NAME> --private-key <PRIVATE_KEY_OF_WALLET> --public-key <BLS_PUBLIC_KEY> --count <COUNT>
```

## Parameters
* `--chain <CHAIN_NAME>`: The name of the chain. Possible values are zq2-devnet, zq2-testnet, zq2-mainnet.
* `--private-key <PRIVATE_KEY_OF_WALLET>`: The private key of the wallet.
* `--public-key <BLS_PUBLIC_KEY>`: The BLS public key of the validator node.
* `--count <COUNT>`: Number of withdrawals to process. This is useful in scenarios when the processing a large number of withdrawals would take the transcation over the block gas limit. Set to `0` to process all withdrawals.

#### Sample run
```bash
z2 withdraw --chain zq2-testnet \
  --private-key 96252e38af375be21d9eb30a6b88abc3836acecaeb2240731fb42e0299e14419 \
  --public-key 825124961d51c99816848875fa505b75f2e62e69937fe9bfa5fa97711845abd667f05bdc3756f7dba6b7e9e0467a3804 \
  --count 0
```