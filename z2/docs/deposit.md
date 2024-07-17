# z2 deposit

`z2 deposit` deposit the $ZILs to the deposit smart contract to promote a node as validator.

```bash
z2 deposit

  --chain <CHAIN_NAME>
  --public-key <PUBLIC_KEY>
  --peer-id <PEER_ID>
  --wallet <WALLET>
  --amount <AMOUNT>
  --reward-address <REWARD_ADDRESS>

Usage: z2 deposit --chain <CHAIN_NAME> --public-key <PUBLIC_KEY> --peer-id <PEER_ID> --wallet <WALLET> --amount <AMOUNT> --reward-address <REWARD_ADDRESS>
```



### Run z2 deposit

#### Requirements

1. node public key
1. node peer id
1. funds wallet
1. the amount (min. 10M $ZILs)
1. reward address

```bash
    z2 deposit --chain prototestnet --peer-id  12D3KooWJiR42GkGPKTUxxxxx --public-key 9357841b3d8135d55aa8d2ece84de720cafd9c1c055b4e46dxxxx \
    --wallet 10bcce301da16xxxx --reward-address 0x3e422c617eB2880F7Axxxxx \
    --amount 10

