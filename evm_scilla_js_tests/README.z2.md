# Running evm js tests with z2

You can run these tests with your `z2 run` network.

`z2 run /my/dir` will write:

 * Include 32 accounts with secret keys `0x...10000` upwards in the genesis account set and write the private keys into `/my/dir/test.signers`
 * Generate a file `/my/dir/test_env.sh` which you can `source` from your shell to set up for testing.

`test_env.sh` sets environment variables which are tested in `hardhat.config.ts` to configure the test environment.

With your network running, you can then do:

```sh
$ source /my/dir/test_env.sh
$ npx hardhat test
```

See `README.md` for other hardhat options.

By default, the RPC endpoint used is the `mitmproxy`'d endpoint, so `mitmproxy` will show you test traffic for debugging.

