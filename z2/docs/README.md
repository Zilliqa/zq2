# Z2 documentation

This directory is the house of the `z2` utility documentation.

`z2` is the in-house built tool to operate the Zilliqa's team Zilliqa 2.0 (ake `zq2`) operated network, and much more.

Using the tool you are able to:
- run a `local` copy of `zq2`
- execute performance and comformancy tests on a given `zq2` network
- convert the Zilliqa 1.0 persistences into a `zq2` persistence format
- generate the `zq2` API documentation
- generate the script to start a `zq2` validator for the supported network, see: `z2 join` for details.
- upgrade the `zq2` validators and the apps.

## Requirements

Before you start using it, ensure you have the following base pre-requirements satisfied:

- Cargo and Rust: You need to have Cargo and Rust installed on your system. You can install them using [rustup](https://rustup.sh).
- Linux/Unix like operating system
- gcloud CLI: The Google Cloud SDK (gcloud) must be installed and configured on your system. Follow the installation [instructions](https://cloud.google.com/sdk/docs/install).

# To use it

Now that you have all the tools installed, it's time for using it.

To use it:

 * Pick a directory. You'll need quite a lot of space. Let's call it `/my/dir`.
 * Clone `git@github.com:zilliqa/zq2` into that directory to get `/my/dir/devops`.
 * Source an appropriate setenv file based on the environment you want to connect to - for now `source /my/dir/zq2/scripts/setenv` will do.
 * This will give you access to the `z2` tool (in `zq2/z2`).

## What to run

- to join as `zq2` validator: [`z2 join`](./join.md)
- upgrade a `zq2` network: [`z2 deployer`](./deployer.md)
- convert `zq1` to `zq2` persistence: [`z2 converter` ](./converter.md)
