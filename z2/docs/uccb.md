# uccb testing

UCCB testing runs via `z2`.

The way this works is that we write a bridge configuration, which
contains all the networks in the bridge. Some of these will have their
own clients (zq2 networks), and some of them will be foreign networks
like ethereum.

The bridge configuration looks something like this:

```
[[z2]]
local.base_port=5000
local.lodes=0-4
local.config_dir=/tmp/d
chain_gateway=
chain_id=


[[remote]]
api=http://example.com/
chain_id=
chain_gateway=
```

You can also configure a z2 network as a remote if you want - this
allows us to test the remote network code with a local network.

First, start the bridge with `z2 bridge start --config-file=<file>`.

We use deterministic deployment to deploy the UCCB contracts to the
locations previously advertised on all networks. The UCCB clients will
then be able to connect to those contracts and we can start running
tests.


