# Testing

There is now some test framework in z2. After starting a z2 network running in the context directory `/tmp/a`, you can...

```sh
./scripts/z2 test /tmp/a partition 0:0/30000 1-2:2000/30000 2-5:1-3:1000/20000
```

This tells the system to call the admin API to partition the network:

 * With node 0 being told to talk just to itself from t=0ms to t=30000ms.
 * With nodes 1 and 2 being told to talk to just 1 and 2 from t=2000ms to t=30000ms
 * With nodes 2-5 being told to talk to nodes 1-3 from t=1000ms to t=20000ms

We do this by calling `admin_whitelist` at appropriate times. Code in `testing.rs`.

You can also see what the nodes think of the chain:

```sh
./scripts/z2 test /tmp/a graphs xc viewmin-viewmax 1-2,3
```

 * In the context `/tmp/a`
 * `graphs` - draw graphs
 * With names `/tmp/xc<node_number>.dot`
 * From `viewmin` to `viewmax` (see below) inclusive.
 * On nodes `1-2,3`

`viewmax==0` means "the latest view". `viewmin>0, viewmax=0` means "the last `viewmin` views".
Otherwise they are a range of views to visualise.

Chrome is the best way to view svgs these days, it seems, so we
convert the dotfiles written by the `admin` API to `svg` with `dot`
(which you need to have installed) and then output the URLs.

