# Scilla client

This repo acts as a way to execute against scilla, running in a docker container. The container exposes tcp ports, here on 12345 to 12347 which are used to make JSON-RPC requests, and to read/write state information.

There is a docker images available on docker hub, which can be run with:

```
docker run --rm -p 12345-12347:12345-12347 nhutton/scilla_tcp:1.0 /scilla/0/run_scilla_tcp.sh
```

You should see:

```
Starting server.
Listening on [0.0.0.0] (family 0, port 12346)
Starting server.
Connection from 172.17.0.1 42400 received!
forwarding traffic.
Starting Scilla server...
```

The docker container is now ready to process scilla transactions. Currently the way to excercise this would be to use the js evm acceptance tests. Refer to that README
for more information.
