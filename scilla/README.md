# Scilla client

This repo acts as a way to execute against scilla, running in a docker container. The container exposes two tcp ports, here on 12345 and 12346 which are used to make JSON-RPC requests, and to read/write state information.

Assuming you have a built docker container here called `scilla_reflector:1.0` with the scilla scripts inside you can run:

```
docker run --rm -it -v /<PATH>/scilla_libs/:/tmp/scilla_libs -v /<PATH>/scilla_init/:/tmp/scilla_init -v /<PATH>/scilla_input/:/tmp/scilla_input -p 12345:12345 -p 12346:12346 scilla_reflector:1.0
./run_scilla_tcp.sh
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

The docker container is now ready to process scilla transactions. Currently the way to excercise this would be to use the js evm acceptance tests.
