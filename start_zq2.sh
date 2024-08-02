#!/opt/homebrew/bin/bash
node_keys=(
  65d7f4da9bedc8fb79cbf6722342960bbdfb9759bc0d9e3fb4989e831ccbc227
  62070b1a3b5b30236e43b4f1bfd617e1af7474635558314d46127a708b9d302e
  56d7a450d75c6ba2706ef71da6ca80143ec4971add9c44d7d129a12fa7d3a364
  db670cbff28f4b15297d03fafdab8f5303d68b7591bd59e31eaef215dd0f246a)

cargo build && \
  for node_key in ${node_keys[@]}; do
    echo "Start node with key ${node_key}"...
    $(RUST_LOG=info ./target/debug/zilliqa --config-file ./infra/config.toml ${node_key} | tee ${node_key}.log >& /dev/null &)
  done

# Add the deterministic address deployer
$(sleep 5 && cd $THIRD_PARTY_ROOT/deterministic-deployment-proxy/ && bash ./scripts/test.sh)
