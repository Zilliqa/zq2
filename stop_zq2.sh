#!/opt/homebrew/bin/bash
zq2_nodes=$(\ps -ef | grep -E 'target/[^\/]+/zilliqa --config-file ./infra/config.toml' | grep -v grep | gawk '{print $2}')
[[ -n "${zq2_nodes}" ]] && echo "${zq2_nodes}" | xargs kill
