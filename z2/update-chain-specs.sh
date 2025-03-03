for network in {protomainnet,prototestnet,devnet,infratest,perftest,richard,uccbtest}; do z2 deployer get-config-file zq2-$network.yaml --out z2/resources/chain-specs/zq2-$network.toml; done
