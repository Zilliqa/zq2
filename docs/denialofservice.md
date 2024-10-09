# Denial of Service Guides

The term **Denial of Service** (DoS) is a phrase that covers a wide range of security issues and vulnerabilities that impact availability.
A comprehensive introduction and overview to a variety of DoS attacks can be found at [CloudFlare](https://www.cloudflare.com/learning/ddos/glossary/denial-of-service/).

## Infrastructure Layer

A good starting point in learning about general infrastructure hardening and DoS mitigations can be found at [OWASP](https://cheatsheetseries.owasp.org/cheatsheets/Denial_of_Service_Cheat_Sheet.html).

- If you are running a node in a Docker container, read the [hardening guide](https://cheatsheetseries.owasp.org/cheatsheets/Docker_Security_Cheat_Sheet.html), particularly on [DoS avoidance](https://cheatsheetseries.owasp.org/cheatsheets/Docker_Security_Cheat_Sheet.html#rule-7-limit-resources-memory-cpu-file-descriptors-processes-restarts).
- If you are running a node in the Cloud, consider reading the secure cloud [hardening guide](https://cheatsheetseries.owasp.org/cheatsheets/Secure_Cloud_Architecture_Cheat_Sheet.html), particularly on [DDoS protection](https://cheatsheetseries.owasp.org/cheatsheets/Secure_Cloud_Architecture_Cheat_Sheet.html#ddos-protection).

## Network Layer

- The P2P layer uses `libp2p`.
They have published a set of useful guidelines on how to mitigate DoS issues in their [documentation](https://docs.libp2p.io/concepts/security/dos-mitigation/).
- The RPC layer uses `jsonrpsee`.
While they have incorporated some [DoS mitigation](https://github.com/paritytech/jsonrpsee/issues/203), it can still benefit from general REST [hardening strategies](https://cheatsheetseries.owasp.org/cheatsheets/REST_Security_Cheat_Sheet.html) published by OWASP.

## Consensus Layer

If the next Proposer can be predicted, it can be crippled with a targeted DoS attack. While *sentry nodes* are a short-term solution, the longer-term solution should be to implement some *single secret leader election* (SSLE) mechanism e.g.

- [Whisk](https://ethresear.ch/t/whisk-a-practical-shuffle-based-ssle-protocol-for-ethereum/11763)
- [Simplified SSLE](https://ethresear.ch/t/simplified-ssle/12315)
- [Secret non-Single Leader Election](https://ethresear.ch/t/secret-non-single-leader-election/11789)

One could be implemented in the future, when the need arises.

## Application Layer

There are many ways to make a Smart Contract unusable.
It would be prudent to develop an understanding for the [Top-10 Smart Contact vulnerabilities](https://owasp.org/www-project-smart-contract-top-10/) published by OWASP.
A collection of additional examples can also be found [here](https://solidity-by-example.org/hacks/denial-of-service/).