# Denial of Service Guidelines

The term **Denial of Service** (DoS) is a phrase that covers a wide range of security issues and vulnerabilities that impact availability.

A comprehensive introduction and overview to a variety of DoS attacks can be found at [CloudFlare](https://www.cloudflare.com/learning/ddos/glossary/denial-of-service/).

## Infrastructure Layer

There is a vast collection of knowledge about DoS mitigation that has accrued over the years.
A good starting point in learning about general infrastructure hardening and DoS mitigations can be found at [OWASP](https://cheatsheetseries.owasp.org/cheatsheets/Denial_of_Service_Cheat_Sheet.html).

- If you are running a node in a Docker container, please read the [hardening guide](https://cheatsheetseries.owasp.org/cheatsheets/Docker_Security_Cheat_Sheet.html), particularly on [DoS avoidance](https://cheatsheetseries.owasp.org/cheatsheets/Docker_Security_Cheat_Sheet.html#rule-7-limit-resources-memory-cpu-file-descriptors-processes-restarts).
- If you are running a node in the Cloud, please consider reading the full secure cloud [hardening guide](https://cheatsheetseries.owasp.org/cheatsheets/Secure_Cloud_Architecture_Cheat_Sheet.html), particularly on [DDoS protection](https://cheatsheetseries.owasp.org/cheatsheets/Secure_Cloud_Architecture_Cheat_Sheet.html#ddos-protection).

## Data Layer

TODO

## Network Layer

- The P2P layers uses `libp2p`.
They have published a set of useful guidelines on how to mitigate DoS issues in their [documentation](https://docs.libp2p.io/concepts/security/dos-mitigation/).
- The RPC layer will benefit from general REST [hardening strategies](https://cheatsheetseries.owasp.org/cheatsheets/REST_Security_Cheat_Sheet.html) published by OWASP.

## Consensus Layer

If the next Proposer can be predicted, it can be subjected to a DoS attack to cripple proposal generation. While *sentry nodes* are a short-term solution, the long-term solution is *single secret leader election* (SSLE) proposals:

- [Whisk](https://ethresear.ch/t/whisk-a-practical-shuffle-based-ssle-protocol-for-ethereum/11763)
- [Simplified SSLE](https://ethresear.ch/t/simplified-ssle/12315)
- [Secret non-Single Leader Election](https://ethresear.ch/t/secret-non-single-leader-election/11789)

One should be implemented in the future, when the need arises.

## Application Layer

TODO