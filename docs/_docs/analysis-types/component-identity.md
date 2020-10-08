---
title: Component Identity
category: Analysis Types
chapter: 3
order: 4
---

Components can be evaluated based on their identity as part of the Dependency-Track policy engine. Identity may include:

| Identity    | Description |
|-------------|-------------|
| Coordinates | Matches components that contain the specified group, name, and version |
| Package URL | Matches components that have the specified Package URL |
| CPE         | Matches components that have the specified CPE |
| SWID TagID  | Matches components with the specified SWID TagID |
| Hash        | Matches components with the specified hash |

* Hash identity automatically checks all supported hash algorithms including:
  * MD5
  * SHA-1
  * SHA-256
  * SHA-384
  * SHA-512
  * SHA3-256
  * SHA3-384
  * SHA3-512
  * BLAKE2b-256
  * BLAKE2b-384
  * BLAKE2b-512
  * BLAKE3

## Usages

Common uses for evaluating components based on their identity include:
* Organizational policy containing pre-defined list of allowed and/or prohibited components
* Identifying counterfeit and/or known malicious components
