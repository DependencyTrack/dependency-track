---
title: VulnDB
category: Datasources
chapter: 3
order: 3
---

VulnDB, a subscription service offered by Risk Based Security, offers a comprehensive and continuously updated 
source of vulnerability intelligence.

Organizations that consume VulnDB content benefit from data which has been enhanced, corrected, and made available 
sooner than most other sources of vulnerability intelligence. As a result, organizations are able to respond quicker
and with more confidence to reduce risk.

Dependency-Track can leverage VulnDB by incorporating the entire contents of the VulnDB service. In doing so, VulnDB
data becomes a first-class citizen in Dependency-Track working alongside other sources of data to identify risk.

Credit is provided to VulnDB with visual and textual cues on where the data originated.
Links back to the original advisory are also provided.

### Setup

* Download the standalone [VulnDB Data Mirror] tool
* Execute the tool and specify the Dependency-Track vulndb directory as the target
* Dependency-Track will automatically sync the contents of the vulndb directory every 24 hours (and on startup)

#### Example

```bash
vulndb-data-mirror.sh \
    --consumer-key mykey \
    --consumer-secret mysecret \
    --dir "~/.dependency-track/vulndb"
```

When running, the console output will resemble:

```bash
VulnDB API Status:
--------------------------------------------------------------------------------
Organization Name.............: Example Inc.
Name of User Requesting.......: Jane Doe
Email of User Requesting......: jane@example.com
Subscription Expiration Date..: 2018-12-31
API Calls Allowed per Month...: 25000
API Calls Made This Month.....: 1523
--------------------------------------------------------------------------------

Mirroring Vendors feed...
  Processing 18344 of 18344 results
Mirroring Products feed...
  Processing 136853 of 136853 results
Mirroring Vulnerabilities feed...
  Processing 142500 of 166721 results
```

[VulnDB Data Mirror]: https://github.com/stevespringett/vulndb-data-mirror