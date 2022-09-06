---
title: VulnDB
category: Datasources
chapter: 4
order: 5
---

VulnDB, a subscription service offered by Risk Based Security, offers a comprehensive and continuously updated 
source of vulnerability intelligence.

Organizations that consume VulnDB content benefit from data which has been enhanced, corrected, and made available 
sooner than the National Vulnerability Database. As a result, organizations are able to respond quicker
and with more confidence to reduce risk.

Credit is provided to VulnDB with visual and textual cues on where the data originated.
Links back to the original advisory are also provided.

Dependency-Track supports VulnDB in two ways:
* A VulnDB Analyzer may be enabled which integrates with VulnDB REST APIs to identify vulnerabilities in components with a CPE
* Ingests VulnDB mirrored content and incorporates the entire vulnerability database into Dependency-Track 

### Using the VulnDB Analyzer

The VulnDB Analyzer is capable of analyzing all components with CPEs against the VulnDB service. The analyzer is a 
consumer of the VulnDB REST APIs and requires an OAuth 1.0a Consumer Key and Consumer Secret be configured in
Dependency-Track. Although not exclusive, any component with a CPE defined will be analyzed with VulnDB.

### Using the Internal Analyzer

The native Dependency-Track internal analyzer is capable of analyzing components that have valid CPEs or Package URLs
against a dictionary of vulnerable software which Dependency-Track maintains. When the NVD or VulnDB are mirrored, the
vulnerability information for the affected products are added to the internal vulnerable software dictionary.

If VulnDB is mirrored using a tool such as [VulnDB Data Mirror] and the contents have been ingested by Dependency-Track, 
the internal analyzer will automatically benefit from the additional data in the dictionary that VulnDB provided.

### Choosing an Approach

Both ways of integration have their advantages. Using the VulnDB analyzer is quick, can be used on an as-needed basis, 
and doesn't have the overhead that a mirroring approach may have. 

Using the mirror will provide faster responses, the ability to browse all VulnDB content within Dependency-Track, but
comes at the expense of performing the initial mirror, which is time consuming and requires a lot of requests to VulnDB.

> VulnDB subscription plans may have a limit on the number of requests that can be made to the service per month.
> Dependency-Track does not monitor this, nor throttle its requests when limits are nearing or have been reached. It 
> is the responsibility of VulnDB customers to manage their subscription and ensure they're using the service within
> the defined license terms.

### VulnDB Mirror Setup

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
