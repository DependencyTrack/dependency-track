---
title: National Vulnerability Database
category: Datasources
chapter: 4
order: 1
---

The National Vulnerability Database (NVD) is the largest publicly available source of vulnerability intelligence.
It is maintained by a group within the National Institute of Standards and Technology (NIST) and builds upon the
work of MITRE and others. Vulnerabilities in the NVD are called Common Vulnerabilities and Exposures (CVE). There
are over 100,000 CVEs documented in the NVD spanning from the 1990's to the present.

Dependency-Track relies heavily on the data provided by the NVD and includes a full mirror, which is 
kept up-to-date on a daily basis, or upon the restarting of the Dependency-Track instance.

Credit is provided to the National Vulnerability Database with visual and textual cues on where the data originated.
Links back to the original CVE are also provided.

### NVD Mirror

Dependency-Track is not only a consumer of the NVD, but provides mirroring functionality as well. This functionality
is built into Dependency-Track and does not require further configuration. The mirror is automatically updated daily.

> The base URL to the mirror is: http://hostname/mirror/nvd

Directory listing is prohibited, but the index consists of identical content available from the NVD. This includes:

##### JSON 1.1 feed
* nvdcve-1.1-modified.json.gz
* nvdcve-1.1-%d.json.gz
* nvdcve-1.1-%d.meta

(Where %d is a four digit year starting with 2002)
