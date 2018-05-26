---
title: National Vulnerability Database
category: Datasources
chapter: 3
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

* nvdcve-modified.xml.gz
* nvdcve-2.0-modified.xml.gz
* nvdcve-%d.xml.gz
* nvdcve-2.0-%d.xml.gz
* nvdcve-1.0-modified.json.gz
* nvdcve-1.0-%d.json.gz

(Where %d is a four digit year starting with 2002)

### Configuring OWASP Dependency-Check

Dependency-Check can be configured to utilize the NVD mirror provided by Dependency-Track. Organizations that utilize
one of the Dependency-Check implementations (Command Line, Jenkins, Maven, Ant, or Gradle plugin) are highly encouraged 
to utilize an internal mirror since it has the following advantages:

* Increases performance by eliminating large downloads over the public Internet
* Increases build stability by eliminating the reliance on external networks
* Reduces likelihood of encountering temporary HTTP 429 (too many requests)
* Demonstrates the organization is good netizens by acknowledging the NVD doesn't have unlimited capacity

Example Dependency-Check configuration:

```ini
cveUrl12Modified=http://hostname/mirror/nvd/nvdcve-modified.xml.gz
cveUrl20Modified=http://hostname/mirror/nvd/nvdcve-2.0-modified.xml.gz
cveUrl12Base=http://hostname/mirror/nvd/nvdcve-%d.xml.gz
cveUrl20Base=http://hostname/mirror/nvd/nvdcve-2.0-%d.xml.gz
```

Consult the [Dependency-Check documentation](https://jeremylong.github.io/DependencyCheck) for further details.