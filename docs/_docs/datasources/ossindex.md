---
title: Sonatype OSS Index
category: Datasources
chapter: 4
order: 3
---

Sonatype OSS Index provides transparent and highly accurate results for components with valid Package URLs. 
The majority of vulnerabilities directly map to CVEs in the National Vulnerability Database (NVD), however, 
OSS Index does contain many vulnerabilities that are not present in the NVD.

Dependency-Track integrates with OSS Index using it's public API. Dependency-Track does not mirror OSS Index, 
but it does consume vulnerabilities from OSS Index on a 'as-identified' basis.

> OSS Index is disabled by default as it requires an account. It's highly recommended that OSS Index is enabled
> in order to provide accurate results. To enable OSS Index, sign up for a free account and enter the account 
> details in Dependency-Track in the 'Analyzers' settings in the administrative console.
