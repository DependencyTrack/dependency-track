---
title: Sonatype OSS Index
category: Datasources
chapter: 4
order: 4
---

Sonatype OSS Index provides transparent and highly accurate results for components with valid Package URLs. 
The majority of vulnerabilities directly map to CVEs in the National Vulnerability Database (NVD), however, 
OSS Index does contain many vulnerabilities that are not present in the NVD.

Dependency-Track integrates with OSS Index using its public API. Dependency-Track does not mirror OSS Index,
but it does consume vulnerabilities from OSS Index on a 'as-identified' basis.

> Starting with Dependency-Track v4.0, OSS Index is enabled by default and does not require an account. For prior 
> Dependency-Track versions, OSS Index is disabled by default and requires an account. To enable OSS Index, 
> sign up for a free account and enter the account details in Dependency-Track in the 'Analyzers' settings in the 
> administrative console.
