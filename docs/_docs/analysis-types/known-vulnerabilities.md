---
title: Known Vulnerability Analysis
category: Analysis Types
chapter: 3
order: 1
---

Dependency-Track integrates with multiple sources of vulnerability intelligence to identify components with known 
vulnerabilities. The platform employs several methods of vulnerability identification including:

| Analyzer  | Description                                                                                            |
|-----------|--------------------------------------------------------------------------------------------------------|
| Internal  | Identifies vulnerable components from an internal directory of vulnerable software                     |
| OSS Index | OSS Index is a service provided by Sonatype which identifies vulnerabilities in third-party components |
| VulnDB    | VulnDB is a commercial service which identifies vulnerabilities in third-party components              |
| Snyk      | Snyk is a commercial service which identifies vulnerabilities in third-party components                |


Each of the analyzers above can be enabled or disabled independently from one another.

### Internal Analyzer

The internal analyzer relies on a dictionary of vulnerable software. This dictionary is automatically populated when 
NVD, GitHub Advisories, or VulnDB mirroring is performed. The internal analyzer is applicable to all components with valid 
CPEs, including application, operating system, and hardware components, and all components with Package URLs.

### OSS Index Analyzer

OSS Index is a service provided by Sonatype which identifies vulnerabilities in third-party components. The service 
supports a wide range of package management ecosystems. Dependency-Track integrates natively with OSS Index to provide 
highly accurate results. This analyzer is applicable to all components with valid Package URLs.

> Starting with Dependency-Track v4.0, OSS Index is enabled by default and does not require an account. For prior 
> Dependency-Track versions, OSS Index is disabled by default and requires an account. To enable OSS Index, 
> sign up for a free account and enter the account details in Dependency-Track in the 'Analyzers' settings in the 
> administrative console.

OSS Index is a source of vulnerability intelligence that provides its own content. Refer to 
[OSS Index (Datasource)]({{ site.baseurl }}{% link _docs/datasources/ossindex.md %}) for additional information.

### VulnDB Analyzer

VulnDB is a subscription service offered by Risk Based Security. The VulnDB Analyzer is capable of analyzing all 
components with CPEs against the VulnDB service. Use of this analyzer requires a valid CPE for the components being 
analyzed.

VulnDB is a source of vulnerability intelligence that provides its own content. Refer to 
[VulnDB (Datasource)]({{ site.baseurl }}{% link _docs/datasources/vulndb.md %}) for additional information.

### Snyk Analyzer

It is a service provided by Snyk which identifies vulnerabilities in third-party components using REST API. Snyk returns only direct vulnerabilities for a specific package version identified by Package URL (purl).
This analyzer is applicable to all components with valid Package URLs.

Snyk REST API version is updated every 6 months and can be referred at
[Snyk REST API for PURL](https://apidocs.snyk.io/?version=2022-10-06#get-/orgs/-org_id-/packages/-purl-/issues) for additional information.

### Analysis Result Cache

Dependency-Track contains an internal limiter which prevents repeated requests to remote services when performing
vulnerability analysis. When a component's Package URL or CPE is successfully analyzed by a given analyzer, 
the result is cached. By default, cache entries expire after 12 hours.
