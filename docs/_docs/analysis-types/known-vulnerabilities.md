---
title: Known Vulnerability Analysis
category: Analysis Types
chapter: 3
order: 1
---

Dependency-Track integrates with multiple sources of vulnerability intelligence to identify components with known 
vulnerabilities. The platform employs several methods of vulnerability identification including:

| Analyzer  | Description |
| ----------|-------------|
| Internal  | Identifies vulnerable components from an internal directory of vulnerable software|
| NPM Audit | NPM Audit is a service which identifies vulnerabilities in Node.js Modules|
| OSS Index | OSS Index is a service provided by Sonatype which identifies vulnerabilities in third-party components|
| VulnDB    | VulnDB is a commercial service which identifies vulnerabilities in third-party components|

Each of the analyzers above can be enabled or disabled independently from one another.

![configure analyzers](/images/screenshots/scanners-configure.png)

### Internal Analyzer

The internal analyzer relies on a dictionary of vulnerable software. This dictionary is automatically populated when 
NVD mirroring or VulnDB mirroring is performed. The dictionary is capable of identifying software by their CPE or 
Package URL along with optionally describing version ranges. The internal analyzer is used by all components with 
valid CPEs, including application, operating system, and hardware components.

This analyzer may also use the [Private Vulnerability Repository]({{ site.baseurl }}{% link _docs/datasources/private-vuln-repo.md %}).

### NPM Audit Analyzer

NPM Audit is a service which identifies vulnerabilities in Node.js Modules. Dependency-Track integrates natively 
with the NPM Audit service to provide highly accurate results. Use of this analyzer requires a valid Package URL for 
the components being analyzed.

NPM is a source of vulnerability intelligence that provides its own content. Refer to 
[NPM Public Advisories (Datasource)]({{ site.baseurl }}{% link _docs/datasources/npm.md %}) for additional information.

### OSS Index Analyzer

OSS Index is a service provided by Sonatype which identifies vulnerabilities in third-party components. The service 
supports a wide range of package management ecosystems. Dependency-Track integrates natively with OSS Index to provide 
highly accurate results. Use of this analyzer requires a valid Package URL for the components being analyzed.

> OSS Index is disabled by default as it requires an account. It's highly recommended that OSS Index is enabled
> in order to provide accurate results. To enable OSS Index, sign up for a free account and enter the account 
> details in Dependency-Track in the 'Analyzers' settings in the administrative console.

OSS Index is a source of vulnerability intelligence that provides its own content. Refer to 
[OSS Index (Datasource)]({{ site.baseurl }}{% link _docs/datasources/ossindex.md %}) for additional information.

### VulnDB Analyzer

VulnDB is a subscription service offered by Risk Based Security. The VulnDB Analyzer is capable of analyzing all 
components with CPEs against the VulnDB service. Use of this analyzer requires a valid CPE for the components being 
analyzed.

VulnDB is a source of vulnerability intelligence that provides its own content. Refer to 
[VulnDB (Datasource)]({{ site.baseurl }}{% link _docs/datasources/vulndb.md %}) for additional information.

### Analysis Interval Throttle

Dependency-Track contains an internal limiter which prevents repeated requests to remote services when performing
vulnerability analysis. When a components Package URL or CPE is successfully used for a given analyzer, the action
and the timestamp is recorded and compared to the interval throttle. The interval throttle defaults to one hour.
