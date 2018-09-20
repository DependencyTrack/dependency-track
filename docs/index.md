---
title: Introduction
---

Modern applications leverage the availability of existing components for use as building blocks 
in application development. By using existing components, organizations can dramatically decrease
time-to-market. Reusing existing components however, comes at a cost. Organizations that build on 
top of existing components assume risk for software they did not create. Vulnerabilities in third-party
components are inherited by all applications that use those components. The [OWASP Top Ten] (2013 and 2017)
both recognize the risk of [using components with known vulnerabilities](https://www.owasp.org/index.php/Top_10_2013-A9-Using_Components_with_Known_Vulnerabilities).

![dashboard](images/screenshots/dashboard.png)

Dependency-Track is a Software Composition Analysis (SCA) platform that keeps track of all third-party 
components used in all the applications an organization creates or consumes. It integrates with multiple
vulnerability databases including the [National Vulnerability Database] (NVD), [NPM Public Advisories] (NPM),
[Sonatype OSS Index], and [VulnDB] from [Risk Based Security]. Dependency-Track monitors all applications in its portfolio in order
to proactively identify vulnerabilities in components that are placing your applications at risk. Use of 
Dependency-Track can play a vital role in an overall [Cyber Supply Chain Risk Management](https://csrc.nist.gov/Projects/Supply-Chain-Risk-Management) (C-SCRM) 
program by fulfilling many of the recommendations laid out by [SAFECode](https://www.safecode.org/wp-content/uploads/2017/05/SAFECode_TPC_Whitepaper.pdf).

Dependency-Track is designed to be used in an automated DevOps environment where BoM (bill-of-material) formats are 
automatically ingested during CI/CD. Use of the [Dependency-Track Jenkins Plugin] is highly recommended for this purpose 
and is well suited for use in [Jenkins Pipeline]. In such an environment, Dependency-Track enables your DevOps teams to 
accelerate while still keeping tabs on component usage and any inherited risk.

Dependency-Track can also be used to monitor vulnerabilities in COTS (commercial off-the-shelf) software.

### Features

* Increases visibility into the use of vulnerable and outdated components
* Flexible data model supporting an unlimited number of projects and components
* Tracks vulnerabilities and inherited risk
  * by component
  * by project
  * across entire portfolio
* Tracks usage of out-of-date components
* Includes a comprehensive auditing workflow for triaging results
* Configurable notifications supporting Slack, Microsoft Teams, Webhooks, and Email
* Supports standardized SPDX license ID’s and tracks license use by component
* Supports [CycloneDX] and [SPDX] bill-of-material formats and Dependency-Check XML
* Easy to read metrics for components, projects, and portfolio
* Provides a reliable mirror of the NVD data feed
* API-first design facilitates easy integration with other systems
* API documentation available in Swagger 2.0 (OpenAPI 3 support coming soon)
* Supports internally managed users, Active Directory/LDAP, and API Keys
* Simple to install and configure. Get up and running in just a few minutes

[OWASP Top Ten]: https://www.owasp.org/index.php/Category:OWASP_Top_Ten_Project
[National Vulnerability Database]: https://nvd.nist.gov
[NPM Public Advisories]: https://www.npmjs.com/advisories
[Sonatype OSS Index]: https://ossindex.sonatype.org
[VulnDB]: https://vulndb.cyberriskanalytics.com
[Risk Based Security]: https://www.riskbasedsecurity.com
[NIST Cybersecurity Framework]: https://www.nist.gov/cybersecurity-framework
[Dependency-Check]: https://www.owasp.org/index.php/OWASP_Dependency_Check
[Dependency-Track Jenkins Plugin]: https://wiki.jenkins.io/display/JENKINS/OWASP+Dependency-Track+Plugin
[Jenkins Pipeline]: https://jenkins.io/solutions/pipeline
[CycloneDX]: http://cyclonedx.org
[SPDX]: https://spdx.org/