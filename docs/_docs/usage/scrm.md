---
title: Supply Chain Risk Management
category: Usage
chapter: 2
order: 3
---

The process of tracking, managing, and continuously evaluating metrics and risk is at the core of
[Cyber Supply Chain Risk Management](https://csrc.nist.gov/Projects/Supply-Chain-Risk-Management) programs. 

![components](/images/screenshots/components.png)

> Dependency-Track fulfills much of the guidance laid out by [SAFECode](https://www.safecode.org/wp-content/uploads/2017/05/SAFECode_TPC_Whitepaper.pdf).

* Tracks component usage among all projects in the enterprise
* Adapts to changes in component dependencies used among the various projects
* Tracks various metadata for each component including:
  * Group / Vendor
  * Component Name
  * Component Version
  * Description
  * Copyright
  * License
  * File Hashes
  * Ecosystem
  * more...
* Continuously analyzes components for known, publicly disclosed vulnerabilities
* Reports component vulnerability metrics to higher-level projects that have dependencies on them
* Reports vulnerability metrics for all projects in an organizations portfolio
* Provides vulnerability metrics over a customizable period of time for individual components, projects, or an 
organizations entire portfolio
* Identifies out-of-date components where the version used is not the latest available

#### Known Vulnerability Detection

Dependency-Track employs several methods of vulnerability identification including:

| Scanner | Description |
| ------|---------------|
| Dependency-Check | OWASP Dependency-Check is a utility designed to discover vulnerabilities in third-party components. Dependency-Check uses evidence-based analysis and performs fuzzy matching against the NVD to present results based on confidence. Dependency-Track has native integration with Dependency-Check.|
| NPM Audit | NPM Audit is a service which identifies vulnerabilities in Node.js Modules. Dependency-Track integrates natively with the NPM Audit service to provide highly accurate results.|
| OSS Index | OSS Index is a service provided by Sonatype which identifies vulnerabilities in third-party components. Dependency-Track integrates natively with the OSS Index service to provide highly accurate results.|

Each of the scanners above can be enabled or disabled independently from one another.

![configure scanners](/images/screenshots/scanners-configure.png)

#### Outdated Component Risk

Components with known vulnerabilities used in a supply chain represent significant risk to projects that have
a dependency on them. However, the use of components which do not have known vulnerabilities 
but are not the latest release, also represent risk in the following ways:
* A large portion of vulnerabilities that are discovered and fixed and never reported through official channels, or
reported at a much later time. Using components with unreported (but still known) vulnerabilities still represents risk
to projects that rely on them.
* The eventuality that vulnerabilities will be reported against a component is fairly high. Components may have
minor API changes between releases, or dramatic API changes between major releases. Keeping components updated is a 
best practice to:
  * benefit from performance, stability, and other bug fixes
  * benefit from additional features and functionality
  * benefit from ongoing community support
  * rapidly respond to a security event when a vulnerability is discovered

By keeping components consistently updated, organizations are better prepared to respond with urgency when a vulnerability
affecting a component becomes known.

Dependency-Track supports identification of outdated components by leveraging tight integration with APIs available
from various repositories. Dependency-Track relies on Package URL (purl) to identify the ecosystem a component belongs 
to, the metadata about the component, and uses that data to query the various repositories capable of supporting the 
components ecosystem. Refer to [Repositories]({{ site.baseurl }}{% link _docs/datasources/repositories.md %}) for 
further information.

#### Internet of Things (IoT)

In a supply chain, any component including firmware, operating systems, applications, libraries, and the hardware 
components they run on, can and should be tracked. Dependency-Track is capable of tracking and analyzing each of
these components.

The analysis of metadata describing hardware is currently possible, although limited. This capability will be expanded 
in future versions of the platform.