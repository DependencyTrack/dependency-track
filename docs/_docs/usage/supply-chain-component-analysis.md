---
title: Supply Chain Component Analysis
category: Usage
chapter: 2
order: 3
redirect_from:
  - /usage/scrm/
---

[Component Analysis](https://www.owasp.org/index.php/Component_Analysis), as defined by [OWASP](https://www.owasp.org/), 
is the process of identifying potential areas of risk from the use of third-party and open-source software and hardware 
components. Component Analysis is a function within an overall [Cyber Supply Chain Risk Management](https://csrc.nist.gov/Projects/Supply-Chain-Risk-Management) 
(C-SCRM) framework.

![components](/images/screenshots/components.png)

> Dependency-Track fulfills much of the guidance laid out by [OWASP](https://www.owasp.org/index.php/Component_Analysis) and [SAFECode](https://www.safecode.org/wp-content/uploads/2017/05/SAFECode_TPC_Whitepaper.pdf).

* Tracks application, library, framework, operating system, and hardware components
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
