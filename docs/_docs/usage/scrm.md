---
title: Supply Chain Risk Management
category: Usage
chapter: 2
order: 3
---

The process of tracking, managing, and continuously evaluating metrics and risk is at the core of
[Cyber Supply Chain Risk Management](https://csrc.nist.gov/Projects/Supply-Chain-Risk-Management) programs. 

![components](/images/screenshots/components.png)

> Dependency-Track fulfills much of the guidance laid out in [NIST SP 800-161](https://csrc.nist.gov/publications/detail/sp/800-161/final).

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

#### Internet of Things (IoT)

In a supply chain, any component including firmware, operating systems, applications, libraries, and the hardware 
components they run on, can and should be tracked. Dependency-Track is capable of tracking and analyzing each of
these components.

The analysis of metadata describing hardware is currently possible, although limited. This capability will be expanded 
in future versions of the platform.