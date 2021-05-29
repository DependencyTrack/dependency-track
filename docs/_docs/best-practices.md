---
title: Best Practices
category: Best Practices
chapter: 9
order: 
---

#### Summary
BOMs are a statement of facts, and the type of facts a BOM has will greatly impact
how effective the system will be when performing component risk analysis.

### Generating and Obtaining BOMs
* When developing software, generate BOMs during Continuous Integration (CI)
* If using Jenkins, use the [Dependency-Track Jenkins Plugin](https://plugins.jenkins.io/dependency-track/) with synchronous publishing mode enabled
* Contractually require BOMs ([CycloneDX](https://cyclonedx.org) from vendors
* Generate or acquire BOMs from commercial-off-the-shelf (COTS) software

#### Summary
The ability for an organization to generate a complete bill-of-material during continuous 
integration is one of many maturity indicators. BOMs are increasingly required for various
compliance, regulatory, legal, or economic reasons.

### Analyzers
* Enable Internal Analyzer
* Enable NPM Audit
* Enable OSS Index

#### Summary
Sonatype OSS Index and NPM Audit provides accurate vulnerability information for application dependencies.
All components in the portfolio should have valid Package URLs to take advantage of OSS Index and NPM Audit.
Non-application dependencies such as operating systems, hardware, firmware, etc, should have valid CPEs to
take advantage of the internal CPE analyzer.

### Leverage APIs and Integrations
* Make findings actionable by leveraging Webhooks (via [notifications]({{ site.baseurl }}{% link _docs/integrations/notifications.md %}))
* Automate response to various events if necessary
* Leverage vulnerability aggregation capabilities of:
    * [Fortify Software Security Center]({{ site.baseurl }}{% link _docs/integrations/fortify-ssc.md %})
    * [Kenna Security]({{ site.baseurl }}{% link _docs/integrations/kenna.md %})
    * [ThreadFix]({{ site.baseurl }}{% link _docs/integrations/threadfix.md %})
* Leverage ChatOps (via [notifications]({{ site.baseurl }}{% link _docs/integrations/notifications.md %})) to keep teams informed

#### Summary
Findings in Dependency-Track are intended to be a source-of-truth, but they're not meant to be kept
in a silo. Dependency-Track has an API-first design intended to promote integration with other systems.
By leveraging these capabilities, organizations benefit from increased software transparency and ultimately 
reduce risk to stakeholders.
