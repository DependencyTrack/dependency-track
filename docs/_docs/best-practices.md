---
title: Best Practices
category: Best Practices
chapter: 8
order: 
---

### Importing and Using BOMs
* For best results, always generate and import [CycloneDX](https://cyclonedx.org) BOMs
* Do not import Dependency-Check XML reports
* Do not import SPDX v2.1 (or previous) BOMs

#### Summary
BOMs are a statement of facts, and the type of facts a BOM has will greatly impact
how effective the system will be when performing component risk analysis.

Dependency-Check operates on evidence, not facts. When Dependency-Check reports are
imported, Dependency-Track attempts to make sense of the evidence and derive certain facts
with reasonable certainly including group/organization, name, and version. Dependency-Check
reports often do not contain license information, nor does Dependency-Check support the
PackageURL specification. Suppressions in Dependency-Check XML reports additionally are not
honored due to a lack of signed audit trail and the fact that suppressions only affect
findings from a single scanner (Dependency-Check).

SPDX BOM format v2.1 and previous do not support PackageURL. When importing SPDX BOMs, 
ensure the format is version 2.2 or higher and contains valid PackageURLs for each component.

### Generating and Obtaining BOMs
* When developing software, generate BOMs during Continuous Integration (CI)
* If using Jenkins, use the [Dependency-Track Jenkins Plugin]({{ site.baseurl }}{% link _docs/integrations/jenkins.md %}) with synchronous publishing mode enabled
* Contractually require BOMs ([CycloneDX](https://cyclonedx.org) or [SPDX](https://spdx.org)) from vendors
* Generate or acquire BOMs from commercial-off-the-shelf (COTS) software

#### Summary
The ability for an organization to generate a complete bill-of-material during continuous 
integration is one of many maturity indicators. BOMs are increasingly required for various
compliance, regulatory, legal, or economic reasons.

### Scanners
* Enable OSSIndex
* Evaluate if Dependency-Check should be enabled or disabled
* Ensure all other scanners are enabled

#### Summary
Sonatype OSSIndex and NPM Audit provides accurate vulnerability information with minimal false positives. 
This allows organizations to have actionable results, faster. If all projects are using CycloneDX BOMs and the
components in those BOMs have valid PackageURLs, then it may be feasible to disable the embedded
Dependency-Check scanner. This will result in fewer false positives, less effort required for auditing
findings, and ultimately more time for development teams to focus on updating vulnerable and outdated 
components. This is especially important for teams that have time-boxed constraints.

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

### More Information
* [Component Analysis](https://www.owasp.org/index.php/Component_Analysis) (OWASP)