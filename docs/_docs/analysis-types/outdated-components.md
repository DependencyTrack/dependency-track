---
title: Outdated Component Analysis
category: Analysis Types
chapter: 3
order: 2
---

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
from various repositories. Dependency-Track relies on Package URL (PURL) to identify the ecosystem a component belongs 
to, the metadata about the component, and uses that data to query the various repositories capable of supporting the 
components ecosystem. Refer to [Repositories]({{ site.baseurl }}{% link _docs/datasources/repositories.md %}) for 
further information.
