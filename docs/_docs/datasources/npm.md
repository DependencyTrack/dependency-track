---
title: NPM Public Advisories
category: Datasources
chapter: 4
order: 2
redirect_from:
  - /datasources/nsp/
---

NPM public advisories is a centralized source of vulnerability intelligence specific to Javascript and Node.js that may 
or may not be documented in the National Vulnerability Database. Projects that leverage Node.js will benefit from the 
NPM Audit datasource as it provides visibility on vulnerabilities specific to the ecosystem.

Dependency-Track integrates with NPM using it's public advisory API. In doing so, Dependency-Track is able to create a 
mirror of all NPM advisory data. The mirror is kept up-to-date on a daily basis, or upon the restarting of the 
Dependency-Track instance.

Credit is provided to NPM with visual and textual cues on where the data originated. Links back to the original NPM 
advisories are also provided.
