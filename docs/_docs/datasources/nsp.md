---
title: Node Security Platform
category: Datasources
chapter: 3
order: 2
---

Node Security Platform contains a number of Javascript vulnerabilities, specific to the Node.js 
platform and supported libraries, that may or may not be documented in the National Vulnerability Database.
Projects that leverage Node.js will benefit from the Node.js datasource as it provides visibility on
vulnerabilities specific to the ecosystem.

Dependency-Track integrates with NSP using it's public API. In doing so, Dependency-Track is able
to create a mirror of all NSP data. The mirror is kept up-to-date on a daily basis, or upon the restarting
of the Dependency-Track instance.

Credit is provided to the Node Security Platform with visual and textual cues on where the data originated.
Links back to the original NSP advisories are also provided.
