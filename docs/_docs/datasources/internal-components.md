---
title: Internal Components
category: Datasources
chapter: 4
order: 7
---

Organizations have the ability to specify a namespace and/or name which represents internally
developed components. Components identified as internal will not be analyzed using external 
sources of vulnerability intelligence or external repositories. With this option configured, 
it is possible, for example, to skip the analysis of internal components via OSS Index, NPM Audit, 
Maven Central, and npm.js. Organizations that have a unique namespace and/or name which does
not conflict with known third-party namespaces and/or names, may opt to define internal components
if the disclosure of such information is not desirable.

> By default, components are not identified as internal.

![configure internal components](/images/screenshots/configure-internal-components.png)
