---
title: Impact Analysis
category: Usage
chapter: 2
order: 3
---

Organizations can analyze the potential for impact of a vulnerability in their environment.
Dependency-Track can help identify all affected projects across the organization. If the vulnerability is published 
to a datasource Dependency-Track supports (i.e. NVD, NPM, OSS Index, VulnDB, etc), then simply looking up the 
vulnerability in the platform is all that's required.

Using Dependency-Track can help organizations answer two important questions:
- What is affected?
- Where am I affected?

![vulnerability](/images/screenshots/vulnerability.png)

Dependency-Track contains a full mirror for each of the vulnerability datasources it supports. Virtually all public
information about the vulnerability including the description, affected versions, CWE, and severity, are captured,
as well as the affected projects. The list of affected projects is dynamically generated based on data in 
Dependency-Track at the time of inquiry. 

![affected projects](/images/screenshots/vulnerability-affected-projects.png)

Alternatively, if the component name and version are known, then performing a search on that component will
reveal a list of vulnerabilities, as well as a list of all projects that have a dependency on the component.

![incident response](/images/screenshots/vulnerable-component.png)
