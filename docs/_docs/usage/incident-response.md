---
title: Incident Response
category: Usage
chapter: 2
order: 2
---

When a high-impact vulnerability is published, organizations typically follow a formalized incident response plan.
Dependency-Track can help identify all affected projects (applications) in an environment. If the vulnerability
is published to one of the sources of vulnerability intelligence Dependency-Track supports (NVD, NSP, VulnDB, etc),
then simply looking up the vulnerability in Dependency-Track is all that's required.

Dependency-Track contains a full mirror for each of the vulnerability datasources it supports. Virtually all public
information about the vulnerability including the description, affected versions, CWE, and severity, are captured,
as well as the affected projects. The list of affected projects is dynamically generated based on data in 
Dependency-Track at the time of inquiry. If an organization adopts Dependency-Track and ensures that applications 
are being tracked with accurate data, then relying on the 'affected projects' feature can help organizations 
reduce risk faster.