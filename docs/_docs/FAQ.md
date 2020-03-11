---
title: Frequently Asked Questions
category: FAQ
chapter: 10
order:
---

Frequently asked questions about Dependency Track functionality that may not be covered by the documentation. If you don't find an answer here, try reaching out to the Slack channel related to dependency track.
<!--A link will be added later when we're done to directly take the reader to the slack channel-->

#### Dependency Check and Dependency Track Comparison

This topic is heavily explained in the [Dependency Check Comparison](./../odt-odc-comparison/) to Dependency Track.

#### I expect to see vulnerable components but I don't

Most common reason: You have to enabled the [Sonatype OSS Index Analyzer](./../datasources/ossindex/). It is not
enabled by default but is necessary to scan dependencies represented by
[Package URLs](./../terminology/#package-url-purl).

#### Why is Sonatype OSS Index Analyzer disabled by default?

Sonatype OSS Index Analyzer is disabled because you need an account and need to configure it first. See
[Sonatype OSS Index Analyzer](./../datasources/ossindex/).

#### Why is the local NVD mirror not used?

The local NVD mirror is used for dependencies that are identified by a [CPE](./../terminology/#cpe). These are mostly
components like operating systems, applications, and hardware. That's what CPE was designed to represent.  
[Package URLs](./../terminology/#package-url-purl) (PURL) on the other hand are designed to represent all kinds of software
dependencies like packages, libraries, and frameworks. In the local mirror there is no mapping from the PURL to CPE/CVE.  
So the local mirror is used, but not for dependencies represented by PURL. Dependency Track will use the Analyzer best
suited to analyze a given dependency.

