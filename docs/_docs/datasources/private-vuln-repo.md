---
title: Private Vulnerability Repository
category: Datasources
chapter: 4
order: 9
redirect_from:
  - /usage/private-vuln-repo/
---

> This feature was experimental in Dependency-Track v3.x and is not yet available in Dependency-Track v4.x

Dependency-Track has the ability to maintain its own repository of internally managed vulnerabilities. The private
repository behaves identically to other sources of vulnerability intelligence such as the NVD.

![add vulnerability](/images/screenshots/vulnerability-add.png)

There are three
primary use cases for the private vulnerability repository.

* Organizations that wish to track vulnerabilities in internally-developed components shared among various software projects in the organization.
* Organizations performing security research that have a need to document said research before optionally disclosing it.
* Organizations that are using unmanaged sources of data to identify vulnerabilities. This includes:
    * Change logs
    * Commit logs
    * Issue trackers
    * Social media posts

Vulnerabilities tracked in the private vulnerability repository have a source of 'INTERNAL'. Like all vulnerabilities
in the system, a unique `VulnID` is required to help uniquely identify each one. It's recommended that organizations 
follow patterns to help identify the source. For example, vulnerabilities in the NVD all start with 'CVE-'. Likewise
an organization tracking their own may opt to use something like 'ACME-' or 'INT-' or use multiple qualifiers depending
on the type of vulnerability. The only requirement is that the VulnID is unique to the INTERNAL source.
