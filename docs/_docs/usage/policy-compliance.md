---
title: Policy Compliance
category: Usage
chapter: 2
order: 4
---

Organizations can create policies and measure policy violations across the portfolio, and against individual 
projects and components. Policies are configurable and can be enforced for the portfolio, or can be 
limited to specific projects.

There are three types of policy violations:
* License
* Security (coming in v4.1)
* Operational

## License Violation
Policy conditions can specify zero or more SPDX license IDs as well as license groups. Dependency-Track comes with
pre-configured groups of related licenses (e.g. Copyleft) that provide a starting point for organizations to create
custom license policies.

## Security Violation
Coming in v4.1

## Operational Violation
Policy conditions can specify zero or more:
* Coordinates (group, name, version)
* Package URL
* CPE
* SWID Tag ID
* Hash (MD5, SHA, SHA3, Blake2b, Blake3)

This allows organizations to create lists of allowable and/or prohibited components. Future versions
of Dependency-Track will incorporate additional operational parameters into the policy framework.
