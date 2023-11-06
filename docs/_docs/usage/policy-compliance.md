---
title: Policy Compliance
category: Usage
chapter: 2
order: 4
---

Organizations can create policies and measure policy violations across the portfolio, and against individual 
projects and components. Policies are configurable and can be enforced for the portfolio, or can be 
limited to specific projects. Policies are evaluated when an SBOM is uploaded.

There are three types of policy violations:
* License
* Security
* Operational

## License Violation
If you want to check whether the declared licenses of the components in a project are compatible with guidelines that
exist in your organization, it is possible to add license violation conditions to your Policy.

To check a rule that certain licenses are allowed, you can add those licenses to a license group, called for example
'Allowed licenses', and create a license violation condition "License group is not 'Allowed licenses'" that reports a
violation if any of the components are not available under licenses from the 'Allowed licenses' group.

Conversely, if there are some licenses that are not allowed by your organization's rules,
you can add them to a license group, called for example 'Forbidden licenses', and create a license violation condition
"License group is 'Forbidden licenses'" that reports a violation if any of the components are only available under licenses
from the 'Forbidden licenses' group.
To forbid or exclusively allow individual licenses, license violation conditions like "License is Apache-2.0" or
"License is not MIT" can be added as well.

For components that are licensed under a combination of licenses, like dual licensing, this can be
captured in an [SPDX expression](https://spdx.github.io/spdx-spec/v2-draft/SPDX-license-expressions/), which can be
specified for the components. If your project includes such components, and you set up a
"License group is 'Forbidden licenses'" violation condition, then a violation is reported only when all choices of license
combinations allowed by the SPDX expression would lead to a license from the 'Forbidden licenses' list being used.
For a violation condition like "License group is not 'Allowed licenses'", a violation is reported when all choices of
license combinations according to the SPDX expression would include a license that does not appear in the
'Allowed licenses' list.

Dependency-Track comes with pre-configured groups of related licenses (e.g. Copyleft) that provide a starting point for
organizations to create custom license policies.

## Security Violation
Policy conditions can specify the severity of vulnerabilities. A vulnerability affecting a component can result in a 
policy violation if the policy condition matches the severity of the vulnerability. Vulnerabilities that are suppressed
will not result in a policy violation.

## Operational Violation
Policy conditions can specify zero or more:
* Coordinates (group, name, version)
* Package URL
* CPE
* SWID Tag ID
* Hash (MD5, SHA, SHA3, Blake2b, Blake3)

This allows organizations to create lists of allowable and/or prohibited components. Future versions
of Dependency-Track will incorporate additional operational parameters into the policy framework.
