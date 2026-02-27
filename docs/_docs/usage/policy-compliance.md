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
* **License**
* **Security**
* **Operational**

---

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

**Subjects under License policies:**
- **LICENSE** → Checks for a specific declared license on a component.
- **LICENSE GROUP** → Checks whether the license belongs to a defined license group (e.g., Copyleft, Non-commercial, Permissive, Weak Copyleft).

---

## Security Violation
Policy conditions can specify the severity of vulnerabilities. A vulnerability affecting a component can result in a 
policy violation if the policy condition matches the severity of the vulnerability. Vulnerabilities that are suppressed
will not result in a policy violation.

**Subjects under Security policies:**
- **CWE** → Identifies violations based on Common Weakness Enumeration identifiers.
- **SEVERITY** → Triggers when vulnerability severity (e.g., Critical, High) meets the policy condition.
- **VULNERABILITY ID** → Matches specific vulnerability identifiers.
- **EPSS** → Uses the Exploit Prediction Scoring System score to assess exploit likelihood.

---

## Operational Violation
This allows organizations to create lists of allowable and/or prohibited components. Future versions
of Dependency-Track will incorporate additional operational parameters into the policy framework.

**Subjects under Security policies:**
- **AGE** → Enforces policies based on the Finding’s age (e.g., older than N days). Age in ISO-8601 period format (e.g. P1Y = 1 Year; P2Y3M = 2 Years, 3 Months)
- **COORDINATES** → Matches a component using its group, name, and version identifiers.
- **PACKAGE URL (purl)** → Applies conditions based on the package URL (purl) of a component.
- **Common Platform Enumeration (CPE)** → Checks components using their CPE identifier.
- **SWID Tag ID** → Targets components identified by their Software Identification (SWID) tag ID.
- **COMPONENT HASH** → Enforces policies using a component’s cryptographic hash (e.g., MD5, SHA, SHA3, Blake2b, Blake3).
- **VERSION** → Evaluates policies against a component’s version number.
- **VERSION DISTANCE** → Compares the version difference from the available release (Epoch, Major, Minor, Patch).

---