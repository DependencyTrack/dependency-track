---
title: Private Vulnerability Repository
category: Datasources
chapter: 4
order: 10
redirect_from:
  - /usage/private-vuln-repo/
---

Dependency-Track has the ability to maintain its own repository of internally managed vulnerabilities. The private
repository behaves identically to other sources of vulnerability intelligence such as the NVD.

There are three primary use cases for the private vulnerability repository:

* Organizations that wish to track vulnerabilities in internally-developed components shared among various software projects in the organization.
* Organizations performing security research that have a need to document said research before optionally disclosing it.
* Organizations that are using unmanaged sources of data to identify vulnerabilities. This includes:
    * Change logs
    * Commit logs
    * Issue trackers
    * Social media posts

### Creating Vulnerabilities

> Creating vulnerabilities requires the `VULNERABILITY_MANAGEMENT` permission.

To create vulnerabilities, navigate to the *Vulnerabilities* view, and click the *Create Vulnerability* button.
A dialog will appear where vulnerability details can be configured.

![Create Vulnerability dialog](/images/screenshots/create-vuln.png)

Vulnerabilities tracked in the private vulnerability repository have a source of `INTERNAL`. Like all vulnerabilities
in the system, a unique *Vulnerability ID* is required to help uniquely identify each one. It's recommended that
organizations follow patterns to help identify the source. For example, vulnerabilities in the NVD all start with `CVE-`.
Likewise, an organization tracking their own may opt to use something like `ACME-`, or `INT-`, or use multiple qualifiers
depending on the type of vulnerability. The only requirement is that the ID is unique to the `INTERNAL` source.

Per default, Dependency-Track will generate vulnerability IDs with the prefix `INT`, followed by three blocks of four 
alphanumeric characters, separated by hyphens. For example `INT-td11-7hzm-qzot`, as shown in the screenshot above.

#### Risk Ratings and Severity

Severities can be set explicitly, or alternatively derived from [CVSS] or [OWASP Risk Rating] scores. CVSSv2, CVSSv3,
and OWASP Risk Rating vectors can be defined through a simple user interface. Once all metric groups of a rating
are provided, Dependency-Track will calculate the respective base- and sub-scores, and derive a severity from them.

![Defining a CVSSv3 rating for an internal vulnerability](/images/screenshots/create-vuln_cvss.png)

To derive the severity, Dependency-Track will:

* Prefer CVSSv3 over CVSSv2 ratings, when both are provided
* Prefer the rating with the highest severity, when both CVSS and OWASP Risk Rating are provided

#### Description and Details

The fields *Description*, *Details*, *Recommendation*, and *References* are intended to inform users about the
vulnerability. *Description* should give a high-level overview, allowing users to grasp the problem and its risk,
whereas *Details* may be used to provide a more in-depth description, like documenting the vulnerability's root cause. 
Via *Recommendation*, instructions for remediation or mitigation of the vulnerability may be provided. 
*References* may hold a list of related external links. All of these fields may contain Markdown, which will be rendered
on the vulnerability's overview page.

![Overview page of the internal vulnerability](/images/screenshots/create-vuln_overview.png)

*Title*, *Description*, and *Recommendation* will be displayed in the *Audit Vulnerabilities* tab of projects affected by the vulnerability.

![Internal vulnerability displayed in Audit Vulnerabilities view](/images/screenshots/create-vuln_audit.png)

#### Affected Components

In order for internal vulnerabilities to be picked up by Dependency-Track's vulnerability scanner, *Affected Components*
must be configured. This is done by providing an identifier ([Package URL] or [CPE]), and specifying either an exact version,
or version range. Multiple versions and version ranges may be provided.

> Dependency-Track will not automatically convert between Package URL and CPE. Users are advised to use identifier types
> that will match the data they ingest. Most BOM generators today will provide Package URLs, but not CPEs.  

##### Version Ranges

The version type *Range* allows for version ranges to be specified. Version ranges can have a lower (`>`, `>=`), 
and an upper bound (`<`, `<=`). Versions falling between those bounds will be considered vulnerable. Providing only 
lower, or only upper bound is supported, too. 

When using ranges in combination with Package URL, providing a version in the Package URL is not necessary. 
The following will mark all versions lower than `1.2.3` of `pkg:maven/com.example/example-lib` as vulnerable:

![Defining Affected Components using version ranges](/images/screenshots/create-vuln_affected-components_range.png)

##### Exact Versions

To label specific component versions as vulnerable, the version type *Exact* may be used. In this case, the Package URL
or CPE provided as identifier MUST contain a version. The following will mark version `1.1.0` of `pkg:maven/com.example/auth-lib`
as vulnerable:

![Defining Affected Components using exact versions](/images/screenshots/create-vuln_affected-components_exact.png)

[CPE]: https://csrc.nist.gov/projects/security-content-automation-protocol/specifications/cpe
[CVSS]: https://www.first.org/cvss/specification-document
[OWASP Risk Rating]: https://owasp.org/www-community/OWASP_Risk_Rating_Methodology
[Package URL]: https://github.com/package-url/purl-spec