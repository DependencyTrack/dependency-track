---
title: Introduction
---

Dependency-Track is an intelligent [Component Analysis] platform that allows organizations to 
identify and reduce risk in the software supply chain. Dependency-Track takes a unique
and highly beneficial approach by leveraging the capabilities of [Software Bill of Materials] (SBOM). This approach 
provides capabilities that traditional Software Composition Analysis (SCA) solutions cannot achieve.

Dependency-Track monitors component usage across all versions of every application in its portfolio in order to 
proactively identify risk across an organization. The platform has an API-first design and is ideal for use in 
CI/CD environments.

![dashboard](images/screenshots/dashboard.png)

## Features
* Consumes and produces [CycloneDX] Software Bill of Materials (SBOM)
* Consumes and produces CycloneDX Vulnerability Exploitability Exchange (VEX)
* Component support for:
  * Applications
  * Libraries
  * Frameworks
  * Operating systems
  * Containers
  * Firmware
  * Files
  * Hardware
  * Services
* Tracks component usage across every application in an organizations portfolio
* Quickly identify what is affected, and where
* Identifies multiple forms of risk including
  * Components with known vulnerabilities
  * Out-of-date components
  * Modified components
  * License risk
  * More coming soon...
* Integrates with multiple sources of vulnerability intelligence including:
  * [National Vulnerability Database] (NVD)
  * [GitHub Advisories]
  * [Sonatype OSS Index]
  * [Snyk]
  * [OSV]
  * [VulnDB] from [Risk Based Security]
  * More coming soon.
* Helps to prioritize mitigation by incorporating support for the [Exploit Prediction Scoring System (EPSS)]
* Maintain a private vulnerability database of vulnerability components
* Robust policy engine with support for global and per-project policies
  * Security risk and compliance
  * License risk and compliance
  * Operational risk and compliance
* Ecosystem agnostic with built-in repository support for:
  * Cargo (Rust)
  * Composer (PHP)
  * Gems (Ruby)
  * Hex (Erlang/Elixir)
  * Maven (Java)
  * NPM (Javascript)
  * NuGet (.NET)
  * Pypi (Python)
  * More coming soon.
* Identifies APIs and external service components including:
  * Service provider
  * Endpoint URIs
  * Data classification
  * Directional flow of data
  * Trust boundary traversal
  * Authentication requirements
* Includes a comprehensive auditing workflow for triaging results
* Configurable notifications supporting Slack, Microsoft Teams, Mattermost, Webhooks, Email and Jira
* Supports standardized SPDX license ID’s and tracks license use by component
* Easy to read metrics for components, projects, and portfolio
* Native support for Kenna Security, Fortify SSC, ThreadFix, and DefectDojo
* API-first design facilitates easy integration with other systems
* API documentation available in OpenAPI format
* OAuth 2.0 + OpenID Connect (OIDC) support for single sign-on (authN/authZ)
* Supports internally managed users, Active Directory/LDAP, and API Keys
* Simple to install and configure. Get up and running in just a few minutes

[National Vulnerability Database]: https://nvd.nist.gov
[GitHub Advisories]: https://www.github.com/advisories
[Sonatype OSS Index]: https://ossindex.sonatype.org
[Snyk]: https://snyk.io
[OSV]: https://osv.dev
[VulnDB]: https://vulndb.cyberriskanalytics.com
[Risk Based Security]: https://www.riskbasedsecurity.com
[Component Analysis]: https://owasp.org/www-community/Component_Analysis
[Software Bill of Materials]: https://owasp.org/www-community/Component_Analysis#software-bill-of-materials-sbom
[CycloneDX]: https://cyclonedx.org
[Exploit Prediction Scoring System (EPSS)]: https://www.first.org/epss/
