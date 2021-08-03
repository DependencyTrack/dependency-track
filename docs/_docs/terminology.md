---
title: Terminology
category: Terminology
chapter: 11
order:
---


### API Key
A long randomly generated number used to assert authentication. All REST APIs use API keys for authentication. API keys
are assigned on a per-team basis. A team may have zero or more API keys assigned.

### Auditing
The process of evaluating findings to determine the accuracy of the findings and its impact on the component and 
affected projects. The auditing process creates an audit trail that captures the thought process and decisions made 
for each finding.

### Bill of Materials (BOM)
In supply chains, a bill of materials (BOM) defines and describes the contents of what is used in the manufacturing and
packaging of the deliverable. In software supply chains, this refers to the contents of all components bundled with the
software including, authors, publishers, names, versions, licenses, and copyrights. Dependency-Track supports the 
CycloneDX format. Bill of Materials specific to software components are commonly referred to as SBOMs.

### Component
Dependency-Track defines a component as a standalone entity. A component may be an open source component, third-party 
library, first-party library, an operating system, or a hardware device.

### CPE
Common Platform Enumeration (CPE) is a structured naming scheme for information technology systems, software, and 
packages. Based upon the generic syntax for Uniform Resource Identifiers (URI), a CPE typically includes the vendor, 
product name, and version.

### CVE
Common Vulnerabilities and Exposures (CVE&reg;) is a list of common identifiers for publicly known cybersecurity 
vulnerabilities. Assigned by CVE Numbering Authorities (CNAs) from around the world, use of CVE Entries ensures 
confidence among parties when used to discuss or share information about a unique software vulnerability, provides 
a baseline for tool evaluation, and enables data exchange for cybersecurity automation.

### CWE
Common Weakness Enumeration (CWE) is a taxonomy of software security errors that standardizes and categorizes a 
common set of weaknesses.

### CycloneDX
A bill-of-materials (BOM) specification that is lightweight and security focused.
See: <https://cyclonedx.org/>

### Dependency
Dependency-Track defines a dependency as a project that includes a component. Once a component is assigned to a 
project, the component becomes a dependency of that project.

### LDAP User
An LDAP user is an externally managed user that may (optionally) have the ability to login to Dependency-Track.

### License
Refers to how a project or component is licensed. Dependency-Track supports (but does not enforce) the use of SPDX
license IDs so that license names and terms can be automatically resolved when BOMs are imported or components are added.

### Managed User
An internally managed user that has the ability to login to Dependency-Track.

### Package URL (PURL)
PURL or Package URL is a lightweight specification that standardizes the ability to reliably identify and locate 
software packages. PURL is a URI string used to identify and locate a software package in a mostly universal and 
uniform way across programing languages, package managers, packaging conventions, tools, APIs and databases. 
See: <https://github.com/package-url/purl-spec>

### Portfolio
Dependency-Track defines a portfolio as the sum total of all projects defined in the system. When metrics are run 
against the portfolio, the aggregate result from all projects are what the portfolio metrics will display.

### Project
A project is a high-level categorization and collection of components (dependencies once added) along with sub 
projects. A project could represent a software application, an environment, a medical or IoT device, or an automobile.
Vulnerabilities from dependent components and sub projects are reported up to the project level. This is called 
inherited risk.

### Repository
A service for storing open-source and third-party components and other artifacts. Repositories are typically used in
software engineering to provide resolved dependencies during build time and are often accompanied with an API for
programmatic integration. 

### Scan
A scan is method by which evidence about a component is gathered and cross-referenced with one or more vulnerability 
intelligence services in an effort to determine if that component has known vulnerabilities.

### SPDX
Software Package Data Exchange (SPDX) provides a standardized license list that has been adopted 
across multiple industries and is recommended for use in all software projects. See: <https://spdx.org/>

### Swagger
A lightweight REST specification that provides a framework to document the use of REST APIs. 
See: <https://swagger.io/>

### Team
A collection of managed and unmanaged (LDAP) users and API keys.

### Vulnerability
A defect that can potentially lead to a security issue. 
