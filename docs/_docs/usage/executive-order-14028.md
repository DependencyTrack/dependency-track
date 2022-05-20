---
title: U.S. Executive Order 14028
category: Usage
chapter: 2
order: 6
---

Since its inception in 2013, OWASP Dependency-Track has been at the forefront of analyzing bill of materials for cybersecurity
risk identification and reduction. Dependency-Track allows organizations and governments to operationalize SBOM in
conformance with [U.S. Executive Order 14028](https://www.whitehouse.gov/briefing-room/presidential-actions/2021/05/12/executive-order-on-improving-the-nations-cybersecurity/).

* Supports the OWASP CycloneDX BOM format specifically defined in the [NTIA Minimum Elements For a Software Bill of Materials(SBOM)](https://www.ntia.gov/files/ntia/publications/sbom_minimum_elements_report.pdf)
* Consumes and analyzes SBOMs for known security, operational, and license risk
* Ideal for use in [procurement](../procurement) and [continuous integration and delivery](../cicd) environments
* Supports the OWASP CycloneDX VEX format exceeding the [Vulnerability Exploitability Exchange requirements defined by CISA](https://www.cisa.gov/sites/default/files/publications/VEX_Use_Cases_Document_508c.pdf)

### For software consumers

* Tracks all systems and applications that have SBOMs
* Upload SBOMs through the user interface or via automation
* Components defined in SBOMs will be analyzed for known vulnerabilities using multiple sources of vulnerability intelligence, including the [NVD](https://nvd.nist.gov/)
* Displays all identified vulnerabilities and vulnerable components for every SBOM analyzed
* Upload CycloneDX VEX obtained from suppliers to gain insight into the vulnerable components that pose risk, and the ones that don't
* Quickly identify all systems and applications that have a specific component or are affected by a specific vulnerability
* Helps to prioritize mitigation by incorporating support for the [Exploit Prediction Scoring System (EPSS)](https://www.first.org/epss/)
* Evaluate the portfolio of systems and applications against user-configurable security, operational, and license policies

### For software producers

* Create and consume CycloneDX SBOMs in development pipelines
* SBOMs will be analyzed for known security, operational, and license risk
* Evaluates the portfolio of applications against user-configurable security, operational, and license policies
* Inspect security findings and make audit decisions about the relevance and exploitability of each vulnerability
* CycloneDX BOMs can be dynamically generated from current inventory for any application
* CycloneDX VEX is dynamically generated from audit decisions for each application
* An API-first design allows software producers to extract SBOMs for released products, produce VEX whenever updated audit decisions are made, and make data available to internal systems responsible for SBOM and VEX distribution.


### Other considerations

* Both CycloneDX and Dependency-Track are full-stack solutions supporting software, hardware, and services. The CycloneDX standard and use with Dependency-Track is not limited to SBOM use cases.
* Software consumers may optionally audit security findings from vendor SBOMs. If consumers discover discrepancies in vendor supplied VEX, consumers can share their own auto-generated VEX with suppliers, completing a bi-directional exchange of vulnerability and exploitability information.
