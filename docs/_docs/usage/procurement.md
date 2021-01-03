---
title: Procurement
category: Usage
chapter: 2
order: 5
---

Dependency-Track is an ideal choice for vendor risk assessments and identifying potential risk in third-party software 
during and after procurement.

The ability for vendors to generate Software Bill of Materials (SBOM) demonstrates a certain level of organizational 
maturity. Vendors that have the capability to provide SBOMs in supported formats may have lower risk than vendors unable 
to do so. The [OWASP Software Component Verification Standard (SCVS)](https://owasp.org/scvs) provides guidance on 
measuring and improving software supply chain assurance. The guidance includes foundational SBOM requirements as well as
guidance for supplier evaluation.

Once obtained, SBOMs can be manually uploaded to Dependency-Track for analysis. First, create a new project that 
corresponds to the software and version being procured. Then, upload the SBOM for analysis.

This will provide complete visibility of component inventory, vulnerabilities, outdated component status, and 
policy violations. If the software being procurred will eventually be deployed to production, simply keep the project
active in Dependency-Track so that visibility of risk can continue to be tracked. If the software will not be procured, simply
delete the project.
