---
title: Snyk
category: Datasources
chapter: 4
order: 5
---

[Snyk](https://security.snyk.io) is a platform allowing you to scan, prioritize, and fix security vulnerabilities in your own code, open source dependencies, container images, and Infrastructure as Code (IaC) configurations.

It is a developer security platform. Integrating directly into development tools, workflows, and automation pipelines, Snyk makes it easy for teams to find, prioritize, and fix security vulnerabilities in code, dependencies, containers, and infrastructure as code. Supported by industry-leading application and security intelligence, Snyk puts security expertise in any developer's toolkit.

Dependency-Track integrates with Snyk using its [REST API](https://apidocs.snyk.io/). Dependency-Track does not mirror Snyk entirely,
but it does consume vulnerabilities on a 'as-identified' basis.

The Snyk integration is disabled by default.

### Authentication

User must get API token from Snyk. You can find your token in your [General Account Settings](https://snyk.io/account/) after you register with Snyk and log in. See [Authentication for API](https://docs.snyk.io/snyk-api-info/authentication-for-api).

Provide the token (**without** 'token' prefixed) in the configuration as shown below.

### Configuration

**Organization ID** can be set at in the [Settings](https://docs.snyk.io/products/snyk-code/cli-for-snyk-code/before-you-start-set-the-organization-for-the-cli-tests/finding-the-snyk-id-and-internal-name-of-an-organization) page of the Organization on the Web UI.

**Snyk base URL** is set by default, can be changed per requirement.

**Snyk API version** is set by default to latest version. It is updated every 6 months and might get expired causing API communication failure in which case it will be updated in next upcoming DT release.
User can change it manually here. Please refer [API](https://apidocs.snyk.io/?version=2022-10-06#overview) to submit the correct version.
**Number of threads for Snyk Analyzer to use** Snyk analyzer is implemented with multithreading model to complete the analysis faster. The number of threads that would be used is configurable. By default, it is set to 10. The value can be overridden by exporting this environment variable: `SNYK_THREAD_BATCH_SIZE`. The value can be set based on the configuration of the machine. 

![](../../images/snyk-configuration.png)

### Understanding Snyk's CVSS analysis

The majority of vulnerabilities published by Snyk originate from proprietary research, public information sources, or through 3rd party disclosures.

When evaluating the severity of a vulnerability, it's important to note that there is no single CVSS vector - there are multiple CVSS vectors defined by multiple vendors, with the National Vulnerability Database (NVD) being one of them.

**NOTE:** For Beta version, user can select either from NVD or SNYK to prioritize the cvss vectors.