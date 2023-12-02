---
title: Trivy
category: Datasources
chapter: 4
order: 6
---

[Trivy](https://www.aquasec.com/products/trivy/) is a tool provided by aquas allowing you to scan for vulnerabilities.

Dependency-Track integrates with Trivy using its undocumented REST API.

The Trivy integration is disabled by default.

### Configuration

To configure the Trivy integration, navigate to *Analyzers* -> *Trivy* in the administration panel.

|:---|:----|
| Base URL | Base URL of the Trivy REST API. Defaults to `http://localhost:8081`. |
| API Token | Authentication token for the REST API. |

![Trivy Configuration](../../images/screenshots/trivy-configuration.png)
