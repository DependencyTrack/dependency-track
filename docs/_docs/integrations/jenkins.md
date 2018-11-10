---
title: Jenkins
category: Integrations
chapter: 5
order: 3
---

The [Dependency-Track Jenkins plugin] aids in publishing [CycloneDX] and [SPDX] Bill-of-Material (BoM) documents as 
well as Dependency-Check XML reports to the Dependency-Track platform.

Publishing BoMs can be performed asynchronously or synchronously.

> Asynchronous publishing simply uploads the BoM to Dependency-Track and the job continues. Synchronous publishing
waits for Dependency-Track to process the BoM after being uploaded. Synchronous publishing has the benefit of 
displaying interactive job trends and per build findings.

![Job Trending](/images/screenshots/jenkins-job-trend.png)
![Job Findings](/images/screenshots/jenkins-job-findings.png)

### Job Configuration
Once configured with a valid URL and API key, simply configure a job to publish the artifact.

![System Configuration](/images/screenshots/jenkins-job-publish.png)

* **Dependency-Track project**: Specifies the unique project ID to upload scan results to. This dropdown will be
automatically populated with a list of projects.

* **Artifact**: Specifies the file to upload. Paths are relative from the Jenkins workspace.

* **Artifact Type**: Options are:
  * Software Bill of Material (CycloneDX or SPDX) 
  * Dependency-Check Scan Result (XML)
  
* **Synchronous mode**: Uploads a BoM to Dependency-Track and waits for Dependency-Track to process and return results.
The results returned are identical to the auditable findings but exclude findings that have previously been suppressed. 
Analysis decisions and vulnerability details are included in the response. Synchronous mode is possible with 
Dependency-Track v3.3.1 and higher.
  
### Global Configuration
To setup, navigate to **Jenkins &raquo; System Configuration** and complete the Dependency-Track section.

![System Configuration](/images/screenshots/jenkins-global-odt.png)

[CycloneDX]: https://cyclonedx.org
[SPDX]: https://spdx.org
[Dependency-Track Jenkins plugin]: https://wiki.jenkins.io/display/JENKINS/OWASP+Dependency-Track+Plugin
