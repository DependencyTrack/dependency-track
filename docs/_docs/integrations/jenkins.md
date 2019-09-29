---
title: Jenkins
category: Integrations
chapter: 6
order: 4
---

The [Dependency-Track Jenkins plugin] aids in publishing [CycloneDX] and [SPDX] Bill-of-Materials (BOM) 
to Dependency-Track.

Publishing BOMs can be performed asynchronously or synchronously.

> Asynchronous publishing simply uploads the BOM to Dependency-Track and the job continues. Synchronous publishing
waits for Dependency-Track to process the BOM after being uploaded. Synchronous publishing has the benefit of 
displaying interactive job trends and per build findings.

![Job Trending](/images/screenshots/jenkins-job-trend.png)
![Job Findings](/images/screenshots/jenkins-job-findings.png)

### Job Configuration
Once configured with a valid URL and API key, simply configure a job to publish the artifact.

![Job Publish Config](/images/screenshots/jenkins-job-publish.png)

* **Dependency-Track project**: Specifies the unique project ID to upload scan results to. This dropdown will be
automatically populated with a list of projects.

* **Artifact**: Specifies the file to upload. Paths are relative from the Jenkins workspace.

* **Artifact Type**: Options are:
  * Software Bill of Material (CycloneDX or SPDX) 
  
* **Synchronous mode**: Uploads a BOM to Dependency-Track and waits for Dependency-Track to process and return results.
The results returned are identical to the auditable findings but exclude findings that have previously been suppressed. 
Analysis decisions and vulnerability details are included in the response. Synchronous mode is possible with 
Dependency-Track v3.3.1 and higher.
  
![Job Publish Thresholds](/images/screenshots/jenkins-job-thresholds.png)
 
When Synchronous mode is enabled, thresholds can be defined which can optionally put the job into an UNSTABLE or FAILURE state.

* **Total Findings**: Sets the threshold for the total number of critical, high, medium, or low severity findings 
allowed. If the number of findings equals or is greater than the threshold for any one of the severities, the job status
 will be changed to UNSTABLE or FAILURE.

* **New Findings**: Sets the threshold for the number of new critical, high, medium, or low severity findings allowed. 
If the number of new findings equals or is greater than the previous builds finding for any one of the severities, the 
job status will be changed to UNSTABLE or FAILURE.
 
### Global Configuration
To setup, navigate to **Jenkins &raquo; System Configuration** and complete the Dependency-Track section.

![System Configuration](/images/screenshots/jenkins-global-odt.png)

### Permissions
The following permission should be assigned to the API key configured above.

| Permission | Description |
| ------|-------------|
| BOM_UPLOAD | Allows the uploading of CycloneDX and SPDX BOMs |
| VIEW_PORTFOLIO | Allows the plugin to list the projects in the dropdown |
| VULNERABILITY_ANALYSIS | Allows access to the findings API for trending and results (synchronous mode only) |
| PROJECT_CREATION_UPLOAD | Allows the dynamic creation of projects (if enabled by the plugin) |


[CycloneDX]: https://cyclonedx.org
[SPDX]: https://spdx.org
[Dependency-Track Jenkins plugin]: https://plugins.jenkins.io/dependency-track
