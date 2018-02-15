---
title: Jenkins
category: Integrations
chapter: 5
order: 3
---

The [Dependency-Check Jenkins plugin] includes a publisher which can be configured to push Dependency-Check 
XML reports or CycloneDX and SPDX bill-of-material documents to Dependency-Track.

### Global Config
To setup, navigate to **Jenkins &raquo; System Configuration** and complete the Dependency-Track section.

![System Configuration](/images/screenshots/jenkins-global-odt.png)

### Job Config
Once configured with a valid URL and API key, simply configure a job to publish the artifact.

![System Configuration](/images/screenshots/jenkins-job-odt-publish.png)

* **Dependency-Track project**: Specifies the unique project ID to upload scan results to. This dropdown will be
automatically populated with a list of projects.

* **Artifact**: Specifies the file to upload. Paths are relative from the Jenkins workspace.

* **Artifact Type**: Options are:
  * Dependency-Check Scan Result (XML)
  * Software Bill of Material (CycloneDX or SPDX) 

[Dependency-Check Jenkins plugin]: https://wiki.jenkins.io/display/JENKINS/OWASP+Dependency-Check+Plugin
