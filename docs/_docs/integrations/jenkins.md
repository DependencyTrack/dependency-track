---
title: Jenkins
category: Integrations
chapter: 5
order: 3
---

The [Dependency-Track Jenkins plugin] can publish CycloneDX or SPDX bill-of-material formats, or Dependency-Check XML 
reports, to Dependency-Track.

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

[Dependency-Track Jenkins plugin]: https://wiki.jenkins.io/display/JENKINS/OWASP+Dependency-Track+Plugin
