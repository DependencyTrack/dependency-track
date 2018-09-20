[![Build Status](https://travis-ci.org/DependencyTrack/dependency-track.svg?branch=3.0-dev)](https://travis-ci.org/DependencyTrack/dependency-track) 
[![Codacy Badge](https://api.codacy.com/project/badge/Grade/a1d99b45c27e4d069f94d24bcce8d7e6)](https://www.codacy.com/app/stevespringett/dependency-track?utm_source=github.com&amp;utm_medium=referral&amp;utm_content=DependencyTrack/dependency-track&amp;utm_campaign=Badge_Grade)[![Alpine](https://img.shields.io/badge/built%20on-Alpine-blue.svg)](https://github.com/stevespringett/Alpine)
<img src="https://docs.dependencytrack.org/images/dt.svg" width="300" align="right">
[![License][license-image]][license-url]
[![Website](https://img.shields.io/badge/https://-dependencytrack.org-blue.svg)](https://dependencytrack.org/)
[![Documentation](https://img.shields.io/badge/read-documentation-blue.svg)](https://docs.dependencytrack.org/)
[![Slack](https://img.shields.io/badge/chat%20on-slack-46BC99.svg)](https://owasp.slack.com/messages/proj-dependency-track)
[![Join the chat at https://gitter.im/dependency-track/Lobby](https://badges.gitter.im/dependency-track/Lobby.svg)](https://gitter.im/dependency-track/Lobby?utm_source=badge&utm_medium=badge&utm_campaign=pr-badge&utm_content=badge)
[![Twitter](https://img.shields.io/twitter/url/http/shields.io.svg?style=social&label=Follow)](https://twitter.com/dependencytrack)
[![Downloads](https://img.shields.io/github/downloads/DependencyTrack/dependency-track/total.svg)](https://github.com/DependencyTrack/dependency-track/releases)
[![Latest](https://img.shields.io/github/release/DependencyTrack/dependency-track.svg)](https://github.com/DependencyTrack/dependency-track/releases)
[![Docker Pulls](https://img.shields.io/docker/pulls/owasp/dependency-track.svg)](https://hub.docker.com/r/owasp/dependency-track/)


Dependency-Track
=========

Modern applications leverage the availability of existing components for use as building blocks 
in application development. By using existing components, organizations can dramatically decrease
time-to-market. Reusing existing components however, comes at a cost. Organizations that build on 
top of existing components assume risk for software they did not create. Vulnerabilities in third-party
components are inherited by all applications that use those components. The [OWASP Top Ten] (2013 and 2017)
both recognize the risk of [using components with known vulnerabilities](https://www.owasp.org/index.php/Top_10_2013-A9-Using_Components_with_Known_Vulnerabilities).

Dependency-Track is a Software Composition Analysis (SCA) platform that keeps track of all third-party 
components used in all the applications an organization creates or consumes. It integrates with multiple
vulnerability databases including the [National Vulnerability Database] (NVD), [NPM Public Advisories],
[Sonatype OSS Index], and [VulnDB] from [Risk Based Security]. Dependency-Track monitors all applications 
in its portfolio in order to proactively identify vulnerabilities in components that are placing your 
applications at risk. Use of Dependency-Track can play a vital role in an overall [Cyber Supply Chain Risk Management](https://csrc.nist.gov/Projects/Supply-Chain-Risk-Management) (C-SCRM) 
program by fulfilling many of the recommendations laid out by [SAFECode](https://www.safecode.org/wp-content/uploads/2017/05/SAFECode_TPC_Whitepaper.pdf).

Dependency-Track is designed to be used in an automated DevOps environment where BoM (bill-of-material) formats are 
automatically ingested during CI/CD. Use of the [Dependency-Track Jenkins Plugin] is highly recommended for this purpose 
and is well suited for use in [Jenkins Pipeline]. In such an environment, Dependency-Track enables your DevOps teams to 
accelerate while still keeping tabs on component usage and any inherited risk.

Dependency-Track can also be used to monitor vulnerabilities in COTS (commercial off-the-shelf) software.

**NOTICE: Always use official binary releases in production.**

Ecosystem Overview
-------------------

![alt text](https://raw.githubusercontent.com/stevespringett/dependency-track/master/docs/images/integrations.png)

Features
-------------------

* Increases visibility into the use of vulnerable and outdated components
* Flexible data model supporting an unlimited number of projects and components
* Tracks vulnerabilities and inherited risk
  * by component
  * by project
  * across entire portfolio
* Tracks usage of out-of-date components
* Includes a comprehensive auditing workflow for triaging results
* Configurable notifications supporting Slack, Microsoft Teams, Webhooks, and Email
* Supports standardized SPDX license ID’s and tracks license use by component
* Supports [CycloneDX] and [SPDX] bill-of-material and [Dependency-Check] XML
* Easy to read metrics for components, projects, and portfolio
* Provides a reliable mirror of the NVD data feed
* API-first design facilitates easy integration with other systems
* API documentation available in Swagger 2.0 (OpenAPI 3 support coming soon)
* Supports internally managed users, Active Directory/LDAP, and API Keys
* Simple to install and configure. Get up and running in just a few minutes

Screenshots
-------------------
![alt text](https://raw.githubusercontent.com/stevespringett/dependency-track/master/docs/images/screenshots/dashboard.png)

For more eye-candy, visit <https://dependencytrack.org/>.

Distributions
-------------------

Dependency-Track supports the following three deployment options:

* Docker container
* Executable WAR
* Conventional WAR

Deploying Docker Container
-------------------

Deploying with Docker is the easiest and fastest method of getting started. No prerequisites are required
other than an modern version of Docker. Dependency-Track uses the following conventions:


* The 'latest' tag, which is pulled by default if no tag is specified, will always refer to the latest stable release (3.0.0, 3.0.1, 3.1.0, etc)
* The 'snapshot' tag will be built and pushed on all CI changes to the master. Use this if you want a "moving target" with all the latest changes.
* Version tags (3.0.0, 3.0.1, etc) are used to indicate each release


```shell
docker pull owasp/dependency-track
docker volume create --name dependency-track
docker run -d -p 8080:8080 --name dependency-track -v dependency-track:/data owasp/dependency-track
```

To run snapshot releases (not recommended for production):

```shell
docker pull owasp/dependency-track:snapshot
docker volume create --name dependency-track
docker run -d -p 8080:8080 --name dependency-track -v dependency-track:/data owasp/dependency-track:snapshot
```

In the event you want to delete all Dependency-Track images, containers, and volumes, the following statements 
may be executed. NOTE: This is a destructive operation and cannot be undone.


```shell
docker rmi owasp/dependency-track
docker rm dependency-track
docker volume rm dependency-track:/data
```

Deploying the Executable WAR
-------------------

Another simple way to get Dependency-Track running quickly is to automatically deploy the executable WAR. This
method requires Java 8u101 or higher. Simply download `dependency-track-embedded.war` and execute:

```shell
java -Xmx4G -jar dependency-track-embedded.war
```

Deploying the Conventional WAR
-------------------

This is the most difficult to deploy option as it requires an already installed and configured Servlet 
container such as Apache Tomcat 8.5 and higher, however, it offers the most flexible deployment options.
Follow the Servlet containers instructions for deploying `dependency-track.war`.
 
 
Compiling From Sources (optional)
-------------------

To create an executable WAR that is ready to launch (recommended for most users):

```shell
mvn clean package -P embedded-jetty
```

To create a WAR that must be manually deployed to a modern Servlet container (i.e. Tomcat 8.5+):

```shell
mvn clean package
```

To create an executable WAR that is ready to be deployed in a Docker container:

```shell
mvn clean package -P embedded-jetty -Dlogback.configuration.file=src/main/docker/logback.xml
```

Website
-------------------

The official Dependency-Track website is accessible at: <https://dependencytrack.org/>

Documentation
-------------------

Online documentation is accessible at: <https://docs.dependencytrack.org/>

Community
-------------------

* Twitter: <https://twitter.com/dependencytrack>

* YouTube: <https://www.youtube.com/channel/UC8xdttysl3gNAQYvk1J9Efg>

* Gitter: <https://gitter.im/dependency-track/Lobby>

* Slack: <https://owasp.slack.com/messages/proj-dependency-track>

* Google Groups: <https://groups.google.com/forum/#!forum/dependency-track>


Support
-------------------

Dependency-Track is an open source project, created by people who believe that the knowledge of using 
vulnerable components should be accessible to anyone with a desire to know. By supporting this project, you'll
allow the team to outsource testing, infrastructure, further research and development efforts, and engage in 
outreach to various communities that would benefit from this technology.

[![PayPal](https://www.paypalobjects.com/en_US/i/btn/btn_donate_SM.gif)](https://www.paypal.com/cgi-bin/webscr?cmd=_donations&business=paypal%40owasp%2eorg&lc=US&item_name=OWASP%20Dependency-Track&no_note=0&currency_code=USD&bn=PP%2dDonationsBF)

Copyright & License
-------------------

Dependency-Track is Copyright (c) Steve Springett. All Rights Reserved.

Permission to modify and redistribute is granted under the terms of the 
[Apache License 2.0] [license-url]

Dependency-Track makes use of several other open source libraries. Please see
the [NOTICES.txt] [notices] file for more information.

  [National Vulnerability Database]: https://nvd.nist.gov
  [NPM Public Advisories]: https://www.npmjs.com/advisories
  [Sonatype OSS Index]: https://ossindex.sonatype.org
  [VulnDB]: https://vulndb.cyberriskanalytics.com
  [Risk Based Security]: https://www.riskbasedsecurity.com
  [OWASP Top Ten]: https://www.owasp.org/index.php/Category:OWASP_Top_Ten_Project
  [OWASP Wiki]: https://www.owasp.org/index.php/OWASP_Dependency_Track_Project
  [Dependency-Check]: https://www.owasp.org/index.php/OWASP_Dependency_Check
  [Dependency-Track Jenkins Plugin]: https://wiki.jenkins.io/display/JENKINS/OWASP+Dependency-Track+Plugin
  [Jenkins Pipeline]: https://jenkins.io/solutions/pipeline
  [CycloneDX]: http://cyclonedx.org
  [SPDX]: https://spdx.org
  [license-image]: https://img.shields.io/badge/license-apache%20v2-brightgreen.svg
  [license-url]: https://github.com/DependencyTrack/dependency-track/blob/master/LICENSE.txt
  [Apache License 2.0]: https://github.com/DependencyTrack/dependency-track/blob/3.0-dev/LICENSE.txt
  [notices]: https://github.com/DependencyTrack/dependency-track/blob/master/NOTICES.txt
  [Alpine]: https://github.com/stevespringett/Alpine
