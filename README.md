[![Build Status](https://travis-ci.org/stevespringett/dependency-track.svg?branch=3.0-dev)](https://travis-ci.org/stevespringett/dependency-track) 
[![Codacy Badge](https://api.codacy.com/project/badge/Grade/a1d99b45c27e4d069f94d24bcce8d7e6)](https://www.codacy.com/app/stevespringett/dependency-track?utm_source=github.com&amp;utm_medium=referral&amp;utm_content=stevespringett/dependency-track&amp;utm_campaign=Badge_Grade)
[![Alpine](https://img.shields.io/badge/built%20on-Alpine-blue.svg)](https://github.com/stevespringett/Alpine)
<img src="https://stevespringett.github.io/dependency-track/images/dt.svg" width="300" align="right">
[![License][license-image]][license-url]
[![Website](https://img.shields.io/badge/https://-dependencytrack.org-blue.svg)](https://dependencytrack.org/)
[![Slack](https://img.shields.io/badge/chat%20on-slack-46BC99.svg)](https://owasp.slack.com/messages/proj-dependency-track)
[![Join the chat at https://gitter.im/dependency-track/Lobby](https://badges.gitter.im/dependency-track/Lobby.svg)](https://gitter.im/dependency-track/Lobby?utm_source=badge&utm_medium=badge&utm_campaign=pr-badge&utm_content=badge)
[![Twitter](https://img.shields.io/twitter/url/http/shields.io.svg?style=social&label=Follow)](https://twitter.com/dependencytrack)

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
vulnerability databases including the [National Vulnerability Database] (NVD), [Node Security Platform] (NSP),
and [VulnDB] from [Risk Based Security]. Dependency-Track monitors all applications in its portfolio in order
to proactively identify vulnerabilities in components that are placing your applications at risk. Use of 
Dependency-Track can play a vital role in an overall Supply Chain Risk Management (SCRM) program by providing 
many of the recommendations outlined in the [NIST Cybersecurity Framework](https://www.nist.gov/cybersecurity-framework).

Dependency-Track is designed to be used in an automated DevOps environment where [Dependency-Check]
results or specific BOM (Bill of Material) formats are automatically ingested during CI/CD. Use of the 
[Dependency-Check Jenkins Plugin] is highly recommended for this purpose and is well suited for use
in [Jenkins Pipeline]. In such an environment, Dependency-Track enables your DevOps teams to accelerate while
still keeping tabs on component usage and any inherited risk.

Dependency-Track can also be used to monitor vulnerabilities in COTS (commercial off-the-shelf) software.

**NOTICE: Dependency-Track is pre-release alpha quality software. It is expected to be feature complete 
in January 2018 with betas and release candidates available in Q1.**


Features
-------------------

* Dramatically increases visibility into the use of vulnerable components
* Supports an unlimited number of projects and components
* Projects can range from applications, operating systems, firmware, to IoT devices
* Tracks vulnerabilities across entire project portfolio
* Tracks vulnerabilities by component
* Easily identify projects that are potentially vulnerable to newly published vulnerabilities
* Supports standardized SPDX license ID’s and tracks license use by component
* Supports [CycloneDX] and [SPDX] bill-of-material formats
* Easy to read metrics for components, projects, and portfolio
* API-first design facilitates easy integration with other systems
* API documentation available in Swagger 2.0 (OpenAPI 3 support coming soon)
* Flexible authentication supports internally managed users, Active Directory/LDAP, and API Keys
* Simple to install and configure. Get up and running in just a few minutes


Ecosystem Overview
-------------------
![alt tag](docs/images/ecosystem.png)
* Dependency-Check results can be published to SonarQube ([plugin](https://github.com/stevespringett/dependency-check-sonar-plugin))
* Dependency-Check results can be published to ThreadFix ([plugin](https://plugins.jenkins.io/threadfix))
* Dependency-Check results can be published to Dependency-Track
* Software bill-of-materials can be published to Dependency-Track
* Dependency-Check can use Dependency-Track as a source of evidence
* Dependency-Track results can be integrated into ThreadFix

Screenshots
-------------------
The dashboard:
![alt text](https://raw.githubusercontent.com/stevespringett/dependency-track/master/docs/images/screenshots/dashboard.png)


A list of all projects:
![alt text](https://raw.githubusercontent.com/stevespringett/dependency-track/master/docs/images/screenshots/projects.png)


Viewing a list of components that are dependencies of a specific project:
![alt text](https://raw.githubusercontent.com/stevespringett/dependency-track/master/docs/images/screenshots/components.png)


Viewing an individual vulnerable component:
![alt text](https://raw.githubusercontent.com/stevespringett/dependency-track/master/docs/images/screenshots/vulnerable-component.png)


Viewing an individual vulnerability:
![alt text](https://raw.githubusercontent.com/stevespringett/dependency-track/master/docs/images/screenshots/vulnerability.png)


Viewing all vulnerabilities in the system:
![alt text](https://raw.githubusercontent.com/stevespringett/dependency-track/master/docs/images/screenshots/vulnerabilities.png)


Viewing an individual license:
![alt text](https://raw.githubusercontent.com/stevespringett/dependency-track/master/docs/images/screenshots/license.png)

Distributions
-------------------

Ready-to-deploy distributions will be available beginning with 3.0.0-beta-1. Dependency-Track
supports the following three deployment options:

* Executable WAR
* Conventional WAR
* Docker container


Deploying the Executable WAR
-------------------

The easiest way to get Dependency-Track setup is to automatically create and deploy an executable WAR.

```shell
mvn clean package -P embedded-jetty
java -jar target/dependency-track-embedded.war
```

Deploying the Conventional WAR
-------------------

This is the most difficult to deploy option as it requires an already installed and configured Servlet 
container such as Apache Tomcat 8.5 and higher, however, it offers the most flexible deployment options.

```shell
mvn clean package
```
Follow the Servlet containers instructions for deploying `dependency-track.war`.

 
Deploying With Docker
-------------------

For users leveraging Docker, the process simply wraps the executable WAR inside a Docker container.
Begin by first compiling the software, then by executing Docker-specific commands. 

```shell
mvn clean package -P embedded-jetty
docker build -f src/main/docker/Dockerfile -t dependency-track .
docker run -p 8080:8080 -t dependency-track
```
 
 
Compiling
-------------------

To create an executable WAR that is ready to launch (recommended for most users):

```shell
mvn clean package -P embedded-jetty
```

To create a WAR that must be manually deployed to a modern Servlet container (i.e. Tomcat 8.5+):

```shell
mvn clean package
```


Configuration
-------------------

Configuration is performed by editing application.properties. Among the configuration parameters are:

* Independently enforce authentication and authorization
* Active Directory integration (via LDAP)

Usage
-------------------

**Webapp URL:** http://$HOSTNAME:$PORT/$CONTEXT

**REST API URL:** http://$HOSTNAME:$PORT/$CONTEXT/api

**Swagger URL:** http://$HOSTNAME:$PORT/$CONTEXT/api/swagger.json


Data Directory
-------------------

Dependency-Track uses ~/.dependency-track on UNIX/Linux systems and .dependency-track in current users home
directory on Windows machines. This directory contains the NIST NVD mirror, embedded database files, application
and audit logs, as well as keys used during normal operation, such as validating JWT tokens. It is essential that
best practices are followed to secure the .dependency-track directory structure.

Community
-------------------

Gitter: https://gitter.im/dependency-track/Lobby

Google Groups: https://groups.google.com/forum/#!forum/dependency-track


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
  [Node Security Platform]: https://nodesecurity.io
  [VulnDB]: https://vulndb.cyberriskanalytics.com
  [Risk Based Security]: https://www.riskbasedsecurity.com
  [OWASP Top Ten]: https://www.owasp.org/index.php/Category:OWASP_Top_Ten_Project
  [OWASP Wiki]: https://www.owasp.org/index.php/OWASP_Dependency_Track_Project
  [Dependency-Check]: https://www.owasp.org/index.php/OWASP_Dependency_Check
  [Dependency-Check Jenkins Plugin]: https://plugins.jenkins.io/dependency-check-jenkins-plugin
  [Jenkins Pipeline]: https://jenkins.io/solutions/pipeline
  [CycloneDX]: https://github.com/CycloneDX
  [SPDX]: https://spdx.org
  [license-image]: https://img.shields.io/badge/license-apache%20v2-brightgreen.svg
  [license-url]: https://github.com/stevespringett/alpine/blob/master/LICENSE.txt
  [Apache License 2.0]: https://github.com/stevespringett/dependency-track/blob/3.0-dev/LICENSE.txt
  [notices]: https://github.com/stevespringett/dependency-track/blob/master/NOTICES.txt
  [Alpine]: https://github.com/stevespringett/Alpine
