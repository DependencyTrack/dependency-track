[![Build Status](https://travis-ci.org/stevespringett/dependency-track.svg?branch=3.0-dev)](https://travis-ci.org/stevespringett/dependency-track) 
[![Codacy Badge](https://api.codacy.com/project/badge/Grade/a1d99b45c27e4d069f94d24bcce8d7e6)](https://www.codacy.com/app/stevespringett/dependency-track?utm_source=github.com&amp;utm_medium=referral&amp;utm_content=stevespringett/dependency-track&amp;utm_campaign=Badge_Grade)
[![Alpine](https://img.shields.io/badge/built%20on-Alpine-blue.svg)](https://github.com/stevespringett/Alpine)
<img src="https://stevespringett.github.io/dependency-track/images/dt.svg" width="300" align="right">
[![License][license-image]][license-url]
[![Join the chat at https://gitter.im/dependency-track/Lobby](https://badges.gitter.im/dependency-track/Lobby.svg)](https://gitter.im/dependency-track/Lobby?utm_source=badge&utm_medium=badge&utm_campaign=pr-badge&utm_content=badge)

Dependency-Track
=========

Modern applications leverage the availability of existing components for use as building blocks 
in application development. By using existing components, organizations can dramatically decrease
time-to-market. Reusing existing components however, comes at a cost. Organizations that build on 
top of existing components assume risk for software they did not create. Vulnerabilities in third-party
components are inherited by all applications that use those components. The OWASP Top Ten (2013 and 2017)
both recognize the risk of using components with known vulnerabilities. 

Dependency-Track is a Software Composition Analysis (SCA) tool that keeps track of all the third-party 
components used in all the applications an organization creates or consumes. It integrates with multiple
vulnerability databases including the National Vulnerability Database (NVD), Node Security Platform (NSP),
and VulnDB (from Risk Based Security) in order to proactively identify vulnerabilities in components that
are placing your applications at risk.  

Dependency-Track is designed to be used in a completely automated DevOps environment where Dependency-Check
results or specific BOM (Bill of Material) formats are automatically ingested during CI/CD. Use of the 
Dependency-Check Jenkins Plugin is highly recommended for this purpose.

Dependency-Track can also be used to monitor vulnerabilities in COTS (commercial off-the-shelf) software.

Dependency-Track is built on top of [Alpine].

**NOTICE: Dependency-Track is pre-release alpha quality software. It is expected to be feature complete 
in Janurary 2018 with betas and release candidates available in Q1.**


Distributions
-------------------

Ready-to-deploy distributions will be available beginning with 3.0.0-beta-1. Dependency-Track
supports the following two deployment options:

* Executable WAR
* Docker container


Deploying Standalone
-------------------

The easiest way to get Dependency-Track setup is to automatically create and deploy an executable WAR.

```shell
mvn clean package -P embedded-jetty
java -jar target/dependency-track.war
```

 
Deploying With Docker
-------------------

For users leveraging Docker, the process simply wraps the executable WAR inside a Docker container.
Begin by first compiling the software, then by executing Docker-specific commands. 

```shell
mvn clean package -P embedded-jetty
docker build -f src/main/docker/Dockerfile -t dependency-track .
docker run -p 8080:8080 -t hakbot
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

Mailing List
-------------------

Subscribe: [https://lists.owasp.org/mailman/listinfo/owasp_dependency_track_project] [subscribe]

Post: [owasp_dependency_track_project@lists.owasp.org] [post]


Support
-------------------

OWASP Dependency-Track is an open source project, created by people who believe that the knowledge of using 
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

  [GitHub Wiki]: https://github.com/stevespringett/dependency-track/wiki
  [OWASP Wiki]: https://www.owasp.org/index.php/OWASP_Dependency_Track_Project
  [license-image]: https://img.shields.io/badge/license-apache%20v2-brightgreen.svg
  [license-url]: https://github.com/stevespringett/alpine/blob/master/LICENSE.txt
  [subscribe]: https://lists.owasp.org/mailman/listinfo/owasp_dependency_track_project
  [post]: mailto:owasp_dependency_track_project@lists.owasp.org
  [Apache License 2.0]: https://github.com/stevespringett/dependency-track/blob/3.0-dev/LICENSE.txt
  [notices]: https://github.com/stevespringett/dependency-track/blob/master/NOTICES.txt
  [Alpine]: https://github.com/stevespringett/Alpine
