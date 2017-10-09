[![Build Status](https://travis-ci.org/stevespringett/dependency-track.svg?branch=3.0-dev)](https://travis-ci.org/stevespringett/dependency-track) 
[![Codacy Badge](https://api.codacy.com/project/badge/Grade/a1d99b45c27e4d069f94d24bcce8d7e6)](https://www.codacy.com/app/stevespringett/dependency-track?utm_source=github.com&amp;utm_medium=referral&amp;utm_content=stevespringett/dependency-track&amp;utm_campaign=Badge_Grade)
[![Alpine](https://img.shields.io/badge/built%20on-Alpine-blue.svg)](https://github.com/stevespringett/Alpine)
<img src="https://stevespringett.github.io/dependency-track/images/dt.svg" width="300" align="right">
[![License][license-image]][license-url]
[![Join the chat at https://gitter.im/dependency-track/Lobby](https://badges.gitter.im/dependency-track/Lobby.svg)](https://gitter.im/dependency-track/Lobby?utm_source=badge&utm_medium=badge&utm_campaign=pr-badge&utm_content=badge)

Dependency-Track
=========

This is the development branch of v3.0, the next generation of Dependency-Track, 
written from the ground-up, using an API-first design, modern technologies, and
without many of the limitations of the previous versions. Version 3 is not 
backward compatible with previous versions due to fundamentally different approaches
and data models.

Introduction
-
OWASP Dependency-Track is a Java web application that allows organizations to
document the use of third-party components across multiple applications and
versions. Further, it provides automatic visibility into the use of components
with known vulnerabilities.

The OWASP Top Ten 2013 introduces, for the first time, the use of third-party
components with known vulnerabilities. Dependency-Track aims to document the
usage of all components, the vendors, libraires, versions and licenses used
and provide visibility into the use of vulnerable components.

Dependency-Track is built on top of [Alpine].

Compiling
-------------------

```shell
mvn clean package
```

Deploying With Servlet Container
-------------------

Dependency-Track can be deployed to any Servlet 3 compatible container including Tomcat and Jetty.
Simply copy dependency-track.war to the webapps directory and restart the servlet engine.

Deploying With Docker
-------------------

The easiest way to get Dependency-Track setup is to automatically create and deploy a Docker container.
This can be accomplished by first compiling the software, then by executing Docker-specific commands. 

```shell
mvn clean package
docker build -f src/main/docker/Dockerfile -t dtrack .
docker run -p 8080:8080 -t dtrack
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

Copyright & License
-------------------

Dependency-Track is Copyright (c) Steve Springett. All Rights Reserved.

Permission to modify and redistribute is granted under the terms of the GPLv3
license. See the [LICENSE.txt] [GPLv3] file for the full license.

Dependency-Track makes use of several other open source libraries. Please see
the [NOTICES.txt] [notices] file for more information.

  [GitHub Wiki]: https://github.com/stevespringett/dependency-track/wiki
  [OWASP Wiki]: https://www.owasp.org/index.php/OWASP_Dependency_Track_Project
  [license-image]: https://img.shields.io/badge/License-GPL%20v3-blue.svg
  [license-url]: https://github.com/stevespringett/dependency-track/blob/master/LICENSE.txt
  [subscribe]: https://lists.owasp.org/mailman/listinfo/owasp_dependency_track_project
  [post]: mailto:owasp_dependency_track_project@lists.owasp.org
  [GPLv3]: https://github.com/stevespringett/dependency-track/blob/master/LICENSE.txt
  [notices]: https://github.com/stevespringett/dependency-track/blob/master/NOTICES.txt
  [Alpine]: https://github.com/stevespringett/Alpine
