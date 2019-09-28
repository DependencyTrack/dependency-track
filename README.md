[![Build Status](https://travis-ci.org/DependencyTrack/dependency-track.svg?branch=3.0-dev)](https://travis-ci.org/DependencyTrack/dependency-track) 
[![Codacy Badge](https://api.codacy.com/project/badge/Grade/a1d99b45c27e4d069f94d24bcce8d7e6)](https://www.codacy.com/app/DependencyTrack/dependency-track?utm_source=github.com&amp;utm_medium=referral&amp;utm_content=DependencyTrack/dependency-track&amp;utm_campaign=Badge_Grade)[![Alpine](https://img.shields.io/badge/built%20on-Alpine-blue.svg)](https://github.com/stevespringett/Alpine)
<img src="https://docs.dependencytrack.org/images/dt.svg" width="300" align="right">
[![License][license-image]][license-url]
[![OWASP Flagship](https://img.shields.io/badge/owasp-flagship%20project-orange.svg)](https://www.owasp.org/index.php/OWASP_Dependency_Track_Project)
[![Website](https://img.shields.io/badge/https://-dependencytrack.org-blue.svg)](https://dependencytrack.org/)
[![Documentation](https://img.shields.io/badge/read-documentation-blue.svg)](https://docs.dependencytrack.org/)
[![Slack](https://img.shields.io/badge/chat%20on-slack-46BC99.svg)](https://dependencytrack.org/slack)
[![Join the chat at https://gitter.im/dependency-track/Lobby](https://badges.gitter.im/dependency-track/Lobby.svg)](https://dependencytrack.org/gitter)
[![Group Discussion](https://img.shields.io/badge/discussion-groups.io-blue.svg)](https://dependencytrack.org/discussion)
[![YouTube Subscribe](https://img.shields.io/badge/youtube-subscribe-%23c4302b.svg)](https://dependencytrack.org/youtube)
[![Twitter](https://img.shields.io/twitter/follow/dependencytrack.svg?label=Follow&style=social)](https://twitter.com/dependencytrack)
[![Downloads](https://img.shields.io/github/downloads/DependencyTrack/dependency-track/total.svg)](https://github.com/DependencyTrack/dependency-track/releases)
[![Latest](https://img.shields.io/github/release/DependencyTrack/dependency-track.svg)](https://github.com/DependencyTrack/dependency-track/releases)
[![Docker Pulls](https://img.shields.io/docker/pulls/owasp/dependency-track.svg)](https://hub.docker.com/r/owasp/dependency-track/)


# Dependency-Track
Dependency-Track is an intelligent Software [Supply Chain Component Analysis] platform that allows organizations to 
identify and reduce risk from the use of third-party and open source components. Dependency-Track takes a unique
and highly beneficial approach by leveraging the capabilities of [Software Bill-of-Materials] (SBOM). This approach 
provides capabilities that traditional Software Composition Analysis (SCA) solutions cannot achieve.

Dependency-Track monitors component usage across all versions of every application in its portfolio in order to 
proactively identify risk across an organization. The platform has an API-first design and is ideal for use in 
Continuous Integration (CI) and Continuous Delivery (CD) environments.

**NOTICE: Always use official binary releases in production.**

## Ecosystem Overview
![alt text](https://raw.githubusercontent.com/DependencyTrack/dependency-track/master/docs/images/integrations.png)

## Features
* Tracks application, library, framework, operating system, and hardware components
* Tracks component usage across all version of every application in an organizations portfolio
* Identifies multiple forms of risk including
  * Components with known vulnerabilities
  * Out-of-date components
  * Modified components
  * License risk
  * More coming soon...
* Integrates with multiple sources of vulnerability intelligence including:
  * [National Vulnerability Database] (NVD)
  * [NPM Public Advisories]
  * [Sonatype OSS Index]
  * [VulnDB] from [Risk Based Security]
  * More coming soon.
* Ecosystem agnostic with built-in repository support for:
  * Ruby Gems
  * Maven
  * NPM
  * NuGet
  * Python (Pypi)
  * More coming soon.  
* Includes a comprehensive auditing workflow for triaging results
* Configurable notifications supporting Slack, Microsoft Teams, Webhooks, and Email
* Supports standardized SPDX license ID’s and tracks license use by component
* Supports importing [CycloneDX] and [SPDX] Software Bill-of-Materials (SBOM) formats
* Easy to read metrics for components, projects, and portfolio
* Native support for Kenna Security, Fortify SSC, and ThreadFix
* API-first design facilitates easy integration with other systems
* API documentation available in OpenAPI format
* Supports internally managed users, Active Directory/LDAP, and API Keys
* Simple to install and configure. Get up and running in just a few minutes

## Screenshots
![alt text](https://raw.githubusercontent.com/DependencyTrack/dependency-track/master/docs/images/screenshots/dashboard.png)

For more eye-candy, visit <https://dependencytrack.org/>.

## Distributions
Dependency-Track supports the following three deployment options:

* Docker container
* Executable WAR
* Conventional WAR

## Deploying Docker Container
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

## Deploying the Executable WAR
Another simple way to get Dependency-Track running quickly is to automatically deploy the executable WAR. This
method requires Java 8u101 or higher. Simply download `dependency-track-embedded.war` and execute:

```shell
java -Xmx4G -jar dependency-track-embedded.war
```

## Deploying the Conventional WAR
This is the most difficult to deploy option as it requires an already installed and configured Servlet 
container such as Apache Tomcat 8.5 and higher, however, it offers the most flexible deployment options.
Follow the Servlet containers instructions for deploying `dependency-track.war`.
 
 
## Compiling From Sources (optional)
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

## Resources

* Website: <https://dependencytrack.org/>
* Documentation: <https://docs.dependencytrack.org/>
* Component Analysis: <https://www.owasp.org/index.php/Component_Analysis>

## Community

* Twitter: <https://dependencytrack.org/twitter>
* YouTube: <https://dependencytrack.org/youtube>
* Gitter: <https://dependencytrack.org/gitter>
* Slack: <https://dependencytrack.org/slack> (Invite:  <https://dependencytrack.org/slack/invite>)
* Discussion (Groups.io): <https://dependencytrack.org/discussion>

## Support
Dependency-Track is an open source project, created by people who believe that the knowledge of using 
vulnerable components should be accessible to anyone with a desire to know. By supporting this project, you'll
allow the team to outsource testing, infrastructure, further research and development efforts, and engage in 
outreach to various communities that would benefit from this technology.

[![PayPal](https://www.paypalobjects.com/en_US/i/btn/btn_donate_SM.gif)](https://www.paypal.com/cgi-bin/webscr?cmd=_donations&business=paypal%40owasp%2eorg&lc=US&item_name=OWASP%20Dependency-Track&no_note=0&currency_code=USD&bn=PP%2dDonationsBF)

## Copyright & License
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
  [Supply Chain Component Analysis]: https://www.owasp.org/index.php/Component_Analysis
  [Software Bill-of-Materials]: https://www.owasp.org/index.php/Component_Analysis#Software_Bill-of-Materials_.28SBOM.29
  [OWASP Wiki]: https://www.owasp.org/index.php/OWASP_Dependency_Track_Project
  [Dependency-Check]: https://www.owasp.org/index.php/OWASP_Dependency_Check
  [CycloneDX]: https://cyclonedx.org
  [SPDX]: https://spdx.org
  [license-image]: https://img.shields.io/badge/license-apache%20v2-brightgreen.svg
  [license-url]: https://github.com/DependencyTrack/dependency-track/blob/master/LICENSE.txt
  [Apache License 2.0]: https://github.com/DependencyTrack/dependency-track/blob/3.0-dev/LICENSE.txt
  [notices]: https://github.com/DependencyTrack/dependency-track/blob/master/NOTICES.txt
  [Alpine]: https://github.com/stevespringett/Alpine
