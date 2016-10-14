[ ![Download](https://api.bintray.com/packages/stevespringett/owasp/dependency-track/images/download.svg) ](https://bintray.com/stevespringett/owasp/dependency-track/_latestVersion)

Dependency-Track
=========

Version 2.0 Development Branch (SpringBoot)
--
This branch was an attempt to modernize Dependency-Track by updating many of the core components including Hibernate and Spring. It also introduced SpringBoot. I'd like to thank all of the contributors who submited enhancements, defects, and ideas for this version. Unforntuantly, the amount of effort necessary to correct all the defects and continue to add new features, far exceeds the limitations of the current design and my capability to devote the time necessary to make it happen.

There's a lot of ideas for future direction of the project and this branch is holding those goals back. Therefore, I do not intend to release the code in this branch. It will remain here, archived, for anyone to pick up and experiment with. But it will not be supported. All new development is focused on v3.0 and beyond.

Introduction
--
OWASP Dependency-Track is a Java web application that allows organizations to
document the use of third-party components across multiple applications and
versions. Further, it provides automatic visibility into the use of components
with known vulnerabilities.

The OWASP Top Ten 2013 introduces, for the first time, the use of third-party
components with known vulnerabilities. Dependency-Track aims to document the
usage of all components, the vendors, libraires, versions and licenses used
and provide visibility into the use of vulnerable components.

Development of Dependency-Track is sponsored in part by [Axway]

Installation, configuration and how-to's can be found on the [GitHub Wiki].

General project information can be found on the [OWASP Wiki].


Usage
-

> $ mvn clean package

Finally, deploy the resulting WAR to your web application server (Tomcat, Jetty, etc)

or leverage the power of Spring Boot and simply execute

> java -jar dtrack.war

If compiling from source, dtrack.war will reside in the 'target' directory.


Mailing List
-

Subscribe: [https://lists.owasp.org/mailman/listinfo/owasp_dependency_track_project] [subscribe]

Post: [owasp_dependency_track_project@lists.owasp.org] [post]

Copyright & License
-

Dependency-Track is Copyright (c) Axway. All Rights Reserved.

Permission to modify and redistribute is granted under the terms of the GPLv3
license. See the [LICENSE.txt] [GPLv3] file for the full license.

Dependency-Track makes use of several other open source libraries. Please see
the [NOTICES.txt] [notices] file for more information.

  [GitHub Wiki]: https://github.com/stevespringett/dependency-track/wiki
  [OWASP Wiki]: https://www.owasp.org/index.php/OWASP_Dependency_Track_Project
  [subscribe]: https://lists.owasp.org/mailman/listinfo/owasp_dependency_track_project
  [post]: mailto:owasp_dependency_track_project@lists.owasp.org
  [GPLv3]: https://github.com/stevespringett/dependency-track/blob/master/LICENSE.txt
  [notices]: https://github.com/stevespringett/dependency-track/blob/master/NOTICES.txt
  [axway]: http://www.axway.com
