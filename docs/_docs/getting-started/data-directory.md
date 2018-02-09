---
title: Data Directory
category: Getting Started
chapter: 1
order: 5
---

Dependency-Track uses ~/.dependency-track on UNIX/Linux systems and .dependency-track in current users home
directory on Windows machines. This directory, referred to as the Dependency-Track Data directory, contains 
the NIST NVD mirror, embedded database files, application and audit logs, as well as keys used during normal 
operation, such as validating JWT tokens. It is essential that best practices are followed to secure the 
.dependency-track directory structure.

The data directory includes:


| Content                    | Purpose                                    |
| -------------------------- | ------------------------------------------ |
| db.mv.db                   | Embedded H2 database                       |
| dependency-track.log       | Application log                            |
| dependency-track-audit.log | Application audit log                      |
| dependency-check           | Dependency-Check data and report directory |
| keys                       | Keys used to generate/verify JWT tokens    |
| nist                       | Full mirrored contents of the NVD          |
| index                      | Internal search engine index               |
| server.log                 | Embedded Jetty server log                  |
| vulndb                     | Read by Dependency-Track to sync contents  |