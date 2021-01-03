---
title: Data Directory
category: Getting Started
chapter: 1
order: 7
---

Dependency-Track uses `~/.dependency-track` on UNIX/Linux systems and `.dependency-track` in the current users 
home directory on Windows machines. This directory, referred to as the *data directory*, contains 
the NIST NVD mirror, embedded database files, application and audit logs, as well as keys used during normal 
operation, such as validating JWT tokens. It is essential that best practices are followed to secure the 
data directory.

The data directory includes:


| Content                    | Purpose                                    |
| -------------------------- | ------------------------------------------ |
| db.mv.db                   | Embedded H2 database                       |
| dependency-track.log       | Application log                            |
| dependency-track-audit.log | Application audit log                      |
| id.system                  | Randomly generated system identifier       |
| index                      | Internal search engine index               |
| keys                       | Keys used to generate/verify JWT tokens    |
| nist                       | Mirror of the NVD and CPE                  |
| server.log                 | Embedded Jetty server log                  |
| vulndb                     | Mirror of VulnDB                           |
