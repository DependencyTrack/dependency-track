---
title: Deploying the Executable WAR
category: Getting Started
chapter: 1
order: 2
---

An executable WAR is a traditional Java Web Archive (WAR) that is packaged in a way where it can executed from 
the command-line. Unlike traditional WARs which require a Servlet container already installed and 
configured, executable WARs fast-track this process by bundling a Servlet container specifically configured to 
execute the bundled application.

The Dependency-Track executable WAR is delivered ready-to-run. To use the executable WAR, the only requirement 
is to have Java 8u101 (or higher) installed and execute:

```bash
java -Xmx4G -jar dependency-track-embedded.war
```

For users with Java already installed on their machines, this method of execution may provide the fastest path
forward.
