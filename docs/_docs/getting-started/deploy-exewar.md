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
is to have Java 8u162 (or higher) installed and execute:

### Requirements

* Java 8 with u162 or higher
* 4GB minimum heap space (-Xmx)
* 2 CPU cores

If these requirements are not met, Dependency-Track will not start correctly. However, for systems with Java 8 
already installed, this method of execution may provide the fastest deployment path.

### Startup

```bash
# Executes Dependency-Track with default options
java -Xmx4G -jar dependency-track-embedded.war
```

#### Command-Line Arguments

The following command-line arguments can be passed to a compiled executable WAR when executing it:

| Argument | Default | Description |
|:---------|:--------|:------------|
| -context | /       | The application context to deploy to |
| -host    | 0.0.0.0 | The IP address to bind to |
| -port    | 8080    | The TCP port to listens on |

#### Examples

```bash
java -Xmx4G -jar dependency-track-embedded.war -context /dtrack
```

```bash
java -Xmx4G -jar dependency-track-embedded.war -port 8081
```

```bash
java -Xmx4G -jar dependency-track-embedded.war -context /dtrack -host 192.168.1.16 -port 9000
```
