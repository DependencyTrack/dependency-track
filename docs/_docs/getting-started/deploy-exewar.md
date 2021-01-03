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
is to have Java 8u162 (or higher) installed.

> **Deprecation Notice**
>
> The Executable WAR is deprecated and will no longer be distributed in a future version of Dependency-Track
> It is advisable that organizations migrate to a container strategy such as Docker or Kubernetes.

The Executable WAR is available in two variants:
* API Server
* Bundled
  
Refer to [distributions](../distributions/) for details.

### Requirements

| Minimum | Recommended |
|:---------|:--------|
| Java 8 u162 (or higher) | Java 8 u162 or higher |
| 4GB RAM | 16GB RAM |
| 2 CPU cores | 4 CPU cores |

If minimum requirements are not met, Dependency-Track will not start correctly. However, for systems with Java 8 
already installed, this method of execution may provide the fastest deployment path.

### Startup

```bash
# Executes Dependency-Track with default options
java -Xmx8G -jar dependency-track-bundled.war
```

#### Command-Line Arguments

The following command-line arguments can be passed to a compiled executable WAR when executing it:

| Argument | Default | Description |
|:---------|:--------|:------------|
| -context | /       | The application context to deploy to |
| -host    | 0.0.0.0 | The IP address to bind to |
| -port    | 8080    | The TCP port to listens on |


**Note:** Setting the context is only supported on the API Server variant. The Frontend requires deployment to the root ('/') context.


#### Examples

```bash
java -Xmx12G -jar dependency-track-apiserver.war -context /dtrack
```

```bash
java -Xmx12G -jar dependency-track-apiserver.war -port 8081
```

```bash
java -Xmx12G -jar dependency-track-apiserver.war -context /dtrack -host 192.168.1.16 -port 9000
```

```bash
java -XX:MaxRAMPercentage=80.0 -jar dependency-track-bundled.war
```
