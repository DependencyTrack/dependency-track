---
title: Deploying the WAR
category: Getting Started
chapter: 1
order: 3
---

This is the most difficult to deploy option as it requires an already installed and configured Servlet 
container such as Apache Tomcat 8.5 and higher. Follow the Servlet containers instructions for deploying `dependency-track.war`.

`dependency-track.war` must be deployed to the ROOT context.

> **Deprecated and unsupported**
> 
> Traditional WAR deployments to a Servlet container are deprecated, unsupported, and will no longer be produced in a
> future version of Dependency-Track. It is advisable that organizations migrate to a container strategy such as
> Docker or Kubernetes.

### Requirements

| Minimum | Recommended |
|:---------|:--------|
| Java 8 u162 (or higher) | Java 8 u162 or higher |
| 4GB RAM | 16GB RAM |
| 2 CPU cores | 4 CPU cores |
