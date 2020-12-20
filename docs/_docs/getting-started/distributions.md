---
title: Distributions
category: Getting Started
chapter: 1
order: 0
---

Dependency-Track has four distribution variants. They are:

| Package | Package Format | Recommended | Supported | Docker | Download |
| :---------- | :---------- | :---------: | :---------: | :---------: | :---------: |
| API Server | Executable WAR | ✅ | ✅ | ✅ | ✅ | 
| Frontend | Single Page Application | ✅ | ✅ | ✅ | ✅ |
| Bundled | Executable WAR | ❌ | ☑️ | ✅ | ✅ |
| Traditional WAR | WAR | ❌ | ❌ | ❌ | ✅ |


### API Server

The API Server contains an embedded Jetty server and all server-side functionality, but excludes the frontend user 
interface. This variant is new as of Dependency-Track v4.0.

### Frontend

The Frontend is the user interface that is accessible in a web browser. The Frontend is a Single Page Application (SPA)
that can be deployed independently of the Dependency-Track API Server. This variant is new as of Dependency-Track v3.8.

### Bundled

The Bundled variant combines the API Server and the Frontend user interface. This variant was previously referred to as 
the executable war and was the preferred distribution from Dependency-Track v3.0 - v3.8. This variant is supported but
deprecated and will be discontinued in a future release.

### Traditional

The Traditional variant combines the API Server and the Frontend user interface and must be deployed to a Servlet 
container. This variant is not supported, deprecated, and will be discontinued in a future release.

