---
title: Initial Startup
category: Getting Started
chapter: 1
order: 4
---

Upon starting Dependency-Track for the first time, multiple tasks occur including:

* Generation of default objects such as users, teams, and permissions
* Generation of secret key used for JWT token creation and validation
* Population of CWE and SPDX license data
* Initial mirroring of all supported vulnerability datasources (National Vulnerability Database, NPM Advisories, etc)

> The initial mirroring may take between 10 - 30 minutes or more. Do not interrupt this process. Wait for the 
> completion of all mirroring tasks before shutting down the system. These tasks can be monitored by watching
> `dependency-track.log` or the Docker containers console.

#### Default credentials

An administrative account is created on initial startup with the following credentials:
* username: admin
* password: admin

Upon first login, the admin user is required to change the password.
