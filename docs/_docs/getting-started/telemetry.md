---
title: Telemetry
category: Getting Started
chapter: 1
order: 14
---

## Collected data

| Data                     | Example                              |
|:-------------------------|:-------------------------------------|
| System ID                | 78701907-3044-493d-92b5-6a45e08aecd3 |
| Dependency-Track version | 4.13.0                               |
| Database type            | PostgreSQL                           |
| Database version         | 15.2                                 |

Information that could allow this data to be traced back to specific organizations,
such as IP addresses, is explicitly **not** collected or stored.

The system ID is randomly generated upon a Dependency-Track instance's first launch.  
It is used to correlate multiple data points of the same system over time,  
but can not be traced back to actual deployments.

The Dependency-Track version is collected to allow the maintainers to gauge
adoption of releases.

Database type and version are collected to gain a better understanding of which
database systems are most commonly used, and which are not. It also allows to draw
conclusions as to when it's safe to raise the baseline of supported database versions.

The insights gained from telemetry collection, excluding system IDs, will be made available to the community.

## Submission frequency

Telemetry data is first submitted one minute after application startup.  
From then onwards, it is submitted on a daily basis.

## Opting out

Telemetry submission can be disabled in multiple ways.

**Via user interface**: Administrators can disable telemetry submission in the  
administration panel under *Configuration* -> *Telemetry*.

![Telemetry preferences]({{ site.baseurl }}/images/screenshots/telemetry.png)

**Via REST API**: Given an API key with `SYSTEM_CONFIGURATION` permission,  
telemetry submission may be disabled using the `/api/v1/configProperty` endpoint.

```shell
curl -X POST \
  -H 'X-Api-Key: odt_******' \
  -H 'Content-Type: application/json' \
  -d '{"groupName":"telemetry","propertyName":"submission.enabled","propertyValue":"false"}' \
  https://dtrack.example.com/api/v1/configProperty
```

**Via environment variable**: *When starting a new instance for the first time*,  
or *when upgrading from an older version to 4.13.0 or higher*,  
the following environment variable can be set:

```
TELEMETRY_SUBMISSION_ENABLED_DEFAULT=false
```

Please note that the environment variable merely impacts the *default value* of the setting.  
It does not overwrite any changes made via REST API or user interface,  
and has no effect past the initial launch of the application.
