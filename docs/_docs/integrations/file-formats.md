---
title: File Formats
category: Integrations
chapter: 6
order: 2
---

Dependency-Track has an *API-first design*. API's are simply at the heart of the platform. However, there are 
occasions when a file-based format is desired for integration with other systems, especially legacy systems or
systems that are not API-aware or compatible.

Dependency-Track has a native format that can be used to share findings with other systems. The findings contain 
identical information as presented while auditing, but also include information about the project and the system 
that created the file. The file type is called **Finding Packaging Format** (FPF).

FPF's are json files and have the following sections:

| Name     | Type   | Description |
| ---------|--------|-----|
| version  | string | The Finding Packaging Format document version |
| meta     | object | Describes the Dependency-Track instance that created the file |
| project  | object | The project the findings are associated with |
| findings | array  | An array of zero or more findings |

To export findings in the FPF format, the `/api/v1/finding/project/{uuid}/export` API endpoint is used.

The **VULNERABILITY_ANALYSIS** permission is required to use the findings API.


#### Example

```json
{
  "version": "1.0",
  "meta" : {
    "application": "Dependency-Track",
    "version": "3.4.0",
    "timestamp": "2018-11-18T23:31:42Z",
    "baseUrl": "http://dtrack.example.org"
  },
  "project" : {
    "uuid": "ca4f2da9-0fad-4a13-92d7-f627f3168a56",
    "name": "Acme Example",
    "version": "1.0",
    "description": "A sample application"
  },
  "findings" : [
  {
    "component": {
      "uuid": "b815b581-fec1-4374-a871-68862a8f8d52",
      "name": "timespan",
      "version": "2.3.0",
      "purl": "pkg:npm/timespan@2.3.0"
    },
    "vulnerability": {
      "uuid": "115b80bb-46c4-41d1-9f10-8a175d4abb46",
      "source": "NPM",
      "vulnId": "533",
      "title": "Regular Expression Denial of Service",
      "subtitle": "timespan",
      "severity": "LOW",
      "severityRank": 3,
      "cweId": 400,
      "cweName": "Uncontrolled Resource Consumption ('Resource Exhaustion')",
      "description": "Affected versions of `timespan`...",
      "recommendation": "No direct patch is available..."
    },
    "analysis": {
      "state": "NOT_SET",
      "isSuppressed": false
    },
    "matrix": "ca4f2da9-0fad-4a13-92d7-f627f3168a56:b815b581-fec1-4374-a871-68862a8f8d52:115b80bb-46c4-41d1-9f10-8a175d4abb46"
  },
  {
    "component": {
      "uuid": "979f87f5-eaf5-4095-9d38-cde17bf9228e",
      "name": "uglify-js",
      "version": "2.4.24",
      "purl": "pkg:npm/uglify-js@2.4.24"
    },
    "vulnerability": {
      "uuid": "701a3953-666b-4b7a-96ca-e1e6a3e1def3",
      "source": "NPM",
      "vulnId": "48",
      "title": "Regular Expression Denial of Service",
      "subtitle": "uglify-js",
      "severity": "LOW",
      "severityRank": 3,
      "cweId": 400,
      "cweName": "Uncontrolled Resource Consumption ('Resource Exhaustion')",
      "description": "Versions of `uglify-js` prior to...",
      "recommendation": "Update to version 2.6.0 or later."
    },
    "analysis": {
      "isSuppressed": false
    },
    "matrix": "ca4f2da9-0fad-4a13-92d7-f627f3168a56:979f87f5-eaf5-4095-9d38-cde17bf9228e:701a3953-666b-4b7a-96ca-e1e6a3e1def3"
  }]
}
```
