---
title: Continuous Delivery
category: Usage
chapter: 2
order: 1
---

Dependency-Track can ingest CycloneDX BoMs or Dependency-Check XML reports as part of a CI/CD pipeline. The 
generation of CycloneDX BoMs or Dependency-Check reports often occur during CI or when the final
application assembly is being generated. 

> Dependency-Track continuously monitors components for known vulnerabilities. When components are added or 
> updated in Dependency-Track, an analysis is performed against the component. This action occurs during 
> ingestion of files as well as changes to the components via REST or from the user interface. All 
> components in Dependency-Track, regardless of changes, are automatically analyzed on a daily basis.

The [Dependency-Track Jenkins Plugin]({{ site.baseurl }}{% link _docs/integrations/jenkins.md %}) is the 
recommended method for publishing CycloneDX BoMs or Dependency-Check XML reports to Dependency-Track in 
a Jenkins environment.

For other environments, cURL (or similar) is all that's required. 

#### Dependency-Check
To publish Dependency-Check XML reports, use a valid API Key and project UUID. Finally, Base64 encode the 
report and insert the resulting text into the 'scan' field.

```bash
curl -X "PUT" "http://dtrack.example.com/api/v1/scan" \
     -H 'Content-Type: application/json' \
     -H 'X-API-Key: LPojpCDSsEd4V9Zi6qCWr4KsiF3Konze' \
     -d $'{
  "project": "f90934f5-cb88-47ce-81cb-db06fc67d4b4",
  "scan": "PD94bWwgdm..."
  }'
```

#### CycloneDX or SPDX BoM
To publish CycloneDX or SPDX BoMs, use a valid API Key and project UUID. Finally, Base64 encode the 
bom and insert the resulting text into the 'bom' field.

```bash
curl -X "PUT" "http://dtrack.example.com/api/v1/bom" \
     -H 'Content-Type: application/json' \
     -H 'X-API-Key: LPojpCDSsEd4V9Zi6qCWr4KsiF3Konze' \
     -d $'{
  "project": "f90934f5-cb88-47ce-81cb-db06fc67d4b4",
  "bom": "PD94bWwgdm..."
  }'
```

#### Large Payloads
In cases where the scan or BoM being uploaded is large, using cURLs capability of specifying a file
containing a payload may be preferred.

```bash
curl -X "PUT" "http://dtrack.example.com/api/v1/scan" \
     -H 'Content-Type: application/json' \
     -H 'X-API-Key: LPojpCDSsEd4V9Zi6qCWr4KsiF3Konze' \
     -d @payload.json
```

