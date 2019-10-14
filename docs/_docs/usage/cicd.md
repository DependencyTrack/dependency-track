---
title: Continuous Integration & Delivery
category: Usage
chapter: 2
order: 1
---

Dependency-Track can ingest CycloneDX and SPDX BOMs as part of a CI/CD pipeline. The 
generation of CycloneDX BOMs often occur during CI or when the final application assembly 
is being generated. 

> Dependency-Track continuously monitors components for known vulnerabilities. When components are added or 
> updated in Dependency-Track, an analysis is performed against the component. This action occurs during 
> ingestion of files as well as changes to the components via REST or from the user interface. All 
> components in Dependency-Track, regardless of changes, are automatically analyzed on a daily basis.

The [Dependency-Track Jenkins Plugin]({{ site.baseurl }}{% link _docs/integrations/jenkins.md %}) is the 
recommended method for publishing CycloneDX BOMs to Dependency-Track in a Jenkins environment.

For other environments, cURL (or similar) can be used. 

#### CycloneDX or SPDX BOM
To publish CycloneDX or SPDX BOMs, use a valid API Key and project UUID. Finally, Base64 encode the 
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

It's also possible to publish BOMs via HTTP POST which does not require Base64 encoding the payload.
 
```bash
curl -X "POST" "http://dtrack.example.com/api/v1/bom" \
     -H 'Content-Type: multipart/form-data; charset=utf-8; boundary=__X_CURL_BOUNDARY__' \
     -H 'X-Api-Key: LPojpCDSsEd4V9Zi6qCWr4KsiF3Konze' \
     -F "project=f90934f5-cb88-47ce-81cb-db06fc67d4b4" \
     -F "bom=<?xml version=\"1.0\" encoding=\"UTF-8\"?>..."
```

#### Large Payloads
In cases where the scan or BOM being uploaded is large, using cURLs capability of specifying a file
containing a payload may be preferred.

```bash
curl -X "PUT" "http://dtrack.example.com/api/v1/bom" \
     -H 'Content-Type: application/json' \
     -H 'X-API-Key: LPojpCDSsEd4V9Zi6qCWr4KsiF3Konze' \
     -d @payload.json
```

