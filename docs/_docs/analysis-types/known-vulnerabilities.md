---
title: Known Vulnerability Analysis
category: Analysis Types
chapter: 3
order: 1
---

Dependency-Track integrates with multiple sources of vulnerability intelligence to identify components with known
vulnerabilities. The platform employs several methods of vulnerability identification:

| Analyzer  | Type            | Identifier   | Description                                                                              |
|-----------|-----------------|--------------|------------------------------------------------------------------------------------------|
| Internal  | Mirror-based    | CPE and PURL | Analyzes components against a local mirror of NVD, GitHub Advisories, OSV, and/or VulnDB data |
| OSS Index | External API    | PURL         | Sonatype's hosted vulnerability service, queried at analysis time                        |
| VulnDB    | External API    | CPE          | Flashpoint's commercial vulnerability service, queried at analysis time                  |
| Snyk      | External API    | PURL         | Snyk's commercial vulnerability service, queried at analysis time                        |
| Trivy     | External server | PURL         | Self-hosted Trivy server, queried at analysis time                                       |

Each of the analyzers above can be enabled or disabled independently of one another.

> **Components must have the right identifier for an analyzer to process them.**
> A component without a CPE is silently skipped by analyzers that require CPE; a component without a PURL is
> silently skipped by analyzers that require PURL. If a component yields no findings, always verify its
> identifiers first.

### Mirror-based vs. External Analyzers

Dependency-Track uses two fundamentally different approaches to vulnerability analysis:

**Mirror-based analysis (Internal Analyzer)**

The Internal Analyzer queries a local copy of vulnerability data that Dependency-Track periodically synchronizes
from upstream sources (NVD, GitHub Advisories, OSV, VulnDB). Analysis happens entirely within Dependency-Track
without any outbound requests at analysis time. The freshness of results depends on how recently the mirrors
were last updated — by default, mirrors are refreshed daily or on instance restart.

**External analyzers (OSS Index, VulnDB, Snyk, Trivy)**

These analyzers send component identifiers to a remote service at analysis time and receive vulnerability findings
in return. Results reflect the current state of the remote service, but are subject to network availability,
rate limits, authentication requirements, and the remote service's own update schedule.
To reduce redundant requests, results are cached locally for 12 hours by default
(see [Analysis Result Cache](#analysis-result-cache)).

### Vulnerability Assignment and Persistence

Once Dependency-Track assigns a vulnerability to a component, that assignment **persists even if the upstream
source data later changes** — for example, if a CVE's affected version ranges are revised to exclude the
component's version, or if the vulnerability is retracted entirely.

This is by design: automatically removing assigned vulnerabilities could silently erase audit trails and analyst
work. Dependency-Track re-evaluates components during each analysis run and may add newly discovered
vulnerabilities, but it does not remove existing ones.

If a previously assigned vulnerability is determined to be incorrect, it must be explicitly addressed by setting
an appropriate analysis state on the finding (e.g. *False Positive* or *Not Affected*).

### Internal Analyzer

The Internal Analyzer relies on a local dictionary of vulnerable software. This dictionary is automatically
populated when NVD, GitHub Advisories, OSV, or VulnDB mirroring is performed. Which identifier is used for
matching depends on the mirrored data source:

* **CPE** — used for data from the NVD and VulnDB mirrors.
* **PURL** — used for data from the GitHub Advisories and OSV mirrors.

A component needs at least one valid identifier to be analyzed. Components with both a CPE and a PURL are
evaluated against all applicable mirrored data sources.

#### CPE Matching

Matching against data from the NVD requires components to have a valid CPE. Dependency-Track follows
the [NIST CPE name matching specification](https://nvlpubs.nist.gov/nistpubs/Legacy/IR/nistir7696.pdf),
with a few customizations.

To reduce false positives, the following additional checks are performed:

* If comparison of *vendor* yields `SUBSET`, and comparison of *product* yields `SUPERSET`, then it's a no-match
* If comparison of *vendor* yields `SUPERSET`, and comparison of *product* yields `SUBSET`, then it's a no-match

This is to avoid component CPEs like `cpe:2.3:a:*:zstandard:1.5.2:*:*:*:*:*:*:*` from getting matched to
CVE CPEs like `cpe:2.3:a:pascom_cloud_phone_system:*:*:*:*:*:*:*:*:*`.

Dependency-Track will emit a log at `DEBUG` level whenever it discards matches due to the above.

### OSS Index Analyzer

> **Requires:** A valid Package URL (PURL). Components without a PURL are not analyzed by OSS Index.

OSS Index is a service provided by Sonatype which identifies vulnerabilities in third-party components. The
service supports a wide range of package management ecosystems. Dependency-Track integrates with OSS Index using
its public API — vulnerability data is not mirrored locally, but consumed on an as-identified basis.

> **Note:** Unauthenticated usage of OSS Index is no longer supported. An API token is required.
> Refer to [OSS Index (Datasource)]({{ site.baseurl }}{% link _docs/datasources/ossindex.md %}) for
> configuration details.

### VulnDB Analyzer

> **Requires:** A valid CPE. Components without a CPE are not analyzed by the VulnDB Analyzer.

VulnDB is a subscription service offered by Flashpoint. The VulnDB Analyzer queries the VulnDB REST APIs at
analysis time to identify vulnerabilities in components. Dependency-Track does not mirror VulnDB data for this
analyzer — it is consumed on an as-identified basis.

> VulnDB data can also be ingested into the Internal Analyzer via the VulnDB mirror. Refer to
> [VulnDB (Datasource)]({{ site.baseurl }}{% link _docs/datasources/vulndb.md %}) for additional information.

### Snyk Analyzer

> **Requires:** A valid Package URL (PURL). Components without a PURL are not analyzed by Snyk.

Snyk is a commercial service that identifies vulnerabilities in third-party components using its REST API. Snyk
returns direct vulnerabilities for a specific package version identified by PURL. Vulnerability data is not
mirrored locally — it is consumed on an as-identified basis.

Refer to [Snyk (Datasource)]({{ site.baseurl }}{% link _docs/datasources/snyk.md %}) for configuration details.

### Trivy Analyzer

> **Requires:** A valid Package URL (PURL). Components without a PURL are not analyzed by Trivy.

The Trivy Analyzer sends components to an external Trivy server instance for analysis using its REST API.
The Trivy integration requires a separately deployed Trivy server and is disabled by default.

> The Trivy server REST API is not publicly documented, so upgrading to a new version may introduce
> compatibility issues. Refer to [Trivy (Datasource)]({{ site.baseurl }}{% link _docs/datasources/trivy.md %})
> for deployment instructions and known limitations.

### Analysis Result Cache

Dependency-Track contains an internal limiter which prevents repeated requests to remote services when performing
vulnerability analysis. When a component's Package URL or CPE is successfully analyzed by a given analyzer,
the result is cached. By default, cache entries expire after 12 hours.

### Troubleshooting False Positives and False Negatives

Before reporting a false positive or false negative as a bug, work through the following steps.

#### Step 1: Verify the component's identifiers in Dependency-Track

Navigate to the component in question and confirm it has a valid CPE and/or PURL, as required by the
analyzer(s) you expect to produce results (see the table at the top of this page). A missing, empty, or
malformed identifier causes the analyzer to silently skip the component and is the most common cause of
unexpected results.

#### Step 2: Check the vulnerability's affected ranges in Dependency-Track

Open the vulnerability in Dependency-Track and review the affected version ranges it lists. If the component's
version does not fall within any listed range, Dependency-Track correctly does not match it — this is expected
behavior, not a bug.

#### Step 3: Compare with the upstream source

* For the **Internal Analyzer**, cross-reference the relevant upstream source directly:
  [NVD](https://nvd.nist.gov), [GitHub Advisories](https://github.com/advisories), [OSV](https://osv.dev),
  or VulnDB. Check whether the upstream source agrees with what Dependency-Track has stored. If there is a
  discrepancy, the local mirror may be stale — trigger a manual re-sync and re-analyze before concluding
  there is a bug.

* For **external analyzers** (OSS Index, VulnDB, Snyk, Trivy), query the remote service directly using the
  exact same PURL or CPE the component has in Dependency-Track. If the external service also does not report
  the vulnerability for that identifier, the discrepancy lies in the upstream data, not in Dependency-Track's
  integration.

Only after completing these steps and confirming a genuine discrepancy between Dependency-Track and the
upstream source should an issue be reported as a bug.
