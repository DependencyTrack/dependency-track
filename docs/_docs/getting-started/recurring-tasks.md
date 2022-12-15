---
title: Recurring Tasks
category: Getting Started
chapter: 1
order: 8
---

Dependency-Track heavily relies on asynchronous recurring tasks to perform various forms of analyses, calculations,
data mirroring, and interactions with 3rd party integrations. 

Each recurring task has a predefined initial delay, as well as a default interval. 
The initial delay ensures that not all tasks are started at the same time, which would put the system under heavy load 
from the get-go. Intervals can be configured (see [Configuration](#configuration)) if desired.

In simple terms, if Dependency-Track is started at 04:00 PM, a task with an initial delay of 5 minutes and an interval
of 24 hours will run at 04:05 PM every day. 

### Tasks

Recurring tasks typically emit log messages whenever they start, complete, or fail unexpectedly. The task names as
listed below will be reflected in those log messages.

| Name                                                       | Description                                                                                     | Initial Delay | Default Interval                   |
|:-----------------------------------------------------------|:------------------------------------------------------------------------------------------------|:--------------|:-----------------------------------|
| LdapSyncTask<span style="color: red">\*</span>             | Synchronizes [LDAP] users                                                                       | 10s           | 6h                                 |
| GitHubAdvisoryMirrorTask<span style="color: red">\*</span> | Mirrors the [GitHub Advisories] database                                                        | 10s           | 24h                                |
| NistMirrorTask<span style="color: red">\*</span>           | Mirrors the [NVD] database                                                                      | 1m            | 24h                                |
| EpssMirrorTask<span style="color: red">\*</span>           | Mirrors the [EPSS] database                                                                     | -             | (Immediately after NistMirrorTask) |
| OsvMirrorTask<span style="color: red">\*</span>            | Mirrors the [OSV] database                                                                      | 10s           | 24h                                |
| VulnDbSyncTask<span style="color: red">\*</span>           | Mirrors the [VulnDB] database                                                                   | 1m            | 24h                                |
| PortfolioMetricsUpdateTask                                 | Updates time series metrics for all projects in the portfolio                                   | 10s           | 1h                                 |
| VulnerabilityMetricsUpdateTask                             | Updates time series metrics for the local vulnerability database                                | 10s           | 1h                                 |
| VulnerabilityAnalysisTask                                  | Analyzes all components in the portfolio for vulnerabilities                                    | 6h            | 24h                                |
| RepositoryMetaAnalyzerTask                                 | Fetches repository metadata (e.g. latest versions) for all components in the portfolio          | 1h            | 24h                                |
| InternalComponentIdentificationTask                        | Identifies [internal components] in the portfolio                                               | 1h            | 6h                                 |
| ClearComponentAnalysisCacheTask                            | Clears internal caches used for vulnerability analysis with external sources (e.g. [OSS Index]) | 10s           | 72h                                |
| FortifySscUploadTask<span style="color: red">\*</span>     | Publishes findings to [Fortify SSC]                                                             | 5m            | 1h                                 |
| DefectDojoUploadTask<span style="color: red">\*</span>     | Publishes findings to [Defect Dojo]                                                             | 5m            | 1h                                 |
| KennaSecurityUploadTask<span style="color: red">\*</span>  | Publishes findings to [Kenna Security]                                                          | 5m            | 1h                                 |
| IndexTask<span style="color: red">\*</span>                | Perform existence, corruption and consistency checks on Apache Lucene indexes used for search   | 3h            | 72h                                |

<span style="color: red">\*</span> *Is only executed when the corresponding feature is enabled and configured.*

### Configuration

As of Dependency-Track v4.6.0, the interval of recurring tasks is configurable in the administration panel. 
Most of the intervals are configured in the _Task scheduler_ section but Lucene indexes task interval is configured in _Search_ section.

Users are strongly encouraged to have proper [monitoring] in place before modifying these settings. Because some tasks
can potentially put the system under high load, or take a long(er) time to complete, choosing intervals that are too 
short may cause unexpected issues. As a rule of thumb, a task's interval should only be modified if there's a good 
reason to.

> For technical reasons, changes to task interval configurations require a restart of the application to take effect.

![Recurring Tasks Configuration]({{ site.baseurl }}/images/screenshots/recurring-tasks_configuration.png)

[Defect Dojo]: {{ site.baseurl }}{% link _docs/integrations/defectdojo.md %}
[EPSS]: https://www.first.org/epss/data_stats
[Fortify SSC]: {{ site.baseurl }}{% link _docs/integrations/fortify-ssc.md %}
[GitHub Advisories]: {{ site.baseurl }}{% link _docs/datasources/github-advisories.md %}
[internal components]: {{ site.baseurl }}{% link _docs/datasources/internal-components.md %}
[Kenna Security]: {{ site.baseurl }}{% link _docs/integrations/kenna.md %}
[LDAP]: {{ site.baseurl }}{% link _docs/getting-started/ldap-configuration.md %}
[monitoring]: {{ site.baseurl }}{% link _docs/getting-started/monitoring.md %}
[NVD]: {{ site.baseurl }}{% link _docs/datasources/nvd.md %}
[OSS Index]: {{ site.baseurl }}{% link _docs/datasources/ossindex.md %}
[OSV]: {{ site.baseurl }}{% link _docs/datasources/osv.md %}
[VulnDB]: {{ site.baseurl }}{% link _docs/datasources/vulndb.md %}
