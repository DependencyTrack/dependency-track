---
title: Frequently Asked Questions
category: FAQ
chapter: 10
order:
---

Frequently asked questions about Dependency Track functionality that may not be covered by the documentation. If you don't find an answer here, try reaching out to the Slack [channel](https://owasp.slack.com/archives/C6R3R32H4) related to dependency track.

#### Dependency Check and Dependency Track Comparison

This topic is heavily explained in the [Dependency Check Comparison](./../odt-odc-comparison/) to Dependency Track.

#### I expect to see vulnerable components but I don't

Most common reason: You have yet to enable the [Sonatype OSS Index Analyzer](./../datasources/ossindex/). It is not
enabled by default but is necessary to scan dependencies represented by
[Package URLs](./../terminology/#package-url-purl).

#### I have just enabled OSS Index Analyzer but still don't see results

The analyzers run asynchronously. After you enable an analyzer it is not immediately run.
You have to wait some time until the analyzers are scheduled, currently this is 6 hours.  
You can also trigger the analysis of one project by re-uploading a SBOM for the project.  
Restarting Dependency Track will not run the analyzers either, it will just reset the clock.

#### Why is the local NVD mirror not used?

The local NVD mirror is used for dependencies that are identified by a [CPE](./../terminology/#cpe). These are mostly
components like operating systems, applications, and hardware. That's what CPE was designed to represent.  
[Package URLs](./../terminology/#package-url-purl) (PURL) on the other hand are designed to represent all kinds of software
dependencies like packages, libraries, and frameworks. In the local mirror there is no mapping from the PURL to CPE/CVE.  
So the local mirror is used, but not for dependencies represented by PURL. Dependency Track will use the Analyzer best
suited to analyze a given dependency.

#### Dependency Track crashes when run as a container

Make sure the container is allowed to allocate enough RAM. For memory requirements see
[Deploying Docker Container](./../getting-started/deploy-docker/). A common source for limited memory is Docker for
Windows's default memory limit of 2GB which is too little. You can change this in Docker's settings.

#### Dependency Track stops working after 1-2 weeks

This might happen if your OS cleans-up temp storage without checking for open files.
This has been observed with Windows and CentOS.
Deleting temporary files is a problem for the embedded Jetty server used by Dependency Track.
When launching Dependency Track, try adding `-Djava.io.tmpdir=/path/to/tmpdir` to the command and specify an
alternative path to where you want DT temp files to reside.

#### Why is there a delay with LDAP synchronization?

For auto-provisioned accounts, LDAP synchronization is performed on-demand and utilizes the same async job scheduling queue that all other jobs use. If the system is busy processing other jobs (mirroring the NVD or processing lots of SBOMs simultaneously for example), there might be a slight delay provisioning the account (which includes permission sync). If the LDAP account is manually created in DT, then synchronization has already happened and there shouldn’t be a delay.

#### I'm seeing "PKIX path building failed" errors in the API server logs, what is that and how can I fix it?

Your Dependency-Track instance is most likely configured to connect to services that use TLS certificates
that are either self-signed, or signed by your organization's internal certificate authority.
Please refer to the [Internal Certificate Authority](./../getting-started/internal-ca/) documentation.

#### Unrelated vulnerabilities are reported as aliases, how can this be fixed?

This can be a problem either in the data that Dependency-Track ingests from any of the enabled vulnerability intelligence
sources, or a bug in the way Dependency-Track correlates this data. Some data sources have been found to not report 
reliable alias data. As of v4.8.0, alias synchronization can be disabled on a per-source basis. For the time being, 
it is recommended to disable alias synchronization for OSV and Snyk.

To reset alias data, do the following:
1. Disable alias synchronization for sources that may report unreliable data
2. Stop the API server application
3. Delete all aliases from the database:
```sql
DELETE FROM "VULNERABILITYALIAS" WHERE "ID" > 0;
```
4. Restart the API server application

Alias data will be re-populated the next time vulnerability intelligence sources are mirrored, or vulnerability
analysis is taking place. If this does not solve the problem, please raise a [defect report] on GitHub, 
as it is likely a bug in Dependency-Track.

[defect report]: https://github.com/DependencyTrack/dependency-track/issues/new?assignees=&labels=defect%2Cin+triage&template=defect-report.yml