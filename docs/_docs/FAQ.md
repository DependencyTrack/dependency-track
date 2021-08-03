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

#### Why is Sonatype OSS Index Analyzer disabled by default?

For Dependency-Track v3.0 - v3.8, Sonatype OSS Index Analyzer is disabled and requires an account. See
[Sonatype OSS Index Analyzer](./../datasources/ossindex/). For Dependency-Track v4.0 and higher, OSS Index is enabled
by default and does not require an account.

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

#### I updated Dependency Track and now I can not upload Dependency-Check reports

Starting with Dependency Track v3.6.0 support for Dependency-Check XML reports was disabled by default. It was finally
removed with v3.7.0. The fundamental concepts of Dependency-Check and Dependency Track are different, so the support
was dropped. A comparison can be found in the [Dependency Check Comparison](./../odt-odc-comparison/).

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

#### Breaking changes with Java 11

Java 11 introduces breaking changes, which is the reason most organizations still use Java 8, and the reason why the DT Docker images still use Java 8 as well.
