---
title: Frequently Asked Questions
category: FAQ
chapter: 10
order:
---

Frequently asked questions about DependencyTrack functionality that may not be covered by the documentation. If you 
don't find an answer here, try reaching out to the Slack [channel](https://owasp.slack.com/archives/C6R3R32H4) related to DependencyTrack.

#### DependencyCheck and DependencyTrack Comparison

This topic is heavily explained in the [Dependency Check Comparison](./../odt-odc-comparison/) to DependencyTrack.

#### Why is CPE not being used in DependencyTrack?

CPE is deprecated because it’s deprecated by the NVD. It is being replaced with [SWID]. [SWID] is now supported in 
CycloneDX v1.2 which will be making its way into DepedencyTrack in future releases.
CPE is only capable of describing vendors, products, and versions. It is not capable of describing individual 
components/modules within a product. It’s also a centralized spec and the CPE values for vendor, product, and version
often do not reflect reality. Case in point, the vendor and product in this CPE do not reflect the reality as specified 
in the PURL. If DependencyTrack was using CPE to identify this vulnerability, it would have lead to a false positive.
For more details: <https://owasp.slack.com/archives/C6R3R32H4/p1593099692019100/>


#### I expect to see vulnerable components but I don't

Most common reason: You have yet to enable the [Sonatype OSS Index Analyzer](./../datasources/ossindex/). It is not
enabled by default but is necessary to scan dependencies represented by
[Package URLs](./../terminology/#package-url-purl).

#### Why is Sonatype OSS Index Analyzer disabled by default?

Sonatype OSS Index Analyzer is disabled because you need an account and need to configure it first. See
[Sonatype OSS Index Analyzer](./../datasources/ossindex/).

#### I have just enabled OSS Index Analyzer but still don't see results

The analyzers run asynchronously. After you enable an analyzer it is not immediately run.
You have to wait some time until the analyzers are scheduled, currently this is 6 hours.  
You can also trigger the analysis of one project by re-uploading a BOM for the project.  
Restarting DependencyTrack will not run the analyzers either, it will just reset the clock.

#### Why is the local NVD mirror not used?

The local NVD mirror is used for dependencies that are identified by a [CPE](./../terminology/#cpe). These are mostly
components like operating systems, applications, and hardware. That's what CPE was designed to represent.  
[Package URLs](./../terminology/#package-url-purl) (PURL) on the other hand are designed to represent all kinds of software
dependencies like packages, libraries, and frameworks. In the local mirror there is no mapping from the PURL to CPE/CVE.  
So the local mirror is used, but not for dependencies represented by PURL. DependencyTrack will use the Analyzer best
suited to analyze a given dependency.

#### I updated DependencyTrack and now I can not upload Dependency-Check reports

Starting with DependencyTrack v3.6.0 support for Dependency-Check XML reports was disabled by default. It was finally
removed with v3.7.0. The fundamental concepts of Dependency-Check and DependencyTrack are different, so the support
was dropped. A comparison can be found in the [Dependency Check Comparison](./../odt-odc-comparison/).

#### DependencyTrack crashes when run as a container

Make sure the container is allowed to allocate enough RAM. For memory requirements see
[Deploying Docker Container](./../getting-started/deploy-docker/). A common source for limited memory is Docker for
Windows's default memory limit of 2GB which is too less. You can change this in docker's settings.

#### DependencyTrack stops working after 1-2 weeks

This might happen if your OS cleans-up temp storage without checking for open files.
This has been observed with Windows and CentOS.
Deleting temporary files is a problem for the embedded Jetty server used by DependencyTrack.
When launching DependencyTrack, try adding `-Djava.io.tmpdir=/path/to/tmpdir` to the command and specify an
alternative path to where you want DependencyTrack temp files to reside. Sample usage in Ubuntu 18.04:

```bash
java -Xmx16G -DdependencyTrack.logging.level=INFO -Dalpine.application.properties=/home/user/dependencytrack/application.properties -Djava.io.tmpdir=my_custom_tmp-dir/ -jar dependency-track-embedded.war -host 192.168.10.9 -port 8080 --illegal-access=deny
```

#### Why is there a delay with LDAP synchronization?

For auto-provisioned accounts, LDAP synchronization is performed on-demand and utilizes the same async job scheduling queue that all other jobs use. If the system is busy processing other jobs (mirroring the NVD or processing lots of BOMs simultaneously for example), there might be a slight delay provisioning the account (which includes permission sync). If the LDAP account is manually created in DT, then synchronization has already happened and there shouldn’t be a delay.

#### Breaking changes with Java 11

Java 11 introduces breaking changes, which is the reason most organizations still use Java 8, and the reason why the DT Docker images still use Java 8 as well.



[SWID]: https://csrc.nist.gov/Projects/Software-Identification-SWID/guidelines