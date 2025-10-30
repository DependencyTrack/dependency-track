---
title: ThreadFix
category: Integrations
chapter: 6
order: 9
---

ThreadFix includes a *remote provider* for Dependency-Track which provides seemless and automatic integration.
Vulnerabilities on a per-project basis in Dependency-Track are mapped to corresponding applications in ThreadFix
along with details of every vulnerability.

### Remote Provider Configuration
In ThreadFix, define a Dependency Track remote provider. Ensure a valid URL to the Dependency-Track server is
specified along with a valid API Key.

![Remote Provider Creation](/images/screenshots/threadfix-remoteprovider-create.png)

Once the remote provider is created, projects in Dependency-Track must be mapped to applications in ThreadFix.

![Remote Provider Mapping](/images/screenshots/threadfix-remoteprovider-mappings.png)

It is recommend to setup a schedule for ThreadFix to automatically import Dependency-Track results periodically.
Refer to the ThreadFix documentation on instructions on how to setup importer schedules.

### Usage
Results are imported and integrated into ThreadFix and behave like any other vulnerability ThreadFix tracks.
Vulnerabilities can be sorted, filtered, and expanded with further details. The vulnerabilities can now be
included in the advanced analytics and workflows that ThreadFix provides.

![ThreadFix Findings](/images/screenshots/threadfix-results.png)
