---
title: Code Dx
category: Integrations
chapter: 6
order: 4
---

Code Dx Enterprise automates the arduous workflows needed to centralize finding, analyzing, and fixing security vulnerabilities across disparate security tools — at DevOps speed.
Code Dx orchestrates scan automation, automates triage, and prioritizes tracking and remediation of vulnerabilities.
It does this while continuously assessing the security risks across the entire software lifecycle.
The Code Dx Dependency-Track connector allows a way to automatically pull in vulnerabilities and legal compliance issues from component analysis (SCA) in Dependency-Track, into Code Dx to allow it to de-duplicate, normalize, and correlate the findings with other tools and offer a single, coherent thread of prioritized issues.

### How it Works

The connector is easy to use and set up.
It leverages the Dependency-Track REST APIs for better interoperability.
Follow these steps to get started:

Retrieve the frontend URL, API URL, and the API Key from Dependency-Track.

Select the Dependency-Track Connector from the Tool Connectors Section for your Code Dx Project - For additional details on configuring data sources please see the Code Dx [User Guide](https://codedx.com/Documentation/UserGuide.html#ToolConnectors).

![Configuration](/images/screenshots/codedx-configuration.png)

Select the specific Dependency-Track project that you need to map to your Code Dx project.

Schedule and automate the ability to pull in data into Code Dx based on your preference.

Check the box "Run this connector during normal analyses" if you want to pull data every time you trigger an explicit analysis cycle in Code Dx.*

*Analysis cycles involve pulling in data from all connected tools for a particular Code Dx project, as well as running scans using the built-in open source tools if configured to do so.

![Findings](/images/screenshots/codedx-findings.png)

![Finding Details](/images/screenshots/codedx-details.png)
