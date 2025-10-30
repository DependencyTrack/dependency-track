---
title: Fortify SSC
category: Integrations
chapter: 6
order: 3
---

Dependency-Track can automatically publish results to Fortify Software Security Center (SSC) providing a 
consolidated view of security-centric code findings and vulnerable component findings. 

Dependency-Track accomplishes this in the following ways:

* Fortify SSC integration is configured in Dependency-Track
* Dependency-Track pushes findings to Fortify SSC on a periodic basis (configurable)
* A plugin for Fortify SSC parses Dependency-Track findings

Requirements:
* Dependency-Track v3.4.0 or higher
* Fortify SSC 17.20 or higher
* [Download](https://github.com/DependencyTrack/fortify-ssc-plugin/releases) and install Dependency-Track plugin for Fortify SSC

### Dependency-Track Configuration

#### Global configuration
Dependency-Track requires the use of a `CIToken`. Refer to the Fortify SSC documentation for more information.

![Configure SSC Integration](/images/screenshots/fortify-ssc-dtrack-configuration.png)

#### Per-project configuration
Dependency-Track includes the ability to specify configuration properties on a per-project basis. 
This feature is used to map projects in Dependency-Track to applications in Fortify SSC. 

| Attribute      | Value                             |
| ---------------| --------------------------------- |
| Group Name     | `integrations`                    |
| Property Name  | `fortify.ssc.applicationId`       |
| Property Value | The application version ID in SSC |
| Property Type  | `STRING`                          |


### Fortify SSC Configuration

#### Step 1: Navigate to parsers
![Navigate to parsers](/images/screenshots/fortify-ssc-step1.png)

#### Step 2: Install the plugin
![Install the plugin](/images/screenshots/fortify-ssc-step2.png)

#### Step 3: Verify plugin is installed
![Verify plugin is installed](/images/screenshots/fortify-ssc-step3.png)

#### Step 4: Enable plugin
![Enable plugin](/images/screenshots/fortify-ssc-step4.png)

#### Step 5: Verify plugin is enabled
![Verify plugin is enabled](/images/screenshots/fortify-ssc-step5.png)

At this point the plugin is installed and ready to accept payloads from Dependency-Track.
Once Dependency-Track pushes a payload to SSC, it will be displayed among the projects
artifacts and the results will be filterable within the audit view.

![SSC artifacts](/images/screenshots/fortify-ssc-artifacts.png)

![SSC analysis](/images/screenshots/fortify-ssc-analysis.png)
