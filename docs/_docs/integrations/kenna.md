---
title: Kenna Security
category: Integrations
chapter: 6
order: 5
---

Dependency-Track can automatically publish results to the Kenna Security platform providing a 
consolidated view of every vulnerability across an organization including vulnerable components. 

Dependency-Track accomplishes this in the following ways:

* Kenna Security integration is configured in Dependency-Track
* Dependency-Track pushes findings to Kenna on a periodic basis (configurable)

Requirements:
* Dependency-Track v3.4.0 or higher
* Kenna Security with Application Risk Module

### Kenna Security Configuration

#### Step 1: Navigate to connectors
![Navigate to connectors](/images/screenshots/kenna-connectors.png)

#### Step 2: Add a KDI connector
![Add KDI connector](/images/screenshots/kenna-add-kdi-connector.png)

Each connector has a unique ID. The ID is typically available in the URL as well as accessible via the Kenna API. The 
connector ID will be used when configuring integration with Dependency-Track.

### Dependency-Track Configuration

#### Global configuration
![Configure Kenna Integration](/images/screenshots/kenna-dtrack-configuration.png)

#### Per-project configuration
Dependency-Track includes the ability to specify configuration properties on a per-project basis. 
This feature is used to map projects in Dependency-Track to applications/assets in Kenna.

![Configure Project Properties](/images/screenshots/kenna-project-properties.png)

| Attribute      | Value                             |
| ---------------| --------------------------------- |
| Group Name     | `integrations`                    |
| Property Name  | `kenna.asset.external_id`         |
| Property Value | The assets external_id            |
| Property Type  | `STRING`                          |

The external_id may be anything as long as it uniquely identifies the application in Kenna. Shown in the example
is the UUID of the Dependency-Track project. However, the external_id may be an organizations internal identifier
for the application.

![Kenna Findings](/images/screenshots/kenna-findings.png)