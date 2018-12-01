---
title: Kenna Security
category: Integrations
chapter: 5
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

### Dependency-Track Configuration

#### Global configuration
![Configure Kenna Integration](/images/screenshots/kenna-dtrack-configuration.png)

#### Per-project configuration
Dependency-Track includes the ability to specify configuration properties on a per-project basis. 
This feature is used to map projects in Dependency-Track to applications/assets in Kenna.

| Attribute      | Value                             |
| ---------------| --------------------------------- |
| Group Name     | `integrations`                    |
| Property Name  | `kenna.asset.external_id`         |
| Property Value | The assets external_id            |
| Property Type  | `STRING`                          |


### Kenna Security Configuration

#### Step 1: Navigate to connectors
![Navigate to connectors](/images/screenshots/kenna-connectors.png)

#### Step 2: Add a KDI connector
![Add KDI connector](/images/screenshots/kenna-add-kdi-connector.png)
