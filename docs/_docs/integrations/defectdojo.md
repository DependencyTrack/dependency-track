---
title: DefectDojo
category: Integrations
chapter: 6
order: 6
---

Dependency-Track can automatically publish results to DefectDojo providing a
consolidated view of security-centric code findings and vulnerable component findings.

Dependency-Track accomplishes this in the following ways:

* DefectDojo integration is configured in Dependency-Track
* Dependency-Track pushes findings to DefectDojo on a periodic basis (configurable)
* DefectDojo parses Dependency-Track findings

Requirements:
* Dependency-Track v4.1.0 or higher
* DefectDojo 1.13.1 or higher

### Dependency-Track Configuration

### DefectDojo Configuration

#### Step 1: Create a product (or navigate to one you've created already
![Create a product](/images/screenshots/defectdojo_create_product.png)

#### Step 2: Create a CI/CD engagement for your product
![Create CI/CD engagement menu](/images/screenshots/defectdojo_create_cicd_menu.png)
![Create CI/CD engagement](/images/screenshots/defectdojo_create_cicd.png)

#### Step 3: Note down the ID of the new engagement
![Note engagement ID](/images/screenshots/defectdojo_cicd_engagement_id.png)

#### Step 4: Note down your API key
![Note API Key](/images/screenshots/defectdojo_api_key_menu.png)
![Note API Key](/images/screenshots/defectdojo_api_key.png)

#### Step 5: Add the API key in Dependency-Track configuration
![Configure DefectDojo Integration](/images/screenshots/defectdojo_config.png)

#### Per-project configuration
Dependency-Track includes the ability to specify configuration properties on a per-project basis.
This feature is used to map projects in Dependency-Track to engagements in DefectDojo.

| Attribute      | Value                             |
| ---------------| --------------------------------- |
| Group Name     | `integrations`                    |
| Property Name  | `defectdojo.engagementId`       |
| Property Value | The CI/CD engagement ID to upload findings to, noted in Step 3 |
| Property Type  | `STRING`                          |
