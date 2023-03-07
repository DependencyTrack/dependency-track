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

#### Step 6: Add Per-project configuration
![Configure Project](/images/screenshots/dtrack_project_properties.png)
Dependency-Track includes the ability to specify configuration properties on a per-project basis. Navigate to Projects / 'Your Project', then click on 'View Details' to open 'Project Details' page; then click on 'Properties' button; click on 'Create Property'.
This feature is used to map projects in Dependency-Track to engagements in DefectDojo.

| Attribute      | Value                             |
| ---------------| --------------------------------- |
| Group Name     | `integrations`                    |
| Property Name  | `defectdojo.engagementId`         |
| Property Value | The CI/CD engagement ID to upload findings to, noted in Step 3 |s
| Property Type  | `STRING`                          |

#### Step 7: Add Per-project configuration for Reimport Enhancement (Optional)
* Dependency-Track v4.6.0 or higher
![Configure Project](/images/screenshots/defectdojo_reimport.png)
Instead of creating numerous tests per DefectDojo engagement, now you have the option to deduplicate the tests automatically with this configuration. Once configured, Dependency Track server will try to determine if previous test exist or not. If no, a new test will be created. Otherwise, the test results will be published into the existing one.
The additional configuration property is defined as below:

| Attribute      | Value                             |
| ---------------| --------------------------------- |
| Group Name     | `integrations`                    |
| Property Name  | `defectdojo.reimport`             |
| Property Value | 'true'                            |
| Property Type  | `BOOLEAN`                         |

#### Step 8: Add Per-project configuration for do_not_reactivate Enhancement (Optional)
![Configure Project](/images/screenshots/defectdojo_do-not-reactivate.png)

* Dependency-Track v4.8.0 or higher
* Only work in combination with reimport
* Enabling this flag will mean that DefectDojo is considered the source of truth and findings closed in DefectDojo are not re-opened.
* WARNING! This comes with the downside that a potentially patched vulnerability that is re-introduced by, for example a library downgrade, is reactivated

As mentioned in the DefectDojo documentation this feature 'Will keep existing findings closed, without reactivating them.' Usually DefectDojo considers the scanners report as the source of truth, this leads DefectDojo to re-open findings that might have been closed in DefectDojo if it shows up in a scan.


| Attribute      | Value                             |
| ---------------| --------------------------------- |
| Group Name     | `integrations`                    |
| Property Name  | `defectdojo.doNotReactivate`             |
| Property Value | 'true'                            |
| Property Type  | `BOOLEAN`                         |

#### Step 9: Global configuration for Reimport Enhancement (Optional)
* Dependency-Track v4.6.0 or higher
![Configure Project](/images/screenshots/defectdojo_global_reimport.png)
Alternatively, you can turn on the above reimport feature for all projects in one click, by checking on 'Enable reimport' box as shown in the screenshot above.
