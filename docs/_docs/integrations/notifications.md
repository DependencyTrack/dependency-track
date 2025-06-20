---
title: Notifications
category: Integrations
chapter: 6
order: 7
---

Dependency-Track includes a robust and configurable notification framework capable of alerting users or systems
to the presence of newly discovered vulnerabilities, previously known vulnerable components that are added to
projects, as well as providing notifications on various system and error conditions.

## Scopes

Dependency-Track notifications come in two flavors (scopes):

| Scope     | Description                                                                           |
|-----------|---------------------------------------------------------------------------------------|
| SYSTEM    | Notifications on system-level informational and error conditions                      |
| PORTFOLIO | Notifications on objects in the portfolio such as vulnerabilities and audit decisions |

## Levels

Notifications can have one of three possible levels:

* INFORMATIONAL
* WARNING
* ERROR

Notification levels behave identical to logging levels:

* Configuring a rule for level INFORMATIONAL will match notifications of level INFORMATIONAL, WARNING, and ERROR
* Configuring a rule for level WARNING will match notifications of level WARNING and ERROR
* Configuring a rule for level ERROR will match notifications of level ERROR

## Triggers

Notifications may be triggered via one of two ways:

| Trigger  | Description                                                 |
|:---------|:------------------------------------------------------------|
| Event    | An event is emitted by the system under certain conditions. |
| Schedule | The notification is sent based on a planned schedule.       |

This differentiation is new as of v4.13.0. In older versions, all notifications were triggered by events.

* Notifications triggered by events are ideal for near real-time automation, and integrations into chat platforms.
* Notifications triggered on schedule are typically used to communicate high-level summaries,
and are thus a better fit for reporting purposes.

## Groups

Each scope contains a set of notification groups that can be subscribed to. Some groups contain notifications of
multiple levels, while others can only ever have a single level.

| Scope     | Group                         | Trigger  | Level(s)      | Description                                                                                                                       |
|-----------|-------------------------------|----------|---------------|-----------------------------------------------------------------------------------------------------------------------------------|
| SYSTEM    | ANALYZER                      | Event    | (Any)         | Notifications generated as a result of interacting with an external source of vulnerability intelligence                          |
| SYSTEM    | DATASOURCE_MIRRORING          | Event    | (Any)         | Notifications generated when performing mirroring of one of the supported datasources such as the NVD                             |
| SYSTEM    | INDEXING_SERVICE              | Event    | (Any)         | Notifications generated as a result of performing maintenance on Dependency-Tracks internal index used for global searching       |
| SYSTEM    | FILE_SYSTEM                   | Event    | (Any)         | Notifications generated as a result of a file system operation. These are typically only generated on error conditions            |
| SYSTEM    | REPOSITORY                    | Event    | (Any)         | Notifications generated as a result of interacting with one of the supported repositories such as Maven Central, RubyGems, or NPM |
| SYSTEM    | USER_CREATED                  | Event    | INFORMATIONAL | Notifications generated as a result of a user creation                                                                            |
| SYSTEM    | USER_DELETED                  | Event    | INFORMATIONAL | Notifications generated as a result of a user deletion                                                                            |
| PORTFOLIO | NEW_VULNERABILITY             | Event    | INFORMATIONAL | Notifications generated whenever a new vulnerability is identified                                                                |
| PORTFOLIO | NEW_VULNERABILITIES_SUMMARY   | Schedule | INFORMATIONAL | Summaries of new vulnerabilities identified in a set of projects                                                                  |
| PORTFOLIO | NEW_VULNERABLE_DEPENDENCY     | Event    | INFORMATIONAL | Notifications generated as a result of a vulnerable component becoming a dependency of a project                                  |
| PORTFOLIO | GLOBAL_AUDIT_CHANGE           | Event    | INFORMATIONAL | Notifications generated whenever an analysis or suppression state has changed on a finding from a component (global)              |
| PORTFOLIO | PROJECT_AUDIT_CHANGE          | Event    | INFORMATIONAL | Notifications generated whenever an analysis or suppression state has changed on a finding from a project                         |
| PORTFOLIO | BOM_CONSUMED                  | Event    | INFORMATIONAL | Notifications generated whenever a supported BOM is ingested and identified                                                       |
| PORTFOLIO | BOM_PROCESSED                 | Event    | INFORMATIONAL | Notifications generated after a supported BOM is ingested, identified, and successfully processed                                 |
| PORTFOLIO | BOM_PROCESSING_FAILED         | Event    | ERROR         | Notifications generated whenever a BOM upload process fails                                                                       |
| PORTFOLIO | BOM_VALIDATION_FAILED         | Event    | ERROR         | Notifications generated whenever an invalid BOM is uploaded                                                                       |
| PORTFOLIO | POLICY_VIOLATION              | Event    | INFORMATIONAL | Notifications generated whenever a policy violation is identified                                                                 |
| PORTFOLIO | NEW_POLICY_VIOLATIONS_SUMMARY | Schedule | INFORMATIONAL | Summary of new policy violations identified in a set of projects                                                                  |

## Configuring Publishers

A notification publisher is a Dependency-Track concept allowing users to describe the structure of a notification (i.e. MIME type, template) and how to send a notification (i.e. publisher class).
The following notification publishers are included by default :

| Publisher  | Description                                         |
|------------|-----------------------------------------------------|
| Slack      | Publishes notifications to Slack channels           |
| Teams      | Publishes notifications to Microsoft Teams channels |
| Mattermost | Publishes notifications to Mattermost channels      |
| WebEx      | Publishes notifications to Cisco WebEx channels     |
| Webhook    | Publishes notifications to a configurable endpoint  |
| Email      | Sends notifications to an email address             |
| Console    | Displays notifications on the system console        |
| Jira       | Publishes notifications to Jira                     |

### Templating

Dependency-Track uses [Pebble Templates](https://pebbletemplates.io/) to generate notifications.
The template context is enhanced with the following variables :

| Variable               | Type                  | Description                                                                                                                |
|------------------------|-----------------------|----------------------------------------------------------------------------------------------------------------------------|
| timestampEpochSecond   | long                  | The notification timestamp                                                                                                 |
| timestamp              | string                | The notification local date time in ISO 8601 format (i.e. uuuu-MM-dd'T'HH:mm:ss.SSSSSSSSS)                                 |
| notification.level     | enum                  | One of INFORMATIONAL, WARNING, or ERROR                                                                                    |
| notification.scope     | string                | The high-level type of notification. One of SYSTEM or PORTFOLIO                                                            |
| notification.group     | string                | The specific type of notification                                                                                          |
| notification.title     | string                | The notification title                                                                                                     |
| notification.content   | string                | The notification content                                                                                                   |
| notification.timestamp | LocalDateTime         | The notification local date time                                                                                           |
| notification.subject   | Object                | An optional object containing specifics of the notification                                                                |
| baseUrl                | string                | Dependency Track base url                                                                                                  |
| subject                | Specific              | An optional object containing specifics of the notification. It is casted whereas notification.subject is a generic Object |
| subjectJson            | javax.json.JsonObject | An optional JSON representation of the subject                                                                             |

> The format of the subject object will vary depending on the scope and group of notification. Not all fields in the
> subject will be present at all times. Some fields are optional since the underlying fields in the datamodel are optional.
> The section below will describe the portfolio notifications in JSON format.

#### NEW_VULNERABILITY
This type of notification will always contain:
* 1 component
* 1 vulnerability
* 1 or more affected projects

```json
{
  "notification": {
    "level": "INFORMATIONAL",
    "scope": "PORTFOLIO",
    "group": "NEW_VULNERABILITY",
    "timestamp": "2018-08-27T23:26:22.961",
    "title": "New Vulnerability Identified",
    "content": "Apache Axis 1.4 and earlier, as used in PayPal Payments Pro, PayPal Mass Pay, PayPal Transactional Information SOAP, the Java Message Service implementation in Apache ActiveMQ, and other products, does not verify that the server hostname matches a domain name in the subject's Common Name (CN) or subjectAltName field of the X.509 certificate, which allows man-in-the-middle attackers to spoof SSL servers via an arbitrary valid certificate.",
    "subject": {
      "component": {
        "uuid": "4d5cd8df-cff7-4212-a038-91ae4ab79396",
        "group": "apache",
        "name": "axis",
        "version": "1.4",
        "md5": "03dcfdd88502505cc5a805a128bfdd8d",
        "sha1": "94a9ce681a42d0352b3ad22659f67835e560d107",
        "sha256": "05aebb421d0615875b4bf03497e041fe861bf0556c3045d8dda47e29241ffdd3",
        "purl": "pkg:maven/apache/axis@1.4"
      },
      "vulnerability": {
        "uuid": "941a93f5-e06b-4304-84de-4d788eeb4969",
        "vulnId": "CVE-2012-5784",
        "source": "NVD",
        "aliases": [
          {
            "vulnId": "GHSA-55w9-c3g2-4rrh",
            "source": "GITHUB"
          }
        ],
        "description": "Apache Axis 1.4 and earlier, as used in PayPal Payments Pro, PayPal Mass Pay, PayPal Transactional Information SOAP, the Java Message Service implementation in Apache ActiveMQ, and other products, does not verify that the server hostname matches a domain name in the subject's Common Name (CN) or subjectAltName field of the X.509 certificate, which allows man-in-the-middle attackers to spoof SSL servers via an arbitrary valid certificate.",
        "cvssv2": 5.8,
        "severity": "MEDIUM",
        "cwe": {
          "cweId": 20,
          "name": "Improper Input Validation"
        },
        "cwes": [
          {
            "cweId": 20,
            "name": "Improper Input Validation"
          }
        ]
      },
      "affectedProjects": [
        {
          "uuid": "6fb1820f-5280-4577-ac51-40124aabe307",
          "name": "Acme Example",
          "version": "1.0.0"
        }
      ]
    }
  }
}
```

> The `cwe` field is deprecated and will be removed in a later version. Please use `cwes` instead.

#### NEW_VULNERABILITIES_SUMMARY

A summary of new vulnerabilities identified in a set of projects. "New" in this context refers to vulnerabilities
identified *since the notification was last triggered*. For example, if the notification is scheduled to trigger
every day at 8AM (cron expression: `0 8 * * *`) it will always contain newly identified vulnerabilities since
the last day at 8AM.

Note that this notification can not be configured to cover the entire portfolio, but only a limited set of
projects. This limitation exists to prevent payloads from growing too large.

```json
{
  "notification": {
    "level": "INFORMATIONAL",
    "scope": "PORTFOLIO",
    "group": "NEW_VULNERABILITIES_SUMMARY",
    "timestamp": "1970-01-01T18:31:06.000000666",
    "title": "New Vulnerabilities Summary",
    "content": "Identified 1 new vulnerabilities across 1 projects and 1 components since 1970-01-01T00:01:06Z, of which 1 are suppressed.",
    "subject": {
      "overview": {
        "affectedProjectsCount": 1,
        "affectedComponentsCount": 1,
        "newVulnerabilitiesCount": 0,
        "newVulnerabilitiesCountBySeverity": {},
        "suppressedNewVulnerabilitiesCount": 1,
        "totalNewVulnerabilitiesCount": 1
      },
      "summary": {
        "projectSummaries": [
          {
            "project": {
              "uuid": "c9c9539a-e381-4b36-ac52-6a7ab83b2c95",
              "name": "projectName",
              "version": "projectVersion",
              "description": "projectDescription",
              "purl": "pkg:maven/org.acme/projectName@projectVersion",
              "tags": "tag1,tag2"
            },
            "summary": {
              "newVulnerabilitiesCountBySeverity": {},
              "suppressedNewVulnerabilitiesCountBySeverity": {
                "MEDIUM": 1
              },
              "totalNewVulnerabilitiesCountBySeverity": {
                "MEDIUM": 1
              }
            }
          }
        ]
      },
      "details": {
        "findingsByProject": [
          {
            "project": {
              "uuid": "c9c9539a-e381-4b36-ac52-6a7ab83b2c95",
              "name": "projectName",
              "version": "projectVersion",
              "description": "projectDescription",
              "purl": "pkg:maven/org.acme/projectName@projectVersion",
              "tags": "tag1,tag2"
            },
            "findings": [
              {
                "component": {
                  "uuid": "94f87321-a5d1-4c2f-b2fe-95165debebc6",
                  "name": "componentName",
                  "version": "componentVersion"
                },
                "vulnerability": {
                  "uuid": "bccec5d5-ec21-4958-b3e8-22a7a866a05a",
                  "vulnId": "INT-001",
                  "source": "INTERNAL",
                  "aliases": [
                    {
                      "source": "OSV",
                      "vulnId": "OSV-001"
                    }
                  ],
                  "title": "vulnerabilityTitle",
                  "subtitle": "vulnerabilitySubTitle",
                  "description": "vulnerabilityDescription",
                  "recommendation": "vulnerabilityRecommendation",
                  "cvssv2": 5.5,
                  "cvssv3": 6.6,
                  "owaspRRLikelihood": 1.1,
                  "owaspRRTechnicalImpact": 2.2,
                  "owaspRRBusinessImpact": 3.3,
                  "severity": "MEDIUM",
                  "cwe": {
                    "cweId": 666,
                    "name": "Operation on Resource in Wrong Phase of Lifetime"
                  },
                  "cwes": [
                    {
                      "cweId": 666,
                      "name": "Operation on Resource in Wrong Phase of Lifetime"
                    },
                    {
                      "cweId": 777,
                      "name": "Regular Expression without Anchors"
                    }
                  ]
                },
                "analyzer": "INTERNAL_ANALYZER",
                "attributedOn": "1970-01-01T18:31:06Z",
                "suppressed": true,
                "analysisState": "FALSE_POSITIVE"
              }
            ]
          }
        ]
      },
      "since": "1970-01-01T00:01:06Z"
    }
  }
}
```

#### NEW_VULNERABLE_DEPENDENCY
This type of notification will always contain:
* 1 project
* 1 component
* 1 or more vulnerabilities

```json
{
  "notification": {
    "level": "INFORMATIONAL",
    "scope": "PORTFOLIO",
    "group": "NEW_VULNERABLE_DEPENDENCY",
    "timestamp": "2018-08-27T23:23:00.145",
    "title": "Vulnerable Dependency Introduced",
    "content": "A dependency was introduced that contains 1 known vulnerability",
    "subject": {
      "project": {
        "uuid": "6fb1820f-5280-4577-ac51-40124aabe307",
        "name": "Acme Example",
        "version": "1.0.0"
      },
      "component": {
        "uuid": "4d5cd8df-cff7-4212-a038-91ae4ab79396",
        "group": "apache",
        "name": "axis",
        "version": "1.4",
        "md5": "03dcfdd88502505cc5a805a128bfdd8d",
        "sha1": "94a9ce681a42d0352b3ad22659f67835e560d107",
        "sha256": "05aebb421d0615875b4bf03497e041fe861bf0556c3045d8dda47e29241ffdd3",
        "purl": "pkg:maven/apache/axis@1.4"
      },
      "vulnerabilities": [
        {
          "uuid": "941a93f5-e06b-4304-84de-4d788eeb4969",
          "vulnId": "CVE-2012-5784",
          "source": "NVD",
          "aliases": [
            {
              "vulnId": "GHSA-55w9-c3g2-4rrh",
              "source": "GITHUB"
            }
          ],
          "description": "Apache Axis 1.4 and earlier, as used in PayPal Payments Pro, PayPal Mass Pay, PayPal Transactional Information SOAP, the Java Message Service implementation in Apache ActiveMQ, and other products, does not verify that the server hostname matches a domain name in the subject's Common Name (CN) or subjectAltName field of the X.509 certificate, which allows man-in-the-middle attackers to spoof SSL servers via an arbitrary valid certificate.",
          "cvssv2": 5.8,
          "severity": "MEDIUM",
          "cwe": {
            "cweId": 20,
            "name": "Improper Input Validation"
          },
          "cwes": [
            {
              "cweId": 20,
              "name": "Improper Input Validation"
            }
          ]
        },
        {
          "uuid": "ca318ca7-616f-4af0-9c6b-15b8e208c586",
          "vulnId": "CVE-2014-3596",
          "source": "NVD",
          "aliases": [],
          "description": "The getCN function in Apache Axis 1.4 and earlier does not properly verify that the server hostname matches a domain name in the subject's Common Name (CN) or subjectAltName field of the X.509 certificate, which allows man-in-the-middle attackers to spoof SSL servers via a certificate with a subject that specifies a common name in a field that is not the CN field.  NOTE: this issue exists because of an incomplete fix for CVE-2012-5784.\n\n<a href=\"http://cwe.mitre.org/data/definitions/297.html\" target=\"_blank\">CWE-297: Improper Validation of Certificate with Host Mismatch</a>",
          "cvssv2": 5.8,
          "severity": "MEDIUM"
        }
      ]
    }
  }
}
```

> The `cwe` field is deprecated and will be removed in a later version. Please use `cwes` instead.

#### PROJECT_AUDIT_CHANGE and GLOBAL_AUDIT_CHANGE
This type of notification will always contain:
* 1 component
* 1 vulnerability
* 1 analysis
* 1 or more affected projects

In the case of PROJECT_AUDIT_CHANGE, the list of affected projects will always be equal to 1, whereas
GLOBAL_AUDIT_CHANGE notifications will list all projects that are currently affected.

Audit change notifications are fired whenever the analysis state changes or when the finding is suppressed or unsuppressed.

```json
{
  "notification": {
    "level": "INFORMATIONAL",
    "scope": "PORTFOLIO",
    "group": "PROJECT_AUDIT_CHANGE",
    "timestamp": "2018-08-28T23:53:54.414",
    "title": "Analysis Decision: Exploitable",
    "content": "An analysis decision was made to a finding affecting a project",
    "subject": {
      "component": {
        "uuid": "4d0da61c-b462-4895-b296-da0b4bb34744",
        "group": "apache",
        "name": "axis",
        "version": "1.4"
      },
      "vulnerability": {
        "uuid": "941a93f5-e06b-4304-84de-4d788eeb4969",
        "vulnId": "CVE-2012-5784",
        "source": "NVD",
        "aliases": [
          {
            "vulnId": "GHSA-55w9-c3g2-4rrh",
            "source": "GITHUB"
          }
        ],
        "description": "Apache Axis 1.4 and earlier, as used in PayPal Payments Pro, PayPal Mass Pay, PayPal Transactional Information SOAP, the Java Message Service implementation in Apache ActiveMQ, and other products, does not verify that the server hostname matches a domain name in the subject's Common Name (CN) or subjectAltName field of the X.509 certificate, which allows man-in-the-middle attackers to spoof SSL servers via an arbitrary valid certificate.",
        "cvssv2": 5.8,
        "severity": "MEDIUM"
      },
      "analysis": {
        "suppressed": false,
        "state": "EXPLOITABLE",
        "project": "6fb1820f-5280-4577-ac51-40124aabe307",
        "component": "4d0da61c-b462-4895-b296-da0b4bb34744",
        "vulnerability": "941a93f5-e06b-4304-84de-4d788eeb4969"
      },
      "affectedProjects": [
        {
          "uuid": "6fb1820f-5280-4577-ac51-40124aabe307",
          "name": "Acme Example",
          "version": "1.0.0"
        }
      ]
    }
  }
}
```

#### BOM_CONSUMED and BOM_PROCESSED
This type of notification will always contain:
* 1 project
* 1 bom

```json
{
  "notification": {
    "level": "INFORMATIONAL",
    "scope": "PORTFOLIO",
    "group": "BOM_CONSUMED",
    "timestamp": "2019-08-23T21:57:57.418",
    "title": "Bill-of-Materials Consumed",
    "content": "A CycloneDX BOM was consumed and will be processed",
    "subject": {
      "project": {
        "uuid": "6fb1820f-5280-4577-ac51-40124aabe307",
        "name": "Acme Example",
        "version": "1.0.0"
      },
      "bom": {
        "content": "<base64 encoded bom>",
        "format": "CycloneDX",
        "specVersion": "1.1"
      }
    }
  }
}
```

#### POLICY_VIOLATION

```json
{
  "notification": {
    "level": "INFORMATIONAL",
    "scope": "PORTFOLIO",
    "group": "POLICY_VIOLATION",
    "timestamp": "2022-05-12T23:07:59.611303",
    "title": "Policy Violation",
    "content": "A operational policy violation occurred",
    "subject": {
      "project": {
        "uuid": "7a36e5c0-9f09-42dd-b401-360da56c2abe",
        "name": "Acme Example",
        "version": "1.0.0"
      },
      "component": {
        "uuid": "4e04c695-9acd-46fc-9bf6-ed23d7eb551e",
        "group": "apache",
        "name": "axis",
        "version": "1.4"
      },
      "policyViolation": {
        "uuid": "c82fcb50-029a-4636-a657-96242b20680e",
        "type": "OPERATIONAL",
        "timestamp": "2022-05-12T20:34:46Z",
        "policyCondition": {
          "uuid": "8e5c0a5b-71fb-45c5-afac-6c6a99742cbe",
          "subject": "COORDINATES",
          "operator": "MATCHES",
          "value": "{\"group\":\"apache\",\"name\":\"axis\",\"version\":\"*\"}",
          "policy": {
            "uuid": "6d4c7398-689a-4ec7-b5c5-9abb6b5393e9",
            "name": "Banned Components",
            "violationState": "FAIL"
          }
        }
      }
    }
  }
}
```

#### NEW_POLICY_VIOLATIONS_SUMMARY

A summary of new policy violations identified in a set of projects. "New" in this context refers to violations
identified *since the notification was last triggered*. For example, if the notification is scheduled to trigger
every day at 8AM (cron expression: `0 8 * * *`) it will always contain newly identified violations since
the last day at 8AM.

Note that this notification can not be configured to cover the entire portfolio, but only a limited set of
projects. This limitation exists to prevent payloads from growing too large.

```json
{
  "notification": {
    "level": "INFORMATIONAL",
    "scope": "PORTFOLIO",
    "group": "NEW_POLICY_VIOLATIONS_SUMMARY",
    "timestamp": "1970-01-01T18:31:06.000000666",
    "title": "New Policy Violations Summary",
    "content": "Identified 1 new policy violations across 1 project and 1 components since 1970-01-01T00:01:06Z, of which 0 are suppressed.",
    "subject": {
      "overview": {
        "affectedProjectsCount": 1,
        "affectedComponentsCount": 1,
        "newViolationsCount": 1,
        "suppressedNewViolationsCount": 0,
        "totalNewViolationsCount": 1
      },
      "summary": {
        "projectSummaries": [
          {
            "project": {
              "uuid": "c9c9539a-e381-4b36-ac52-6a7ab83b2c95",
              "name": "projectName",
              "version": "projectVersion",
              "description": "projectDescription",
              "purl": "pkg:maven/org.acme/projectName@projectVersion",
              "tags": "tag1,tag2"
            },
            "summary": {
              "newViolationsCountByType": {
                "LICENSE": 1
              },
              "suppressedNewViolationsCountByType": {},
              "totalNewViolationsCountByType": {
                "LICENSE": 1
              }
            }
          }
        ]
      },
      "details": {
        "violationsByProject": [
          {
            "project": {
              "uuid": "c9c9539a-e381-4b36-ac52-6a7ab83b2c95",
              "name": "projectName",
              "version": "projectVersion",
              "description": "projectDescription",
              "purl": "pkg:maven/org.acme/projectName@projectVersion",
              "tags": "tag1,tag2"
            },
            "violations": [
              {
                "uuid": "924eaf86-454d-49f5-96c0-71d9008ac614",
                "component": {
                  "uuid": "94f87321-a5d1-4c2f-b2fe-95165debebc6",
                  "name": "componentName",
                  "version": "componentVersion"
                },
                "policyCondition": {
                  "uuid": "b029fce3-96f2-4c4a-9049-61070e9b6ea6",
                  "subject": "AGE",
                  "operator": "NUMERIC_EQUAL",
                  "value": "P666D",
                  "policy": {
                    "uuid": "8d2f1ec1-3625-48c6-97c4-2a7553c7a376",
                    "name": "policyName",
                    "violationState": "INFO"
                  }
                },
                "type": "LICENSE",
                "timestamp": "1970-01-01T18:31:06Z",
                "suppressed": false,
                "analysisState": "APPROVED"
              }
            ]
          }
        ]
      },
      "since": "1970-01-01T00:01:06Z"
    }
  }
}
```

#### USER_CREATED

```json
{
  "notification": {
    "level": "INFORMATIONAL",
    "scope": "SYSTEM",
    "group": "USER_CREATED",
    "timestamp": "2022-05-12T23:07:59.611303",
    "title": "User Created",
    "content": "LDAP user created",
    "subject": {
      "id": "user",
      "username": "user",
      "name": "User 1",
      "email": "user@example.com",
      }
  }
}
```

#### USER_DELETED

```json
{
  "notification": {
    "level": "INFORMATIONAL",
    "scope": "SYSTEM",
    "group": "USER_CREATED",
    "timestamp": "2022-05-12T23:07:59.611303",
    "title": "User Deleted",
    "content": "LDAP user deleted",
    "subject": {
      "username": "user",
    }
  }
}
```


### Override of default templates
Default publishers are installed in the database at startup using templates retrieved in Dependency-Track classpath. Those publishers are **read-only** by default.
Dependency-Track can be configured from the administrative page to allow an override of the default templates. This requires SYSTEM_CONFIGURATION permission.
The default publishers will still be **read-only** except for their templates. You will not be able to delete or add new default publishers.

![notification publisher general configuration](/images/screenshots/notifications-publisher-configure.png)

Switch on enable default template override flag and provide a filesystem base directory to search for custom templates.

![notification publisher general configuration](/images/screenshots/notifications-publisher-override-template.png)

> The default template override flag is switched off by default and can set at initial startup with environment variable `DEFAULT_TEMPLATES_OVERRIDE_ENABLED`.
> The default templates base directory is set to ${user.home} by default and can be set at initial startup with environment variable `DEFAULT_TEMPLATES_OVERRIDE_BASE_DIRECTORY`.

To override all default templates, you must have the following [Pebble Templates](https://pebbletemplates.io/) template files inside the configured base directory.

```bash
<base directory>/templates/notification/publisher/slack.peb
<base directory>/templates/notification/publisher/msteams.peb
<base directory>/templates/notification/publisher/mattermost.peb
<base directory>/templates/notification/publisher/email.peb
<base directory>/templates/notification/publisher/console.peb
<base directory>/templates/notification/publisher/webhook.peb
<base directory>/templates/notification/publisher/cswebex.peb
<base directory>/templates/notification/publisher/jira.peb
```

**A restart is needed for the modification to be taken into account.**

> When deploying Dependency Track in a container environment, you must mount a volume or a configmap to supply custom Pebbles template.
> Please refer to [deploy-docker](../../getting-started/deploy-docker/) for details.

> **You must set appropriate rights to the provided Pebble templates base directory in order to prevent untrusted third party to supply a fraudulent template which can lead to a code execution vulnerability.**

You can, at any time, restore the default templates bundled with Dependency-Track as shown below. Please note that restoring the default templates will automatically set the templates override flag to **false**.

![notification publisher general configuration](/images/screenshots/notifications-publisher-restore-default-template.png)

### Creation of publisher
Creating publishers can be performed from the administrative page which requires SYSTEM_CONFIGURATION permission.

![create notification publisher](/images/screenshots/notifications-create-publisher.png)

Once the publisher is created, you can modify, clone or delete it.

![modify notification publisher](/images/screenshots/notifications-modify-publisher.png)

> Deleting a publisher will delete all related notifications.

## Configuring Notifications
Creating notifications can be performed from the administrative page which requires the SYSTEM_CONFIGURATION permission.
Notifications are configured in two easy steps. First create a new alert by specifying the name, scope, notification level,
and publisher to use.

![create notification](/images/screenshots/notifications-create.png)

Once the alert is created it can be configured. Start with selecting from the list of available notification groups
to notify on. Then specify the destination:
- For the Email publisher: it's a comma separated list of email addresses
- For Slack, Mattermost and Microsoft Teams: it's the incoming webhook URL generated from each respective
- For Jira: it's the project key where the issue will be created. The Jira alert also asks for the Jira ticket type ('Task', 'Story', etc., refer to the Jira documentation for more details) to be created
- For the Outbound Webhook publisher: it's a URL to which to publish the notification

![configure notification](/images/screenshots/notifications-configure.png)

By default, portfolio notifications are published regardless of which project is affected. This behavior can be altered
by optionally limiting the projects. Expand the 'Limit To' button to reveal and configure the list of projects.

Since v4.12, it is also possible to limit notifications to projects with a specific tag.
Multiple tags can be configured. Projects must have *at least one* of the configured tags
in order for the notification to be sent.

If both *Limit to Projects* and *Limit to Tags* are configured, projects must match *any*
of the two conditions. They are disjunctive.

When making use of parent-child relationships of projects, it can be desirable to configure notifications
only for a parent project, and have its children inherit the notification configuration. This can be achieved
by enabling the *Include active children of projects* option in the *Limit To* section.
Both *Limit to projects* and *Limit to tags* are inherited.

## Configuring Scheduled Notifications

To create a scheduled notification, select the trigger type *Schedule* when creating an alert:

![](/images/screenshots/notifications-create-scheduled.png)

> As of v4.13.0, only the *Email* and *Outbound Webhook* publishers are capable of utilizing the full
> content of scheduled notifications. Messenger publishers such as Slack are more likely to reject large
> payloads, which is why their support for this feature was deprioritized. In the meantime, user may
> [create their own publisher](#creation-of-publisher), and taylor it to their needs and constraints.

The interval at which scheduled notifications are triggered is configured using [cron] expressions.

A cron expression is generally structured as follows:

```
* * * * *
| | | | |
| | | | day of the week (0-6, [Sunday to Saturday])
| | | month of the year (1-12)
| | day of the month (1-31)
| hour of the day (0-23)
minute of the hour (0-59)
```

Where the wildcard `*` simply means *any*. For example, `* * * * *` means *every minute*.

Dependency-Track will check for notifications with due schedules *every minute*, and process all of them *serially*.  
This means that notifications will almost never arrive exactly on the minute, but rather with a slight delay of a few minutes.

* The default interval of newly created scheduled notifications is *hourly*.
* Expressions are evaluated in the UTC timezone, which means that "every day at 8AM" refers to 8AM UTC.
* Consider using tools such as [crontab guru] to construct an expression.

For every scheduled notification rule, Dependency-Track will take note of when it was last triggered successfully.  
The next planned trigger is calculated based on the configured cron expression, and the timestamp of the last successful trigger.

Both the last successful, and the next planned trigger timestamp can be viewed in a notification rule's configuration panel.

To further reduce the noise produced by the system, users can opt into skipping the publishing of a notification,  
if no new data has been identified since the last time it triggered.

Certain notification groups may require the alert to be limited to specific projects.  
This is to protect the system from generating payloads that are too resource intensive to compute,  
or too large for receiving systems to accept.

![](/images/screenshots/notifications-configure-scheduled.png)

## Outbound Webhooks
With outbound webhooks, notifications and all of their relevant details can be delivered via HTTP to an endpoint
configured through Dependency-Track's notification settings.

Notifications are sent via HTTP(S) POST and contain a JSON payload. The payload has the format described above in the templating section.

## Debugging missing notifications

Missing notifications may be caused by a variety of issues:

* Network outage between Dependency-Track and notification destination
* Faulty proxy configuration, causing Dependency-Track to be unable to reach the notification destination
* Misconfiguration of notification rules in Dependency-Track, causing the notification to not be sent
* Bug in Dependency-Track's notification routing mechanism, causing the notification to not be sent
* Syntactically invalid notification content, causing the destination system to fail upon parsing it

Generally, when Dependency-Track *fails* to deliver a notification to the destination, it will emit log messages
with level `WARN` or `ERROR` about it.

As of Dependency-Track v4.10, notification rules can additionally be configured to emit a log message with level `INFO`
when publishing *succeeded*. Other than for debugging missing notifications, enabling this may also be useful in cases
where notification volume needs to be audited or monitored. Note that this can cause a significant increase in log
output, depending on how busy the system is.

Logs include high-level details about the notification itself, its subjects, as well as the matched rule. For example:

```
INFO [WebhookPublisher] Destination acknowledged reception of notification with status code 200 (PublishContext{notificationGroup=NEW_VULNERABILITY, notificationLevel=INFORMATIONAL, notificationScope=PORTFOLIO, notificationTimestamp=2023-11-20T19:14:43.427901Z, notificationSubjects={component=Component[uuid=9f608f76-382c-4e05-b05f-7f69f2f6f507, group=org.apache.commons, name=commons-compress, version=1.23.0], projects=[Project[uuid=79de8ff7-6929-4fa4-8bff-ddec2424cbd2, name=Acme App, version=1.2.3]], vulnerability=Vulnerability[id=GHSA-cgwf-w82q-5jrr, source=GITHUB]}, ruleName=Foo, ruleScope=PORTFOLIO, ruleLevel=INFORMATIONAL})
```

For Webhook-based notifications (*Outbound Webhook*, *Slack*, *MS Teams*, *Mattermost*, *Cisco WebEx*, *JIRA*),
services like [Request Bin](https://pipedream.com/requestbin) can be used to manually verify that notifications are sent:

* Create a (private) Request Bin at https://pipedream.com/requestbin
* Copy the generated endpoint URL to the *Destination* field of the notification rule
* Ensure the desired *Groups* are selected for the notification rule
* Perform an action that triggers any of the selected groups
  * e.g. for group `BOM_PROCESSED`, upload a BOM
* Observe the Request Bin output for any incoming requests

If requests make it to the Bin, the problem is not in Dependency-Track.

[cron]: https://en.wikipedia.org/wiki/Cron
[crontab guru]: https://crontab.guru/