---
title: Notifications
category: Integrations
chapter: 6
order: 7
---

Dependency-Track includes a robust and configurable notification framework capable of alerting users or systems
to the presence of newly discovered vulnerabilities, previously known vulnerable components that are added to
projects, as well as providing notifications on various system and error conditions.


Dependency-Track notifications come in two flavors:

| Scope | Description |
| ------|-------------|
| SYSTEM    | Notifications on system-level informational and error conditions |
| PORTFOLIO | Notifications on objects in the portfolio such as vulnerabilities and audit decisions |


Each scope contains a set of notification groups that can be used to subscribe to.

| Scope | Group | Description                                                                                                                       |
| ------|-------|-----------------------------------------------------------------------------------------------------------------------------------|
| SYSTEM | ANALYZER | Notifications generated as a result of interacting with an external source of vulnerability intelligence                          |
| SYSTEM | DATASOURCE_MIRRORING | Notifications generated when performing mirroring of one of the supported datasources such as the NVD                             |
| SYSTEM | INDEXING_SERVICE | Notifications generated as a result of performing maintenance on Dependency-Tracks internal index used for global searching       |
| SYSTEM | FILE_SYSTEM | Notifications generated as a result of a file system operation. These are typically only generated on error conditions            |
| SYSTEM | REPOSITORY | Notifications generated as a result of interacting with one of the supported repositories such as Maven Central, RubyGems, or NPM |
| PORTFOLIO | NEW_VULNERABILITY | Notifications generated whenever a new vulnerability is identified                                                                |
| PORTFOLIO | NEW_VULNERABLE_DEPENDENCY | Notifications generated as a result of a vulnerable component becoming a dependency of a project                                  |
| PORTFOLIO | GLOBAL_AUDIT_CHANGE | Notifications generated whenever an analysis or suppression state has changed on a finding from a component (global)              |
| PORTFOLIO | PROJECT_AUDIT_CHANGE | Notifications generated whenever an analysis or suppression state has changed on a finding from a project                         |
| PORTFOLIO | BOM_CONSUMED | Notifications generated whenever a supported BOM is ingested and identified                                                       |
| PORTFOLIO | BOM_PROCESSED | Notifications generated after a supported BOM is ingested, identified, and successfully processed                                 |
| PORTFOLIO | POLICY_VIOLATION | Notifications generated whenever a policy violation is identified                                                                 |

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

### Templating

Dependency-Track uses [Pebble Templates](https://pebbletemplates.io/) to generate notifications.
The template context is enhanced with the following variables :

| Variable               | Type                  | Description                                                                                                                |
|------------------------|-----------------------|----------------------------------------------------------------------------------------------------------------------------|
| timestampEpochSecond   | long                  | The notification timestamp                                                                                                 |
| timestamp              | string                | The notification local date time in ISO 8601 format (i.e. uuuu-MM-dd'T'HH:mm:ss.SSSSSSSSS)                                |
| notification.level     | enum                  | One of INFORMATIONAL, WARNING, or ERROR                                                                                    |
| notification.scope     | string                | The high-level type of notification. One of SYSTEM or PORTFOLIO                                                            |
| notification.group     | string                | The specific type of notification                                                                                          |
| notification.title     | string                | The notification title                                                                                                     |
| notification.content   | string                | The notification content                                                                                                   |
| notification.timestamp | LocalDateTime         | The notification local date time                                                                                           |
| notification.subject   | Object                | An optional object containing specifics of the notification                                                                |
| baseUrl                | string                | Dependency Track base url                                                                                                  |
| subject                | Specific              | An optional object containing specifics of the notification. It is casted whereas notification.subject is a generic Object |
| subjectJson            | javax.json.JsonObject | An optional JSON representation of the subject                                                                            |

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
to notify on. Then specify the destination. The destination may be a comma speparated list of email addresses (when the Email publisher is used),
or a URL. In the case of Slack, Mattermost and Microsoft Teams, this will be the incoming webhook URL generated from each respective
platform. In the case of the Outbound Webhook publisher, this will be a URL to which to publish the notification.

![configure notification](/images/screenshots/notifications-configure.png)

By default, portfolio notifications are published regardless of which project is affected. This behavior can be altered
by optionally limiting the projects. Expand the 'Limit To' button to reveal and configure the list of projects.

## Outbound Webhooks
With outbound webhooks, notifications and all of their relevant details can be delivered via HTTP to an endpoint
configured through Dependency-Track's notification settings.

Notifications are sent via HTTP(S) POST and contain a JSON payload. The payload has the format described above in the templating section.