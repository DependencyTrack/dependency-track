---
title: Notifications
category: Integrations
chapter: 6
order: 7
---

Dependency-Track includes a robust and configurable notification framework capable of alerting users or systems
to the presence of newly discovered vulnerabilities, previously known vulnerable components that are added to
projects, as well as providing notifications on various system and error conditions.

The following notification publishers are included:

| Publisher | Description |
| ------|-------------|
| Slack   | Publishes notifications to Slack channels |
| Teams   | Publishes notifications to Microsoft Teams channels |
| WebEx   | Publishes notifications to Cisco WebEx channels |
| Webhook | Publishes notifications to a configurable endpoint |
| Email   | Sends notifications to an email address |
| Console | Displays notifications on the system console |


Dependency-Track notifications come in two flavors:

| Scope | Description |
| ------|-------------|
| SYSTEM    | Notifications on system-level informational and error conditions |
| PORTFOLIO | Notifications on objects in the portfolio such as vulnerabilities and audit decisions |


Each scope contains a set of notification groups that can be used to subscribe to.

| Scope | Group | Description |
| ------|-------|-------------|
| SYSTEM | ANALYZER | Notifications generated as a result of interacting with an external source of vulnerability intelligence |
| SYSTEM | DATASOURCE_MIRRORING | Notifications generated when performing mirroring of one of the supported datasources such as the NVD |
| SYSTEM | INDEXING_SERVICE | Notifications generated as a result of performing maintenance on Dependency-Tracks internal index used for global searching |
| SYSTEM | FILE_SYSTEM | Notifications generated as a result of a file system operation. These are typically only generated on error conditions |
| SYSTEM | REPOSITORY | Notifications generated as a result of interacting with one of the supported repositories such as Maven Central, RubyGems, or NPM |
| PORTFOLIO | NEW_VULNERABILITY | Notifications generated whenever a new vulnerability is identified |
| PORTFOLIO | NEW_VULNERABLE_DEPENDENCY | Notifications generated as a result of a vulnerable component becoming a dependency of a project |
| PORTFOLIO | GLOBAL_AUDIT_CHANGE | Notifications generated whenever an analysis or suppression state has changed on a finding from a component (global) |
| PORTFOLIO | PROJECT_AUDIT_CHANGE | Notifications generated whenever an analysis or suppression state has changed on a finding from a project |
| PORTFOLIO | BOM_CONSUMED | Notifications generated whenever a supported BOM is ingested and identified |
| PORTFOLIO | BOM_PROCESSED | Notifications generated after a supported BOM is ingested, identified, and successfully processed |


## Configuring Notifications
Creating notifications can be performed from the administrative page which requires the SYSTEM_CONFIGURATION permission.
Notifications are configured in two easy steps. First create a new alert by specifying the name, scope, notification level,
and publisher to use.

![create notification](/images/screenshots/notifications-create.png)

Once the alert is created it can be configured. Start with selecting from the list of available notification groups
to notify on. Then specify the destination. The destination may be a comma speparated list of email addresses (when the Email publisher is used),
or a URL. In the case of Slack and Microsoft Teams, this will be the incoming webhook URL generated from each respective
platform. In the case of the Outbound Webhook publisher, this will be a URL to which to publish the notification.

![configure notification](/images/screenshots/notifications-configure.png)

By default, portfolio notifications are published regardless of which project is affected. This behavior can be altered
by optionally limiting the projects. Expand the 'Limit To' button to reveal and configure the list of projects.

## Outbound Webhooks
With outbound webhooks, notifications and all of their relevant details can be delivered via HTTP to an endpoint
configured through Dependency-Track's notification settings.

Notifications are sent via HTTP(S) POST and contain a JSON payload. The payload has the following fields:

| Field | Description |
| ------|-------------|
| level | One of INFORMATIONAL, WARNING, or ERROR |
| scope | The high-level type of notification. One of SYSTEM or PORTFOLIO |
| group | The specific type of notification |
| timestamp | The timestamp the notification was generated |
| title | The title of the notification |
| content | A short description of the notification |
| subject | An optional object containing specifics of the notification |


> The format of the subject object will vary depending on the scope and group of notification. Not all fields in the
> subject will be present at all times. Some fields are optional since the underlying fields in the datamodel are optional.

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
        }
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
          }
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
