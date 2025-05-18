/*
 * This file is part of Dependency-Track.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) OWASP Foundation. All Rights Reserved.
 */
package org.dependencytrack.notification.publisher;

import org.junit.jupiter.api.Test;

import static com.github.tomakehurst.wiremock.client.WireMock.anyUrl;
import static com.github.tomakehurst.wiremock.client.WireMock.equalTo;
import static com.github.tomakehurst.wiremock.client.WireMock.equalToJson;
import static com.github.tomakehurst.wiremock.client.WireMock.postRequestedFor;
import static com.github.tomakehurst.wiremock.client.WireMock.verify;

public class WebhookPublisherTest extends AbstractWebhookPublisherTest<WebhookPublisher> {

    public WebhookPublisherTest() {
        super(DefaultNotificationPublishers.WEBHOOK, new WebhookPublisher());
    }

    @Test
    public void testInformWithBomConsumedNotification() {
        super.baseTestInformWithBomConsumedNotification();

        verify(postRequestedFor(anyUrl())
                .withHeader("Content-Type", equalTo("application/json"))
                .withRequestBody(equalToJson("""
                        {
                          "notification" : {
                            "level" : "INFORMATIONAL",
                            "scope" : "PORTFOLIO",
                            "group" : "BOM_CONSUMED",
                            "timestamp" : "1970-01-01T18:31:06.000000666",
                            "title" : "Bill of Materials Consumed",
                            "content" : "A CycloneDX BOM was consumed and will be processed",
                            "subject" : {
                              "project" : {
                                "uuid" : "c9c9539a-e381-4b36-ac52-6a7ab83b2c95",
                                "name" : "projectName",
                                "version" : "projectVersion",
                                "description" : "projectDescription",
                                "purl" : "pkg:maven/org.acme/projectName@projectVersion",
                                "tags" : "tag1,tag2"
                              },
                              "bom" : {
                                "content" : "bomContent",
                                "format" : "CycloneDX",
                                "specVersion" : "1.5"
                              }
                            }
                          }
                        }
                        """)));
    }

    @Test
    public void testInformWithBomProcessingFailedNotification() {
        super.baseTestInformWithBomProcessingFailedNotification();

        verify(postRequestedFor(anyUrl())
                .withHeader("Content-Type", equalTo("application/json"))
                .withRequestBody(equalToJson("""
                        {
                          "notification" : {
                            "level" : "ERROR",
                            "scope" : "PORTFOLIO",
                            "group" : "BOM_PROCESSING_FAILED",
                            "timestamp" : "1970-01-01T18:31:06.000000666",
                            "title" : "Bill of Materials Processing Failed",
                            "content" : "An error occurred while processing a BOM",
                            "subject" : {
                              "project" : {
                                "uuid" : "c9c9539a-e381-4b36-ac52-6a7ab83b2c95",
                                "name" : "projectName",
                                "version" : "projectVersion",
                                "description" : "projectDescription",
                                "purl" : "pkg:maven/org.acme/projectName@projectVersion",
                                "tags" : "tag1,tag2"
                              },
                              "bom" : {
                                "content" : "bomContent",
                                "format" : "CycloneDX",
                                "specVersion" : "1.5"
                              },
                              "cause" : "cause"
                            }
                          }
                        }
                        """)));
    }

    @Test
    public void testInformWithBomValidationFailedNotification() {
        super.baseTestInformWithBomValidationFailedNotification();

        verify(postRequestedFor(anyUrl())
                .withHeader("Content-Type", equalTo("application/json"))
                .withRequestBody(equalToJson("""
                        {
                          "notification" : {
                            "level" : "ERROR",
                            "scope" : "PORTFOLIO",
                            "group" : "BOM_VALIDATION_FAILED",
                            "timestamp" : "1970-01-01T00:20:34.000000888",
                            "title" : "Bill of Materials Validation Failed",
                            "content" : "An error occurred during BOM Validation",
                            "subject" : {
                              "project" : {
                                "uuid" : "c9c9539a-e381-4b36-ac52-6a7ab83b2c95",
                                "name" : "projectName",
                                "version" : "projectVersion",
                                "description" : "projectDescription",
                                "purl" : "pkg:maven/org.acme/projectName@projectVersion",
                                "tags" : "tag1,tag2"
                              },
                              "bom" : {
                                "content" : "bomContent",
                                "format" : "CycloneDX"
                              },
                              "errors" : "$.components[928].externalReferences[1].url: does not match the iri-reference pattern must be a valid RFC 3987 IRI-reference"
                            }
                          }
                        }
                        """)));
    }

    @Test
    public void testInformWithBomProcessingFailedNotificationAndNoSpecVersionInSubject() {
        super.baseTestInformWithBomProcessingFailedNotificationAndNoSpecVersionInSubject();

        verify(postRequestedFor(anyUrl())
                .withHeader("Content-Type", equalTo("application/json"))
                .withRequestBody(equalToJson("""
                        {
                          "notification" : {
                            "level" : "ERROR",
                            "scope" : "PORTFOLIO",
                            "group" : "BOM_PROCESSING_FAILED",
                            "timestamp" : "1970-01-01T18:31:06.000000666",
                            "title" : "Bill of Materials Processing Failed",
                            "content" : "An error occurred while processing a BOM",
                            "subject" : {
                              "project" : {
                                "uuid" : "c9c9539a-e381-4b36-ac52-6a7ab83b2c95",
                                "name" : "projectName",
                                "version" : "projectVersion",
                                "description" : "projectDescription",
                                "purl" : "pkg:maven/org.acme/projectName@projectVersion",
                                "tags" : "tag1,tag2"
                              },
                              "bom" : {
                                "content" : "bomContent",
                                "format" : "CycloneDX",
                                "specVersion" : "Unknown"
                              },
                              "cause" : "cause"
                            }
                          }
                        }
                        """)));
    }

    @Test
    public void testInformWithDataSourceMirroringNotification() {
        super.baseTestInformWithDataSourceMirroringNotification();

        verify(postRequestedFor(anyUrl())
                .withHeader("Content-Type", equalTo("application/json"))
                .withRequestBody(equalToJson("""
                        {
                          "notification": {
                            "level": "ERROR",
                            "scope": "SYSTEM",
                            "group": "DATASOURCE_MIRRORING",
                            "timestamp": "1970-01-01T18:31:06.000000666",
                            "title": "GitHub Advisory Mirroring",
                            "content": "An error occurred mirroring the contents of GitHub Advisories. Check log for details.",
                            "subject": null
                          }
                        }
                        """)));
    }

    @Test
    public void testInformWithNewVulnerabilityNotification() {
        super.baseTestInformWithNewVulnerabilityNotification();

        verify(postRequestedFor(anyUrl())
                .withHeader("Content-Type", equalTo("application/json"))
                .withRequestBody(equalToJson("""
                        {
                          "notification": {
                            "level": "INFORMATIONAL",
                            "scope": "PORTFOLIO",
                            "group": "NEW_VULNERABILITY",
                            "timestamp": "1970-01-01T18:31:06.000000666",
                            "title": "New Vulnerability Identified",
                            "content": "",
                            "subject": {
                              "component": {
                                "uuid": "94f87321-a5d1-4c2f-b2fe-95165debebc6",
                                "name": "componentName",
                                "version": "componentVersion"
                              },
                              "vulnerabilityAnalysisLevel": "BOM_UPLOAD_ANALYSIS",
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
                              "affectedProjects": [
                                {
                                  "uuid": "c9c9539a-e381-4b36-ac52-6a7ab83b2c95",
                                  "name": "projectName",
                                  "version": "projectVersion",
                                  "description": "projectDescription",
                                  "purl": "pkg:maven/org.acme/projectName@projectVersion",
                                  "tags": "tag1,tag2"
                                }
                              ]
                            }
                          }
                        }
                        """)));
    }

    @Test
    public void testInformWithNewVulnerableDependencyNotification() {
        super.baseTestInformWithNewVulnerableDependencyNotification();

        verify(postRequestedFor(anyUrl())
                .withHeader("Content-Type", equalTo("application/json"))
                .withRequestBody(equalToJson("""
                        {
                          "notification": {
                            "level": "INFORMATIONAL",
                            "scope": "PORTFOLIO",
                            "group": "NEW_VULNERABLE_DEPENDENCY",
                            "timestamp": "1970-01-01T18:31:06.000000666",
                            "title": "Vulnerable Dependency Introduced",
                            "content": "",
                            "subject": {
                              "project": {
                                "uuid": "c9c9539a-e381-4b36-ac52-6a7ab83b2c95",
                                "name": "projectName",
                                "version": "projectVersion",
                                "description": "projectDescription",
                                "purl": "pkg:maven/org.acme/projectName@projectVersion",
                                "tags": "tag1,tag2"
                              },
                              "component": {
                                "uuid": "94f87321-a5d1-4c2f-b2fe-95165debebc6",
                                "name": "componentName",
                                "version": "componentVersion"
                              },
                              "vulnerabilities": [
                                {
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
                                }
                              ]
                            }
                          }
                        }
                        """)));
    }

    @Test
    public void testInformWithProjectAuditChangeNotification() {
        super.baseTestInformWithProjectAuditChangeNotification();

        verify(postRequestedFor(anyUrl())
                .withHeader("Content-Type", equalTo("application/json"))
                .withRequestBody(equalToJson("""
                        {
                          "notification": {
                            "level": "INFORMATIONAL",
                            "scope": "PORTFOLIO",
                            "group": "PROJECT_AUDIT_CHANGE",
                            "timestamp": "1970-01-01T18:31:06.000000666",
                            "title": "Analysis Decision: Finding Suppressed",
                            "content": "",
                            "subject": {
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
                              "analysis": {
                                "suppressed": true,
                                "state": "FALSE_POSITIVE",
                                "project": "c9c9539a-e381-4b36-ac52-6a7ab83b2c95",
                                "component": "94f87321-a5d1-4c2f-b2fe-95165debebc6",
                                "vulnerability": "bccec5d5-ec21-4958-b3e8-22a7a866a05a"
                              },
                              "affectedProjects": [
                                {
                                  "uuid": "c9c9539a-e381-4b36-ac52-6a7ab83b2c95",
                                  "name": "projectName",
                                  "version": "projectVersion",
                                  "description": "projectDescription",
                                  "purl": "pkg:maven/org.acme/projectName@projectVersion",
                                  "tags": "tag1,tag2"
                                }
                              ]
                            }
                          }
                        }
                        """)));
    }

    @Test
    public void testPublishWithScheduledNewVulnerabilitiesNotification() {
        super.baseTestPublishWithScheduledNewVulnerabilitiesNotification();

        verify(postRequestedFor(anyUrl())
                .withHeader("Content-Type", equalTo("application/json"))
                .withRequestBody(equalToJson(/* language=JSON */ """
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
                        """)));
    }

    @Test
    public void testPublishWithScheduledNewPolicyViolationsNotification() {
        super.baseTestPublishWithScheduledNewPolicyViolationsNotification();

        verify(postRequestedFor(anyUrl())
                .withHeader("Content-Type", equalTo("application/json"))
                .withRequestBody(equalToJson(/* language=JSON */ """
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
                        """)));
    }
}
