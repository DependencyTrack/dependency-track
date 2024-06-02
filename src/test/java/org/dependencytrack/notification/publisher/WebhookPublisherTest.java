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

import static com.github.tomakehurst.wiremock.client.WireMock.anyUrl;
import static com.github.tomakehurst.wiremock.client.WireMock.equalTo;
import static com.github.tomakehurst.wiremock.client.WireMock.equalToJson;
import static com.github.tomakehurst.wiremock.client.WireMock.postRequestedFor;
import static com.github.tomakehurst.wiremock.client.WireMock.verify;

public class WebhookPublisherTest extends AbstractWebhookPublisherTest<WebhookPublisher> {

    public WebhookPublisherTest() {
        super(DefaultNotificationPublishers.WEBHOOK, new WebhookPublisher());
    }

    @Override
    public void testInformWithBomConsumedNotification() {
        super.testInformWithBomConsumedNotification();

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

    @Override
    public void testInformWithBomProcessingFailedNotification() {
        super.testInformWithBomProcessingFailedNotification();

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

    @Override
    public void testInformWithBomValidationFailedNotification() {
        super.testInformWithBomValidationFailedNotification();

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

    @Override
    public void testInformWithBomProcessingFailedNotificationAndNoSpecVersionInSubject() {
        super.testInformWithBomProcessingFailedNotificationAndNoSpecVersionInSubject();

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

    @Override
    public void testInformWithDataSourceMirroringNotification() {
        super.testInformWithDataSourceMirroringNotification();

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

    @Override
    public void testInformWithNewVulnerabilityNotification() {
        super.testInformWithNewVulnerabilityNotification();

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

    @Override
    public void testInformWithNewVulnerableDependencyNotification() {
        super.testInformWithNewVulnerableDependencyNotification();

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

    @Override
    public void testInformWithProjectAuditChangeNotification() {
        super.testInformWithProjectAuditChangeNotification();

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
}
