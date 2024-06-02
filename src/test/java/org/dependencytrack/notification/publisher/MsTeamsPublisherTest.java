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

public class MsTeamsPublisherTest extends AbstractWebhookPublisherTest<MsTeamsPublisher> {

    public MsTeamsPublisherTest() {
        super(DefaultNotificationPublishers.MS_TEAMS, new MsTeamsPublisher());
    }

    @Override
    public void testInformWithBomConsumedNotification() {
        super.testInformWithBomConsumedNotification();

        verify(postRequestedFor(anyUrl())
                .withHeader("Content-Type", equalTo("application/json"))
                .withRequestBody(equalToJson("""
                        {
                          "@type": "MessageCard",
                          "@context": "http://schema.org/extensions",
                          "summary": "Bill of Materials Consumed",
                          "title": "Bill of Materials Consumed",
                          "sections": [
                            {
                              "activityTitle": "Dependency-Track",
                              "activitySubtitle": "1970-01-01T18:31:06.000000666",
                              "activityImage": "https://raw.githubusercontent.com/DependencyTrack/branding/master/dt-logo-symbol-blue-background.png",
                              "facts": [
                                {
                                  "name": "Level",
                                  "value": "INFORMATIONAL"
                                },
                                {
                                  "name": "Scope",
                                  "value": "PORTFOLIO"
                                },
                                {
                                  "name": "Group",
                                  "value": "BOM_CONSUMED"
                                }
                              ],
                              "text": "A CycloneDX BOM was consumed and will be processed"
                            }
                          ]
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
                          "@type": "MessageCard",
                          "@context": "http://schema.org/extensions",
                          "summary": "Bill of Materials Processing Failed",
                          "title": "Bill of Materials Processing Failed",
                          "sections": [
                            {
                              "activityTitle": "Dependency-Track",
                              "activitySubtitle": "1970-01-01T18:31:06.000000666",
                              "activityImage": "https://raw.githubusercontent.com/DependencyTrack/branding/master/dt-logo-symbol-blue-background.png",
                              "facts": [
                                {
                                  "name": "Level",
                                  "value": "ERROR"
                                },
                                {
                                  "name": "Scope",
                                  "value": "PORTFOLIO"
                                },
                                {
                                  "name": "Group",
                                  "value": "BOM_PROCESSING_FAILED"
                                },
                                {
                                  "name": "Project",
                                  "value": "pkg:maven/org.acme/projectName@projectVersion"
                                },
                                {
                                  "name": "Project URL",
                                  "value": "https://example.com/projects/c9c9539a-e381-4b36-ac52-6a7ab83b2c95"
                                }
                              ],
                              "text": "An error occurred while processing a BOM"
                            }
                          ]
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
                          "@type": "MessageCard",
                          "@context": "http://schema.org/extensions",
                          "summary": "Bill of Materials Validation Failed",
                          "title": "Bill of Materials Validation Failed",
                          "sections": [
                            {
                              "activityTitle": "Dependency-Track",
                              "activitySubtitle": "1970-01-01T00:20:34.000000888",
                              "activityImage": "https://raw.githubusercontent.com/DependencyTrack/branding/master/dt-logo-symbol-blue-background.png",
                              "facts": [
                                {
                                  "name": "Level",
                                  "value": "ERROR"
                                },
                                {
                                  "name": "Scope",
                                  "value": "PORTFOLIO"
                                },
                                {
                                  "name": "Group",
                                  "value": "BOM_VALIDATION_FAILED"
                                },
                                {
                                  "name": "Project",
                                  "value": "pkg:maven/org.acme/projectName@projectVersion"
                                },
                                {
                                  "name": "Project URL",
                                  "value": "https://example.com/projects/c9c9539a-e381-4b36-ac52-6a7ab83b2c95"
                                },
                                {
                                  "name": "Errors",
                                  "value": "[$.components[928].externalReferences[1].url: does not match the iri-reference pattern must be a valid RFC 3987 IRI-reference]"
                                }
                              ],
                              "text": "An error occurred during BOM Validation"
                            }
                          ]
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
                          "@type": "MessageCard",
                          "@context": "http://schema.org/extensions",
                          "summary": "Bill of Materials Processing Failed",
                          "title": "Bill of Materials Processing Failed",
                          "sections": [
                            {
                              "activityTitle": "Dependency-Track",
                              "activitySubtitle": "1970-01-01T18:31:06.000000666",
                              "activityImage": "https://raw.githubusercontent.com/DependencyTrack/branding/master/dt-logo-symbol-blue-background.png",
                              "facts": [
                                {
                                  "name": "Level",
                                  "value": "ERROR"
                                },
                                {
                                  "name": "Scope",
                                  "value": "PORTFOLIO"
                                },
                                {
                                  "name": "Group",
                                  "value": "BOM_PROCESSING_FAILED"
                                },
                                {
                                  "name": "Project",
                                  "value": "pkg:maven/org.acme/projectName@projectVersion"
                                },
                                {
                                  "name": "Project URL",
                                  "value": "https://example.com/projects/c9c9539a-e381-4b36-ac52-6a7ab83b2c95"
                                }
                              ],
                              "text": "An error occurred while processing a BOM"
                            }
                          ]
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
                          "@type": "MessageCard",
                          "@context": "http://schema.org/extensions",
                          "summary": "GitHub Advisory Mirroring",
                          "title": "GitHub Advisory Mirroring",
                          "sections": [
                            {
                              "activityTitle": "Dependency-Track",
                              "activitySubtitle": "1970-01-01T18:31:06.000000666",
                              "activityImage": "https://raw.githubusercontent.com/DependencyTrack/branding/master/dt-logo-symbol-blue-background.png",
                              "facts": [
                                {
                                  "name": "Level",
                                  "value": "ERROR"
                                },
                                {
                                  "name": "Scope",
                                  "value": "SYSTEM"
                                },
                                {
                                  "name": "Group",
                                  "value": "DATASOURCE_MIRRORING"
                                }
                              ],
                              "text": "An error occurred mirroring the contents of GitHub Advisories. Check log for details."
                            }
                          ]
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
                          "@type": "MessageCard",
                          "@context": "http://schema.org/extensions",
                          "summary": "New Vulnerability Identified",
                          "title": "New Vulnerability Identified",
                          "sections": [
                            {
                              "activityTitle": "Dependency-Track",
                              "activitySubtitle": "1970-01-01T18:31:06.000000666",
                              "activityImage": "https://raw.githubusercontent.com/DependencyTrack/branding/master/dt-logo-symbol-blue-background.png",
                              "facts": [
                                {
                                  "name": "VulnID",
                                  "value": "INT-001"
                                },
                                {
                                  "name": "Severity",
                                  "value": "MEDIUM"
                                },
                                {
                                  "name": "Source",
                                  "value": "INTERNAL"
                                },
                                {
                                  "name": "Component",
                                  "value": "componentName : componentVersion"
                                }
                              ],
                              "text": ""
                            }
                          ]
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
                          "@type": "MessageCard",
                          "@context": "http://schema.org/extensions",
                          "summary": "Vulnerable Dependency Introduced",
                          "title": "Vulnerable Dependency Introduced",
                          "sections": [
                            {
                              "activityTitle": "Dependency-Track",
                              "activitySubtitle": "1970-01-01T18:31:06.000000666",
                              "activityImage": "https://raw.githubusercontent.com/DependencyTrack/branding/master/dt-logo-symbol-blue-background.png",
                              "facts": [
                                {
                                  "name": "Project",
                                  "value": "pkg:maven/org.acme/projectName@projectVersion"
                                },
                                {
                                  "name": "Component",
                                  "value": "componentName : componentVersion"
                                }
                              ],
                              "text": ""
                            }
                          ]
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
                          "@type": "MessageCard",
                          "@context": "http://schema.org/extensions",
                          "summary": "Analysis Decision: Finding Suppressed",
                          "title": "Analysis Decision: Finding Suppressed",
                          "sections": [
                            {
                              "activityTitle": "Dependency-Track",
                              "activitySubtitle": "1970-01-01T18:31:06.000000666",
                              "activityImage": "https://raw.githubusercontent.com/DependencyTrack/branding/master/dt-logo-symbol-blue-background.png",
                              "facts": [
                                {
                                  "name": "Analysis Type",
                                  "value": "Project Analysis"
                                },
                                {
                                  "name": "Analysis State",
                                  "value": "FALSE_POSITIVE"
                                },
                                {
                                  "name": "Suppressed",
                                  "value": "true"
                                },
                                {
                                  "name": "VulnID",
                                  "value": "INT-001"
                                },
                                {
                                  "name": "Severity",
                                  "value": "MEDIUM"
                                },
                                {
                                  "name": "Source",
                                  "value": "INTERNAL"
                                },
                                {
                                  "name": "Component",
                                  "value": "componentName : componentVersion"
                                },
                                {
                                  "name": "Project",
                                  "value": "pkg:maven/org.acme/projectName@projectVersion"
                                }
                              ],
                              "text": ""
                            }
                          ]
                        }
                        """)));
    }

}
