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

import alpine.model.ConfigProperty;
import org.junit.Test;

import static com.github.tomakehurst.wiremock.client.WireMock.anyUrl;
import static com.github.tomakehurst.wiremock.client.WireMock.equalTo;
import static com.github.tomakehurst.wiremock.client.WireMock.equalToJson;
import static com.github.tomakehurst.wiremock.client.WireMock.postRequestedFor;
import static com.github.tomakehurst.wiremock.client.WireMock.verify;
import static org.dependencytrack.model.ConfigPropertyConstants.GENERAL_BASE_URL;

public class SlackPublisherTest extends AbstractWebhookPublisherTest<SlackPublisher> {

    public SlackPublisherTest() {
        super(DefaultNotificationPublishers.SLACK, new SlackPublisher());
    }

    @Override
    public void testInformWithBomConsumedNotification() {
        super.testInformWithBomConsumedNotification();

        verify(postRequestedFor(anyUrl())
                .withHeader("Content-Type", equalTo("application/json"))
                .withRequestBody(equalToJson("""
                        {
                          "blocks": [
                            {
                              "type": "header",
                              "text": {
                                "type": "plain_text",
                                "text": "BOM_CONSUMED"
                              }
                            },
                            {
                              "type": "context",
                              "elements": [
                                {
                                  "text": "*INFORMATIONAL*  |  *PORTFOLIO*",
                                  "type": "mrkdwn"
                                }
                              ]
                            },
                            {
                              "type": "divider"
                            },
                            {
                              "type": "section",
                              "text": {
                                "text": "Bill of Materials Consumed",
                                "type": "plain_text"
                              }
                            },
                            {
                              "type": "section",
                              "text": {
                                "text": "A CycloneDX BOM was consumed and will be processed",
                                "type": "plain_text"
                              }
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
                          "blocks": [
                            {
                              "type": "header",
                              "text": {
                                "type": "plain_text",
                                "text": "BOM_PROCESSING_FAILED"
                              }
                            },
                            {
                              "type": "context",
                              "elements": [
                                {
                                  "text": "*ERROR*  |  *PORTFOLIO*",
                                  "type": "mrkdwn"
                                }
                              ]
                            },
                            {
                              "type": "divider"
                            },
                            {
                              "type": "section",
                              "text": {
                                "text": "Bill of Materials Processing Failed",
                                "type": "plain_text"
                              }
                            },
                            {
                              "type": "section",
                              "text": {
                                "text": "An error occurred while processing a BOM",
                                "type": "plain_text"
                              }
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
                          "blocks": [
                            {
                              "type": "header",
                              "text": {
                                "type": "plain_text",
                                "text": "BOM_VALIDATION_FAILED | pkg:maven/org.acme/projectName@projectVersion"
                              }
                            },
                            {
                              "type": "context",
                              "elements": [
                                {
                                  "text": "*ERROR*  |  *PORTFOLIO*",
                                  "type": "mrkdwn"
                                }
                              ]
                            },
                            {
                              "type": "divider"
                            },
                            {
                              "type": "section",
                              "text": {
                                "text": "Bill of Materials Validation Failed",
                                "type": "plain_text"
                              }
                            },
                            {
                              "type": "section",
                              "text": {
                                "text": "An error occurred during BOM Validation",
                                "type": "plain_text"
                              }
                            },
                            {
                                "type" : "section",
                                "text" : {
                                  "text" : "[$.components[928].externalReferences[1].url: does not match the iri-reference pattern must be a valid RFC 3987 IRI-reference]",
                                  "type" : "plain_text"
                                 }
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
                          "blocks": [
                            {
                              "type": "header",
                              "text": {
                                "type": "plain_text",
                                "text": "BOM_PROCESSING_FAILED"
                              }
                            },
                            {
                              "type": "context",
                              "elements": [
                                {
                                  "text": "*ERROR*  |  *PORTFOLIO*",
                                  "type": "mrkdwn"
                                }
                              ]
                            },
                            {
                              "type": "divider"
                            },
                            {
                              "type": "section",
                              "text": {
                                "text": "Bill of Materials Processing Failed",
                                "type": "plain_text"
                              }
                            },
                            {
                              "type": "section",
                              "text": {
                                "text": "An error occurred while processing a BOM",
                                "type": "plain_text"
                              }
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
                          "blocks": [
                            {
                              "type": "header",
                              "text": {
                                "type": "plain_text",
                                "text": "DATASOURCE_MIRRORING"
                              }
                            },
                            {
                              "type": "context",
                              "elements": [
                                {
                                  "text": "*ERROR*  |  *SYSTEM*",
                                  "type": "mrkdwn"
                                }
                              ]
                            },
                            {
                              "type": "divider"
                            },
                            {
                              "type": "section",
                              "text": {
                                "text": "GitHub Advisory Mirroring",
                                "type": "plain_text"
                              }
                            },
                            {
                              "type": "section",
                              "text": {
                                "text": "An error occurred mirroring the contents of GitHub Advisories. Check log for details.",
                                "type": "plain_text"
                              }
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
                          "blocks": [
                            {
                              "type": "header",
                              "text": {
                                "type": "plain_text",
                                "text": "New Vulnerability"
                              }
                            },
                            {
                              "type": "context",
                              "elements": [
                                {
                                  "text": "*INFORMATIONAL*  |  *PORTFOLIO*",
                                  "type": "mrkdwn"
                                }
                              ]
                            },
                            {
                              "type": "divider"
                            },
                            {
                              "type": "section",
                              "text": {
                                "text": "New Vulnerability Identified",
                                "type": "mrkdwn"
                              },
                              "fields": [
                                {
                                  "type": "mrkdwn",
                                  "text": "*VulnID*"
                                },
                                {
                                  "type": "plain_text",
                                  "text": "INT-001"
                                },
                                {
                                  "type": "mrkdwn",
                                  "text": "*Severity*"
                                },
                                {
                                  "type": "plain_text",
                                  "text": "MEDIUM"
                                },
                                {
                                  "type": "mrkdwn",
                                  "text": "*Source*"
                                },
                                {
                                  "type": "plain_text",
                                  "text": "INTERNAL"
                                },
                                {
                                  "type": "mrkdwn",
                                  "text": "*Component*"
                                },
                                {
                                  "type": "plain_text",
                                  "text": "componentName : componentVersion"
                                }
                              ]
                            },
                            {
                              "type": "actions",
                              "elements": [
                                {
                                  "type": "button",
                                  "text": {
                                    "type": "plain_text",
                                    "text": "View Vulnerability"
                                  },
                                  "action_id": "actionId-1",
                                  "url": "https://example.com/vulnerabilities/INTERNAL/INT-001"
                                },
                                {
                                  "type": "button",
                                  "text": {
                                    "type": "plain_text",
                                    "text": "View Component"
                                  },
                                  "action_id": "actionId-2",
                                  "url": "https://example.com/components/94f87321-a5d1-4c2f-b2fe-95165debebc6"
                                }
                              ]
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
                          "blocks": [
                            {
                              "type": "header",
                              "text": {
                                "type": "plain_text",
                                "text": "New Vulnerable Dependency"
                              }
                            },
                            {
                              "type": "context",
                              "elements": [
                                {
                                  "text": "*INFORMATIONAL*  |  *PORTFOLIO*",
                                  "type": "mrkdwn"
                                }
                              ]
                            },
                            {
                              "type": "divider"
                            },
                            {
                              "type": "section",
                              "text": {
                                "text": "Vulnerable Dependency Introduced",
                                "type": "mrkdwn"
                              },
                              "fields": [
                                {
                                  "type": "mrkdwn",
                                  "text": "*Component*"
                                },
                                {
                                  "type": "plain_text",
                                  "text": "componentName : componentVersion"
                                },
                                {
                                  "type": "mrkdwn",
                                  "text": "*Project*"
                                },
                                {
                                  "type": "plain_text",
                                  "text": "pkg:maven/org.acme/projectName@projectVersion"
                                }
                              ]
                            },
                            {
                              "type": "actions",
                              "elements": [
                                {
                                  "type": "button",
                                  "text": {
                                    "type": "plain_text",
                                    "text": "View Project"
                                  },
                                  "action_id": "actionId-1",
                                  "url": "https://example.com/projects/"
                                },
                                {
                                  "type": "button",
                                  "text": {
                                    "type": "plain_text",
                                    "text": "View Component"
                                  },
                                  "action_id": "actionId-2",
                                  "url": "https://example.com/components/94f87321-a5d1-4c2f-b2fe-95165debebc6"
                                }
                              ]
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
                          "blocks": [
                            {
                        	  "type": "header",
                        	  "text": {
                        	    "type": "plain_text",
                        		"text": "Project Audit Change"
                        	  }
                        	},
                        	{
                        	  "type": "context",
                        	  "elements": [
                        	    {
                        		  "text": "*INFORMATIONAL*  |  *PORTFOLIO*",
                        		  "type": "mrkdwn"
                        		}
                        	  ]
                        	},
                        	{
                        	  "type": "divider"
                        	},
                        	{
                        	  "type": "section",
                        	  "text": {
                        	    "text": "Analysis Decision: Finding Suppressed",
                        		"type": "plain_text"
                        	  },
                        	  "fields": [
                        	    {
                        		  "type": "mrkdwn",
                        		  "text": "*Analysis State*"
                        		},
                        		{
                        		  "type": "plain_text",
                        		  "emoji": true,
                        		  "text": "FALSE_POSITIVE"
                        		},
                        		{
                        		  "type": "mrkdwn",
                        		  "text": "*Suppressed*"
                        		},
                        		{
                        		  "type": "plain_text",
                        		  "text": "true"
                        		},
                        		{
                        		  "type": "mrkdwn",
                        		  "text": "*VulnID*"
                        		},
                        		{
                        		  "type": "plain_text",
                        		  "text": "INT-001"
                        		},
                        		{
                        		  "type": "mrkdwn",
                        		  "text": "*Severity*"
                        		},
                        		{
                        		  "type": "plain_text",
                        		  "text": "MEDIUM"
                        		},
                        		{
                        		  "type": "mrkdwn",
                        		  "text": "*Source*"
                        		},
                        		{
                        		  "type": "plain_text",
                        		  "text": "INTERNAL"
                        		}
                        	  ]
                        	},
                            {
                        	  "type": "section",
                        	  "fields": [
                        		{
                        		  "type": "mrkdwn",
                        		  "text": "*Component*"
                        		},
                        		{
                        		  "type": "plain_text",
                        		  "text": "componentName : componentVersion"
                        		},
                        		{
                        		  "type": "mrkdwn",
                        		  "text": "*Project*"
                        		},
                        		{
                        		  "type": "plain_text",
                        		  "text": "pkg:maven/org.acme/projectName@projectVersion"
                        		}
                        	  ]
                        	},
                        	{
                        	  "type": "actions",
                        	  "elements": [
                        	    {
                        		  "type": "button",
                        		  "text": {
                        		    "type": "plain_text",
                        			"text": "View Project"
                        		  },
                        		  "action_id": "actionId-1",
                        		  "url": "https://example.com/projects/c9c9539a-e381-4b36-ac52-6a7ab83b2c95"
                        		},
                        		{
                        		  "type": "button",
                        		  "text": {
                        		    "type": "plain_text",
                        			"text": "View Component"
                        		  },
                        		  "action_id": "actionId-2",
                        		  "url": "https://example.com/components/94f87321-a5d1-4c2f-b2fe-95165debebc6"
                        		},
                        	    {
                        		  "type": "button",
                        		  "text": {
                        		    "type": "plain_text",
                        			"text": "View Vulnerability"
                        		  },
                        		  "action_id": "actionId-3",
                        		  "url": "https://example.com/vulnerabilities/INTERNAL/INT-001"
                        		}
                        	  ]
                        	}
                          ]
                        }
                        """)));
    }

    @Test
    public void testInformWithNewVulnerabilityNotificationWithoutBaseUrl() {
        final ConfigProperty baseUrlProperty = qm.getConfigProperty(
                GENERAL_BASE_URL.getGroupName(),
                GENERAL_BASE_URL.getPropertyName()
        );
        baseUrlProperty.setPropertyValue(null);
        qm.persist(baseUrlProperty);

        super.testInformWithNewVulnerabilityNotification();

        verify(postRequestedFor(anyUrl())
                .withHeader("Content-Type", equalTo("application/json"))
                .withRequestBody(equalToJson("""
                        {
                          "blocks": [
                            {
                              "type": "header",
                              "text": {
                                "type": "plain_text",
                                "text": "New Vulnerability"
                              }
                            },
                            {
                              "type": "context",
                              "elements": [
                                {
                                  "text": "*INFORMATIONAL*  |  *PORTFOLIO*",
                                  "type": "mrkdwn"
                                }
                              ]
                            },
                            {
                              "type": "divider"
                            },
                            {
                              "type": "section",
                              "text": {
                                "text": "New Vulnerability Identified",
                                "type": "mrkdwn"
                              },
                              "fields": [
                                {
                                  "type": "mrkdwn",
                                  "text": "*VulnID*"
                                },
                                {
                                  "type": "plain_text",
                                  "text": "INT-001"
                                },
                                {
                                  "type": "mrkdwn",
                                  "text": "*Severity*"
                                },
                                {
                                  "type": "plain_text",
                                  "text": "MEDIUM"
                                },
                                {
                                  "type": "mrkdwn",
                                  "text": "*Source*"
                                },
                                {
                                  "type": "plain_text",
                                  "text": "INTERNAL"
                                },
                                {
                                  "type": "mrkdwn",
                                  "text": "*Component*"
                                },
                                {
                                  "type": "plain_text",
                                  "text": "componentName : componentVersion"
                                }
                              ]
                            }
                          ]
                        }
                        """)));
    }

    @Test
    public void testInformWithNewVulnerableDependencyNotificationWithoutBaseUrl() {
        final ConfigProperty baseUrlProperty = qm.getConfigProperty(
                GENERAL_BASE_URL.getGroupName(),
                GENERAL_BASE_URL.getPropertyName()
        );
        baseUrlProperty.setPropertyValue(null);
        qm.persist(baseUrlProperty);

        super.testInformWithNewVulnerableDependencyNotification();

        verify(postRequestedFor(anyUrl())
                .withHeader("Content-Type", equalTo("application/json"))
                .withRequestBody(equalToJson("""
                        {
                          "blocks": [
                            {
                              "type": "header",
                              "text": {
                                "type": "plain_text",
                                "text": "New Vulnerable Dependency"
                              }
                            },
                            {
                              "type": "context",
                              "elements": [
                                {
                                  "text": "*INFORMATIONAL*  |  *PORTFOLIO*",
                                  "type": "mrkdwn"
                                }
                              ]
                            },
                            {
                              "type": "divider"
                            },
                            {
                              "type": "section",
                              "text": {
                                "text": "Vulnerable Dependency Introduced",
                                "type": "mrkdwn"
                              },
                              "fields": [
                                {
                                  "type": "mrkdwn",
                                  "text": "*Component*"
                                },
                                {
                                  "type": "plain_text",
                                  "text": "componentName : componentVersion"
                                },
                                {
                                  "type": "mrkdwn",
                                  "text": "*Project*"
                                },
                                {
                                  "type": "plain_text",
                                  "text": "pkg:maven/org.acme/projectName@projectVersion"
                                }
                              ]
                            }
                          ]
                        }
                        """)));
    }

    @Test
    public void testInformWithProjectAuditChangeNotificationWithoutBaseUrl() {
        final ConfigProperty baseUrlProperty = qm.getConfigProperty(
                GENERAL_BASE_URL.getGroupName(),
                GENERAL_BASE_URL.getPropertyName()
        );
        baseUrlProperty.setPropertyValue(null);
        qm.persist(baseUrlProperty);

        super.testInformWithProjectAuditChangeNotification();

        verify(postRequestedFor(anyUrl())
                .withHeader("Content-Type", equalTo("application/json"))
                .withRequestBody(equalToJson("""
                        {
                          "blocks": [
                            {
                        	  "type": "header",
                        	  "text": {
                        	    "type": "plain_text",
                        		"text": "Project Audit Change"
                        	  }
                        	},
                        	{
                        	  "type": "context",
                        	  "elements": [
                        	    {
                        		  "text": "*INFORMATIONAL*  |  *PORTFOLIO*",
                        		  "type": "mrkdwn"
                        		}
                        	  ]
                        	},
                        	{
                        	  "type": "divider"
                        	},
                        	{
                        	  "type": "section",
                        	  "text": {
                        	    "text": "Analysis Decision: Finding Suppressed",
                        		"type": "plain_text"
                        	  },
                        	  "fields": [
                        	    {
                        		  "type": "mrkdwn",
                        		  "text": "*Analysis State*"
                        		},
                        		{
                        		  "type": "plain_text",
                        		  "emoji": true,
                        		  "text": "FALSE_POSITIVE"
                        		},
                        		{
                        		  "type": "mrkdwn",
                        		  "text": "*Suppressed*"
                        		},
                        		{
                        		  "type": "plain_text",
                        		  "text": "true"
                        		},
                        		{
                        		  "type": "mrkdwn",
                        		  "text": "*VulnID*"
                        		},
                        		{
                        		  "type": "plain_text",
                        		  "text": "INT-001"
                        		},
                        		{
                        		  "type": "mrkdwn",
                        		  "text": "*Severity*"
                        		},
                        		{
                        		  "type": "plain_text",
                        		  "text": "MEDIUM"
                        		},
                        		{
                        		  "type": "mrkdwn",
                        		  "text": "*Source*"
                        		},
                        		{
                        		  "type": "plain_text",
                        		  "text": "INTERNAL"
                        		}
                        	  ]
                        	},
                            {
                        	  "type": "section",
                        	  "fields": [
                        		{
                        		  "type": "mrkdwn",
                        		  "text": "*Component*"
                        		},
                        		{
                        		  "type": "plain_text",
                        		  "text": "componentName : componentVersion"
                        		},
                        		{
                        		  "type": "mrkdwn",
                        		  "text": "*Project*"
                        		},
                        		{
                        		  "type": "plain_text",
                        		  "text": "pkg:maven/org.acme/projectName@projectVersion"
                        		}
                        	  ]
                        	}
                          ]
                        }
                        """)));
    }

}
