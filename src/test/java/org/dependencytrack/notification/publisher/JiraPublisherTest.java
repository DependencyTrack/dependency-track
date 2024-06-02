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
import alpine.security.crypto.DataEncryption;
import org.junit.Before;
import org.junit.Test;

import jakarta.json.JsonObjectBuilder;

import static com.github.tomakehurst.wiremock.client.WireMock.equalTo;
import static com.github.tomakehurst.wiremock.client.WireMock.equalToJson;
import static com.github.tomakehurst.wiremock.client.WireMock.postRequestedFor;
import static com.github.tomakehurst.wiremock.client.WireMock.urlPathEqualTo;
import static com.github.tomakehurst.wiremock.client.WireMock.verify;
import static org.dependencytrack.model.ConfigPropertyConstants.JIRA_PASSWORD;
import static org.dependencytrack.model.ConfigPropertyConstants.JIRA_URL;
import static org.dependencytrack.model.ConfigPropertyConstants.JIRA_USERNAME;

public class JiraPublisherTest extends AbstractWebhookPublisherTest<JiraPublisher> {

    public JiraPublisherTest() {
        super(DefaultNotificationPublishers.JIRA, new JiraPublisher());
    }

    @Before
    public void setUp() throws Exception {
        super.setUp();

        qm.createConfigProperty(
                JIRA_URL.getGroupName(),
                JIRA_URL.getPropertyName(),
                wireMock.baseUrl(),
                JIRA_URL.getPropertyType(),
                JIRA_URL.getDescription()
        );
        qm.createConfigProperty(
                JIRA_USERNAME.getGroupName(),
                JIRA_USERNAME.getPropertyName(),
                "jiraUser",
                JIRA_USERNAME.getPropertyType(),
                JIRA_USERNAME.getDescription()
        );
        qm.createConfigProperty(
                JIRA_PASSWORD.getGroupName(),
                JIRA_PASSWORD.getPropertyName(),
                DataEncryption.encryptAsString("jiraPassword"),
                JIRA_PASSWORD.getPropertyType(),
                JIRA_PASSWORD.getDescription()
        );
    }

    @Override
    public void testInformWithBomConsumedNotification() {
        super.testInformWithBomConsumedNotification();

        verify(postRequestedFor(urlPathEqualTo("/rest/api/2/issue"))
                .withHeader("Authorization", equalTo("Basic amlyYVVzZXI6amlyYVBhc3N3b3Jk"))
                .withHeader("Content-Type", equalTo("application/json"))
                .withRequestBody(equalToJson("""
                        {
                          "fields" : {
                            "project" : {
                              "key" : "PROJECT"
                            },
                            "issuetype" : {
                              "name" : "Task"
                            },
                            "summary" : "[Dependency-Track] [BOM_CONSUMED] Bill of Materials Consumed",
                            "description" : "A CycloneDX BOM was consumed and will be processed\\n\\\\\\\\\\n\\\\\\\\\\n*Level*\\nINFORMATIONAL\\n\\n"
                          }
                        }
                        """)));
    }

    @Override
    public void testInformWithBomProcessingFailedNotification() {
        super.testInformWithBomProcessingFailedNotification();

        verify(postRequestedFor(urlPathEqualTo("/rest/api/2/issue"))
                .withHeader("Authorization", equalTo("Basic amlyYVVzZXI6amlyYVBhc3N3b3Jk"))
                .withHeader("Content-Type", equalTo("application/json"))
                .withRequestBody(equalToJson("""
                        {
                          "fields" : {
                            "project" : {
                              "key" : "PROJECT"
                            },
                            "issuetype" : {
                              "name" : "Task"
                            },
                            "summary" : "[Dependency-Track] [BOM_PROCESSING_FAILED] Bill of Materials Processing Failed",
                            "description" : "An error occurred while processing a BOM\\n\\\\\\\\\\n\\\\\\\\\\n*Level*\\nERROR\\n\\n"
                          }
                        }
                        """)));
    }

    @Override
    public void testInformWithBomValidationFailedNotification() {
        super.testInformWithBomValidationFailedNotification();

        verify(postRequestedFor(urlPathEqualTo("/rest/api/2/issue"))
                .withHeader("Authorization", equalTo("Basic amlyYVVzZXI6amlyYVBhc3N3b3Jk"))
                .withHeader("Content-Type", equalTo("application/json"))
                .withRequestBody(equalToJson("""
                        {
                          "fields" : {
                            "project" : {
                              "key" : "PROJECT"
                            },
                            "issuetype" : {
                              "name" : "Task"
                            },
                            "summary" : "[Dependency-Track] [BOM_VALIDATION_FAILED] Bill of Materials Validation Failed",
                            "description" : "An error occurred during BOM Validation\\n\\\\\\\\\\n\\\\\\\\\\n*Level*\\nERROR\\n\\n"
                          }
                        }
                        """)));
    }

    @Override
    public void testInformWithBomProcessingFailedNotificationAndNoSpecVersionInSubject() {
        super.testInformWithBomProcessingFailedNotificationAndNoSpecVersionInSubject();

        verify(postRequestedFor(urlPathEqualTo("/rest/api/2/issue"))
                .withHeader("Authorization", equalTo("Basic amlyYVVzZXI6amlyYVBhc3N3b3Jk"))
                .withHeader("Content-Type", equalTo("application/json"))
                .withRequestBody(equalToJson("""
                        {
                          "fields" : {
                            "project" : {
                              "key" : "PROJECT"
                            },
                            "issuetype" : {
                              "name" : "Task"
                            },
                            "summary" : "[Dependency-Track] [BOM_PROCESSING_FAILED] Bill of Materials Processing Failed",
                            "description" : "An error occurred while processing a BOM\\n\\\\\\\\\\n\\\\\\\\\\n*Level*\\nERROR\\n\\n"
                          }
                        }
                        """)));
    }

    @Override
    public void testInformWithDataSourceMirroringNotification() {
        super.testInformWithDataSourceMirroringNotification();

        verify(postRequestedFor(urlPathEqualTo("/rest/api/2/issue"))
                .withHeader("Authorization", equalTo("Basic amlyYVVzZXI6amlyYVBhc3N3b3Jk"))
                .withHeader("Content-Type", equalTo("application/json"))
                .withRequestBody(equalToJson("""
                        {
                          "fields" : {
                            "project" : {
                              "key" : "PROJECT"
                            },
                            "issuetype" : {
                              "name" : "Task"
                            },
                            "summary" : "[Dependency-Track] [DATASOURCE_MIRRORING] GitHub Advisory Mirroring",
                            "description" : "An error occurred mirroring the contents of GitHub Advisories. Check log for details.\\n\\\\\\\\\\n\\\\\\\\\\n*Level*\\nERROR\\n\\n"
                          }
                        }
                        """)));
    }

    @Override
    public void testInformWithNewVulnerabilityNotification() {
        super.testInformWithNewVulnerabilityNotification();

        verify(postRequestedFor(urlPathEqualTo("/rest/api/2/issue"))
                .withHeader("Authorization", equalTo("Basic amlyYVVzZXI6amlyYVBhc3N3b3Jk"))
                .withHeader("Content-Type", equalTo("application/json"))
                .withRequestBody(equalToJson("""
                        {
                          "fields" : {
                            "project" : {
                              "key" : "PROJECT"
                            },
                            "issuetype" : {
                              "name" : "Task"
                            },
                            "summary" : "[Dependency-Track] [NEW_VULNERABILITY] [MEDIUM] New medium vulnerability identified: INT-001",
                            "description" : "A new vulnerability has been identified on your project(s).\\n\\\\\\\\\\n\\\\\\\\\\n*Vulnerability description*\\n{code:none|bgColor=white|borderStyle=none}vulnerabilityDescription{code}\\n\\n*VulnID*\\nINT-001\\n\\n*Severity*\\nMedium\\n\\n*Component*\\n[componentName : componentVersion|https://example.com/components/94f87321-a5d1-4c2f-b2fe-95165debebc6]\\n\\n*Affected project(s)*\\n- [projectName (projectVersion)|https://example.com/projects/c9c9539a-e381-4b36-ac52-6a7ab83b2c95]\\n"
                          }
                        }
                        """)));
    }

    @Override
    public void testInformWithNewVulnerableDependencyNotification() {
        super.testInformWithNewVulnerableDependencyNotification();

        verify(postRequestedFor(urlPathEqualTo("/rest/api/2/issue"))
                .withHeader("Authorization", equalTo("Basic amlyYVVzZXI6amlyYVBhc3N3b3Jk"))
                .withHeader("Content-Type", equalTo("application/json"))
                .withRequestBody(equalToJson("""
                        {
                          "fields": {
                            "project": {
                              "key": "PROJECT"
                            },
                            "issuetype": {
                              "name": "Task"
                            },
                            "summary": "[Dependency-Track] [NEW_VULNERABLE_DEPENDENCY] Vulnerable dependency introduced on project projectName",
                            "description": "A component which contains one or more vulnerabilities has been added to your project.\\n\\\\\\\\\\n\\\\\\\\\\n*Project*\\n[pkg:maven/org.acme/projectName@projectVersion|https://example.com/projects/c9c9539a-e381-4b36-ac52-6a7ab83b2c95]\\n\\n*Component*\\n[componentName : componentVersion|https://example.com/components/94f87321-a5d1-4c2f-b2fe-95165debebc6]\\n\\n*Vulnerabilities*\\n- INT-001 (Medium)\\n"
                          }
                        }
                        """)));
    }

    @Override
    public void testInformWithProjectAuditChangeNotification() {
        super.testInformWithProjectAuditChangeNotification();

        verify(postRequestedFor(urlPathEqualTo("/rest/api/2/issue"))
                .withHeader("Authorization", equalTo("Basic amlyYVVzZXI6amlyYVBhc3N3b3Jk"))
                .withHeader("Content-Type", equalTo("application/json"))
                .withRequestBody(equalToJson("""
                        {
                          "fields" : {
                            "project" : {
                              "key" : "PROJECT"
                            },
                            "issuetype" : {
                              "name" : "Task"
                            },
                            "summary" : "[Dependency-Track] [PROJECT_AUDIT_CHANGE] Analysis Decision: Finding Suppressed",
                            "description" : "\\n\\\\\\\\\\n\\\\\\\\\\n*Level*\\nINFORMATIONAL\\n\\n"
                          }
                        }
                        """)));
    }

    @Test
    public void testPublishWithBearerToken() throws Exception {
        final ConfigProperty usernameProperty = qm.getConfigProperty(JIRA_USERNAME.getGroupName(), JIRA_USERNAME.getPropertyName());
        usernameProperty.setPropertyValue(null);
        qm.persist(usernameProperty);

        final ConfigProperty passwordProperty = qm.getConfigProperty(JIRA_PASSWORD.getGroupName(), JIRA_PASSWORD.getPropertyName());
        passwordProperty.setPropertyValue(DataEncryption.encryptAsString("jiraToken"));
        qm.persist(passwordProperty);

        super.testInformWithBomConsumedNotification();

        verify(postRequestedFor(urlPathEqualTo("/rest/api/2/issue"))
                .withHeader("Authorization", equalTo("Bearer jiraToken"))
                .withHeader("Content-Type", equalTo("application/json"))
                .withRequestBody(equalToJson("""
                        {
                          "fields" : {
                            "project" : {
                              "key" : "PROJECT"
                            },
                            "issuetype" : {
                              "name" : "Task"
                            },
                            "summary" : "[Dependency-Track] [BOM_CONSUMED] Bill of Materials Consumed",
                            "description" : "A CycloneDX BOM was consumed and will be processed\\n\\\\\\\\\\n\\\\\\\\\\n*Level*\\nINFORMATIONAL\\n\\n"
                          }
                        }
                        """)));
    }

    @Override
    public JsonObjectBuilder extraConfig() {
        return super.extraConfig()
                .add(Publisher.CONFIG_DESTINATION, "PROJECT")
                .add("jiraTicketType", "Task");
    }

}

