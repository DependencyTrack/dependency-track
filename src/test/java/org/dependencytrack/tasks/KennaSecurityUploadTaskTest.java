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
package org.dependencytrack.tasks;

import alpine.model.IConfigProperty;
import alpine.security.crypto.DataEncryption;
import com.github.tomakehurst.wiremock.junit.WireMockRule;
import org.dependencytrack.PersistenceCapableTest;
import org.dependencytrack.event.KennaSecurityUploadEventAbstract;
import org.dependencytrack.model.Component;
import org.dependencytrack.model.Project;
import org.dependencytrack.model.Severity;
import org.dependencytrack.model.Vulnerability;
import org.dependencytrack.tasks.scanners.AnalyzerIdentity;
import org.junit.Rule;
import org.junit.Test;

import static com.github.tomakehurst.wiremock.client.WireMock.aMultipart;
import static com.github.tomakehurst.wiremock.client.WireMock.aResponse;
import static com.github.tomakehurst.wiremock.client.WireMock.equalTo;
import static com.github.tomakehurst.wiremock.client.WireMock.equalToJson;
import static com.github.tomakehurst.wiremock.client.WireMock.post;
import static com.github.tomakehurst.wiremock.client.WireMock.postRequestedFor;
import static com.github.tomakehurst.wiremock.client.WireMock.stubFor;
import static com.github.tomakehurst.wiremock.client.WireMock.urlPathEqualTo;
import static com.github.tomakehurst.wiremock.client.WireMock.verify;
import static com.github.tomakehurst.wiremock.core.WireMockConfiguration.options;
import static org.dependencytrack.model.ConfigPropertyConstants.KENNA_API_URL;
import static org.dependencytrack.model.ConfigPropertyConstants.KENNA_CONNECTOR_ID;
import static org.dependencytrack.model.ConfigPropertyConstants.KENNA_ENABLED;
import static org.dependencytrack.model.ConfigPropertyConstants.KENNA_TOKEN;

public class KennaSecurityUploadTaskTest extends PersistenceCapableTest {

    @Rule
    public WireMockRule wireMockRule = new WireMockRule(options().dynamicPort());

    @Test
    public void test() throws Exception {
        qm.createConfigProperty(
                KENNA_ENABLED.getGroupName(),
                KENNA_ENABLED.getPropertyName(),
                "true",
                KENNA_ENABLED.getPropertyType(),
                KENNA_ENABLED.getDescription());
        qm.createConfigProperty(
                KENNA_API_URL.getGroupName(),
                KENNA_API_URL.getPropertyName(),
                wireMockRule.baseUrl(),
                KENNA_API_URL.getPropertyType(),
                KENNA_API_URL.getDescription());
        qm.createConfigProperty(
                KENNA_TOKEN.getGroupName(),
                KENNA_TOKEN.getPropertyName(),
                DataEncryption.encryptAsString("token"),
                KENNA_TOKEN.getPropertyType(),
                KENNA_TOKEN.getDescription());
        qm.createConfigProperty(
                KENNA_CONNECTOR_ID.getGroupName(),
                KENNA_CONNECTOR_ID.getPropertyName(),
                "foo",
                KENNA_CONNECTOR_ID.getPropertyType(),
                KENNA_CONNECTOR_ID.getDescription());

        final var project = new Project();
        project.setName("acme-app");
        project.setVersion("1.0.0");
        qm.persist(project);

        final var component = new Component();
        component.setProject(project);
        component.setName("acme-lib");
        component.setVersion("1.2.3");
        qm.persist(component);

        final var vuln = new Vulnerability();
        vuln.setVulnId("INT-123");
        vuln.setSource(Vulnerability.Source.INTERNAL);
        vuln.setSeverity(Severity.HIGH);
        qm.persist(vuln);

        qm.addVulnerability(vuln, component, AnalyzerIdentity.INTERNAL_ANALYZER);

        qm.createProjectProperty(project, "integrations", "kenna.asset.external_id",
                "666", IConfigProperty.PropertyType.STRING, null);

        stubFor(post(urlPathEqualTo("/connectors/foo/data_file"))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withBody(/* language=JSON */ """
                                {
                                  "success": "true"
                                }
                                """)));

        final var task = new KennaSecurityUploadTask();
        task.inform(new KennaSecurityUploadEventAbstract());

        verify(postRequestedFor(urlPathEqualTo("/connectors/foo/data_file"))
                .withHeader("X-Risk-Token", equalTo("token"))
                .withAnyRequestBodyPart(aMultipart()
                        .withName("file")
                        .withBody(equalToJson("""
                                {
                                  "skip_autoclose": false,
                                  "assets": [
                                    {
                                      "application": "acme-app 1.0.0",
                                      "vulns": [
                                        {
                                          "scanner_type": "Dependency-Track",
                                          "override_score": 70,
                                          "scanner_score": 7,
                                          "last_seen_at": "${json-unit.any-string}",
                                          "scanner_identifier": "INTERNAL-INT-123",
                                          "status": "open"
                                        }
                                      ],
                                      "external_id": "666"
                                    }
                                  ],
                                  "vuln_defs": [
                                    {
                                      "scanner_type": "Dependency-Track",
                                      "name": "INT-123 (source: INTERNAL)",
                                      "scanner_identifier": "INTERNAL-INT-123"
                                    }
                                  ]
                                }
                                """))));
    }

}