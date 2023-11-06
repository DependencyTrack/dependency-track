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
 * Copyright (c) Steve Springett. All Rights Reserved.
 */
package org.dependencytrack.resources.v1;

import alpine.server.filters.ApiFilter;
import alpine.server.filters.AuthenticationFilter;
import org.dependencytrack.ResourceTest;
import org.dependencytrack.model.AnalysisResponse;
import org.dependencytrack.model.AnalysisState;
import org.dependencytrack.model.Classifier;
import org.dependencytrack.model.Component;
import org.dependencytrack.model.Project;
import org.dependencytrack.model.Severity;
import org.dependencytrack.model.Vulnerability;
import org.dependencytrack.tasks.scanners.AnalyzerIdentity;
import org.glassfish.jersey.media.multipart.MultiPartFeature;
import org.glassfish.jersey.server.ResourceConfig;
import org.glassfish.jersey.servlet.ServletContainer;
import org.glassfish.jersey.test.DeploymentContext;
import org.glassfish.jersey.test.ServletDeploymentContext;
import org.junit.Test;

import javax.ws.rs.core.Response;

import static net.javacrumbs.jsonunit.assertj.JsonAssertions.assertThatJson;
import static org.assertj.core.api.Assertions.assertThat;
import static org.hamcrest.CoreMatchers.equalTo;

public class VexResourceTest extends ResourceTest {

    @Override
    protected DeploymentContext configureDeployment() {
        return ServletDeploymentContext.forServlet(new ServletContainer(
                        new ResourceConfig(VexResource.class)
                                .register(ApiFilter.class)
                                .register(AuthenticationFilter.class)
                                .register(MultiPartFeature.class)))
                .build();
    }

    @Test
    public void exportProjectAsCycloneDxTest() {
        var vulnA = new Vulnerability();
        vulnA.setVulnId("INT-001");
        vulnA.setSource(Vulnerability.Source.INTERNAL);
        vulnA.setSeverity(Severity.HIGH);
        vulnA = qm.createVulnerability(vulnA, false);

        var vulnB = new Vulnerability();
        vulnB.setVulnId("INT-002");
        vulnB.setSource(Vulnerability.Source.INTERNAL);
        vulnB.setSeverity(Severity.LOW);
        vulnB = qm.createVulnerability(vulnB, false);

        final var project = new Project();
        project.setName("acme-app");
        project.setVersion("1.0.0");
        project.setClassifier(Classifier.APPLICATION);
        qm.persist(project);

        var componentWithoutVuln = new Component();
        componentWithoutVuln.setProject(project);
        componentWithoutVuln.setName("acme-lib-a");
        componentWithoutVuln.setVersion("1.0.0");
        componentWithoutVuln.setDirectDependencies("[]");
        componentWithoutVuln = qm.createComponent(componentWithoutVuln, false);

        var componentWithVuln = new Component();
        componentWithVuln.setProject(project);
        componentWithVuln.setName("acme-lib-b");
        componentWithVuln.setVersion("1.0.0");
        componentWithVuln.setDirectDependencies("[]");
        componentWithVuln = qm.createComponent(componentWithVuln, false);
        qm.addVulnerability(vulnA, componentWithVuln, AnalyzerIdentity.INTERNAL_ANALYZER);

        var componentWithVulnAndAnalysis = new Component();
        componentWithVulnAndAnalysis.setProject(project);
        componentWithVulnAndAnalysis.setName("acme-lib-c");
        componentWithVulnAndAnalysis.setVersion("1.0.0");
        componentWithVulnAndAnalysis.setDirectDependencies("[]");
        componentWithVulnAndAnalysis = qm.createComponent(componentWithVulnAndAnalysis, false);
        qm.addVulnerability(vulnB, componentWithVulnAndAnalysis, AnalyzerIdentity.INTERNAL_ANALYZER);
        qm.makeAnalysis(componentWithVulnAndAnalysis, vulnB, AnalysisState.RESOLVED, null, AnalysisResponse.UPDATE, null, true);

        // Make componentWithoutVuln (acme-lib-a) depend on componentWithVuln (acme-lib-b)
        componentWithoutVuln.setDirectDependencies("""
                [
                    {"uuid": "%s"}
                ]
                """.formatted(componentWithVuln.getUuid()));

        // Make project depend on componentWithoutVuln (acme-lib-a)
        // and componentWithVulnAndAnalysis (acme-lib-c)
        project.setDirectDependencies("""
                [
                    {"uuid": "%s"},
                    {"uuid": "%s"}
                ]
                """
                .formatted(
                        componentWithoutVuln.getUuid(),
                        componentWithVulnAndAnalysis.getUuid()
                ));
        qm.persist(project);

        final Response response = target("%s/cyclonedx/project/%s".formatted(V1_VEX, project.getUuid()))
                .request()
                .header(X_API_KEY, apiKey)
                .get(Response.class);
        assertThat(response.getStatus()).isEqualTo(200);
        assertThatJson(getPlainTextBody(response))
                .withMatcher("vulnAUuid", equalTo(vulnA.getUuid().toString()))
                .withMatcher("vulnBUuid", equalTo(vulnB.getUuid().toString()))
                .withMatcher("projectUuid", equalTo(project.getUuid().toString()))
                .isEqualTo("""
                        {
                          "bomFormat": "CycloneDX",
                          "specVersion": "1.5",
                          "serialNumber": "${json-unit.any-string}",
                          "version": 1,
                          "metadata": {
                            "timestamp": "${json-unit.any-string}",
                            "component": {
                              "type": "application",
                              "bom-ref": "${json-unit.matches:projectUuid}",
                              "name": "acme-app",
                              "version": "1.0.0"
                            },
                            "tools": [
                              {
                                "vendor": "OWASP",
                                "name": "Dependency-Track",
                                "version": "${json-unit.any-string}"
                              }
                            ]
                          },
                          "vulnerabilities": [
                            {
                              "bom-ref": "${json-unit.matches:vulnAUuid}",
                              "id": "INT-001",
                              "source": {
                                "name": "INTERNAL"
                              },
                              "ratings": [
                                {
                                  "source": {
                                    "name": "INTERNAL"
                                  },
                                  "severity": "high",
                                  "method": "other"
                                }
                              ],
                              "affects": [
                                {
                                  "ref": "${json-unit.matches:projectUuid}"
                                }
                              ]
                            },
                            {
                              "bom-ref": "${json-unit.matches:vulnBUuid}",
                              "id": "INT-002",
                              "source": {
                                "name": "INTERNAL"
                              },
                              "ratings": [
                                {
                                  "source": {
                                    "name": "INTERNAL"
                                  },
                                  "severity": "low",
                                  "method": "other"
                                }
                              ],
                              "analysis":{
                                "state": "resolved",
                                "response": [
                                  "update"
                                ]
                              },
                              "affects": [
                                {
                                  "ref": "${json-unit.matches:projectUuid}"
                                }
                              ]
                            }
                          ]
                        }
                        """);
    }

}