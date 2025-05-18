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
package org.dependencytrack.resources.v1;

import alpine.common.util.UuidUtil;
import alpine.model.IConfigProperty;
import alpine.server.filters.ApiFilter;
import alpine.server.filters.AuthenticationFilter;
import com.fasterxml.jackson.core.StreamReadConstraints;
import jakarta.json.JsonObject;
import jakarta.ws.rs.client.ClientBuilder;
import jakarta.ws.rs.client.Entity;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import org.apache.http.HttpStatus;
import org.dependencytrack.JerseyTestExtension;
import org.dependencytrack.ResourceTest;
import org.dependencytrack.auth.Permissions;
import org.dependencytrack.model.AnalysisResponse;
import org.dependencytrack.model.AnalysisState;
import org.dependencytrack.model.BomValidationMode;
import org.dependencytrack.model.Classifier;
import org.dependencytrack.model.Component;
import org.dependencytrack.model.ComponentProperty;
import org.dependencytrack.model.OrganizationalContact;
import org.dependencytrack.model.OrganizationalEntity;
import org.dependencytrack.model.Project;
import org.dependencytrack.model.ProjectCollectionLogic;
import org.dependencytrack.model.ProjectMetadata;
import org.dependencytrack.model.ProjectProperty;
import org.dependencytrack.model.Severity;
import org.dependencytrack.model.Tag;
import org.dependencytrack.model.Vulnerability;
import org.dependencytrack.parser.cyclonedx.CycloneDxValidator;
import org.dependencytrack.resources.v1.exception.JsonMappingExceptionMapper;
import org.dependencytrack.resources.v1.vo.BomSubmitRequest;
import org.dependencytrack.tasks.scanners.AnalyzerIdentity;
import org.glassfish.jersey.client.ClientConfig;
import org.glassfish.jersey.client.HttpUrlConnectorProvider;
import org.glassfish.jersey.media.multipart.FormDataMultiPart;
import org.glassfish.jersey.media.multipart.MultiPartFeature;
import org.glassfish.jersey.server.ResourceConfig;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;
import org.junitpioneer.jupiter.DefaultLocale;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Collections;
import java.util.List;
import java.util.UUID;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import static net.javacrumbs.jsonunit.assertj.JsonAssertions.assertThatJson;
import static net.javacrumbs.jsonunit.assertj.JsonAssertions.json;
import static org.apache.commons.io.IOUtils.resourceToByteArray;
import static org.apache.commons.io.IOUtils.resourceToString;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatNoException;
import static org.dependencytrack.model.ConfigPropertyConstants.BOM_VALIDATION_MODE;
import static org.dependencytrack.model.ConfigPropertyConstants.BOM_VALIDATION_TAGS_EXCLUSIVE;
import static org.dependencytrack.model.ConfigPropertyConstants.BOM_VALIDATION_TAGS_INCLUSIVE;
import static org.hamcrest.CoreMatchers.equalTo;

@DefaultLocale("en-US")
class BomResourceTest extends ResourceTest {

    @RegisterExtension
    public static JerseyTestExtension jersey = new JerseyTestExtension(
            () -> new ResourceConfig(BomResource.class)
                    .register(ApiFilter.class)
                    .register(AuthenticationFilter.class)
                    .register(MultiPartFeature.class)
                    .register(JsonMappingExceptionMapper.class));

    @Test
    void exportProjectAsCycloneDxTest() {
        Project project = qm.createProject("Acme Example", null, "1.0", null, null, null, true, false);
        Component c = new Component();
        c.setProject(project);
        c.setName("sample-component");
        c.setVersion("1.0");
        Component component = qm.createComponent(c, false);
        Response response = jersey.target(V1_BOM + "/cyclonedx/project/" + project.getUuid()).request()
                .header(X_API_KEY, apiKey)
                .get(Response.class);
        Assertions.assertEquals(200, response.getStatus(), 0);
        Assertions.assertNull(response.getHeaderString(TOTAL_COUNT_HEADER));
        String body = getPlainTextBody(response);
        Assertions.assertTrue(body.startsWith("{"));
    }

    @Test
    void exportProjectAsCycloneDxInvalidTest() {
        Response response = jersey.target(V1_BOM + "/cyclonedx/project/" + UUID.randomUUID()).request()
                .header(X_API_KEY, apiKey)
                .get(Response.class);
        Assertions.assertEquals(404, response.getStatus(), 0);
        Assertions.assertNull(response.getHeaderString(TOTAL_COUNT_HEADER));
        String body = getPlainTextBody(response);
        Assertions.assertEquals("The project could not be found.", body);
    }

    @Test
    void exportProjectAsCycloneDxInventoryTest() {
        var vulnerability = new Vulnerability();
        vulnerability.setVulnId("INT-001");
        vulnerability.setSource(Vulnerability.Source.INTERNAL);
        vulnerability.setSeverity(Severity.HIGH);
        vulnerability = qm.createVulnerability(vulnerability, false);

        final var projectManufacturer = new OrganizationalEntity();
        projectManufacturer.setName("projectManufacturer");
        final var projectSupplier = new OrganizationalEntity();
        projectSupplier.setName("projectSupplier");

        var project = new Project();
        project.setName("acme-app");
        project.setClassifier(Classifier.APPLICATION);
        project.setManufacturer(projectManufacturer);
        project.setSupplier(projectSupplier);
        List<OrganizationalContact> authors = new ArrayList<>();
        authors.add(new OrganizationalContact() {{
            setName("SampleAuthor");
        }});
        project.setAuthors(authors);
        project = qm.createProject(project, null, false);

        final var projectProperty = new ProjectProperty();
        projectProperty.setProject(project);
        projectProperty.setGroupName("foo");
        projectProperty.setPropertyName("bar");
        projectProperty.setPropertyValue("baz");
        projectProperty.setPropertyType(IConfigProperty.PropertyType.STRING);
        qm.persist(projectProperty);

        final var bomSupplier = new OrganizationalEntity();
        bomSupplier.setName("bomSupplier");
        final var bomAuthor = new OrganizationalContact();
        bomAuthor.setName("bomAuthor");
        final var projectMetadata = new ProjectMetadata();
        projectMetadata.setProject(project);
        projectMetadata.setAuthors(List.of(bomAuthor));
        projectMetadata.setSupplier(bomSupplier);
        qm.persist(projectMetadata);

        final var componentSupplier = new OrganizationalEntity();
        componentSupplier.setName("componentSupplier");

        var componentWithoutVuln = new Component();
        componentWithoutVuln.setProject(project);
        componentWithoutVuln.setName("acme-lib-a");
        componentWithoutVuln.setVersion("1.0.0");
        componentWithoutVuln.setSupplier(componentSupplier);
        componentWithoutVuln.setDirectDependencies("[]");
        componentWithoutVuln = qm.createComponent(componentWithoutVuln, false);

        final var componentProperty = new ComponentProperty();
        componentProperty.setComponent(componentWithoutVuln);
        componentProperty.setGroupName("foo");
        componentProperty.setPropertyName("bar");
        componentProperty.setPropertyValue("baz");
        componentProperty.setPropertyType(IConfigProperty.PropertyType.STRING);
        qm.persist(componentProperty);

        var componentWithVuln = new Component();
        componentWithVuln.setProject(project);
        componentWithVuln.setName("acme-lib-b");
        componentWithVuln.setVersion("1.0.0");
        componentWithVuln.setDirectDependencies("[]");
        componentWithVuln = qm.createComponent(componentWithVuln, false);
        qm.addVulnerability(vulnerability, componentWithVuln, AnalyzerIdentity.INTERNAL_ANALYZER);

        var componentWithVulnAndAnalysis = new Component();
        componentWithVulnAndAnalysis.setProject(project);
        componentWithVulnAndAnalysis.setName("acme-lib-c");
        componentWithVulnAndAnalysis.setVersion("1.0.0");
        componentWithVulnAndAnalysis.setDirectDependencies("[]");
        componentWithVulnAndAnalysis = qm.createComponent(componentWithVulnAndAnalysis, false);
        qm.addVulnerability(vulnerability, componentWithVulnAndAnalysis, AnalyzerIdentity.INTERNAL_ANALYZER);
        qm.makeAnalysis(componentWithVulnAndAnalysis, vulnerability, AnalysisState.RESOLVED, null, AnalysisResponse.UPDATE, null, true);

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

        final Response response = jersey.target(V1_BOM + "/cyclonedx/project/" + project.getUuid())
                .queryParam("variant", "inventory")
                .request()
                .header(X_API_KEY, apiKey)
                .get(Response.class);
        assertThat(response.getStatus()).isEqualTo(HttpStatus.SC_OK);

        final String jsonResponse = getPlainTextBody(response);
        assertThatNoException().isThrownBy(() -> CycloneDxValidator.getInstance().validate(jsonResponse.getBytes()));
        assertThatJson(jsonResponse)
                .withMatcher("projectUuid", equalTo(project.getUuid().toString()))
                .withMatcher("componentWithoutVulnUuid", equalTo(componentWithoutVuln.getUuid().toString()))
                .withMatcher("componentWithVulnUuid", equalTo(componentWithVuln.getUuid().toString()))
                .withMatcher("componentWithVulnAndAnalysisUuid", equalTo(componentWithVulnAndAnalysis.getUuid().toString()))
                .isEqualTo(json("""
                {
                    "bomFormat": "CycloneDX",
                    "specVersion": "1.5",
                    "serialNumber": "${json-unit.ignore}",
                    "version": 1,
                    "metadata": {
                        "timestamp": "${json-unit.any-string}",
                        "authors": [
                          {
                            "name": "bomAuthor"
                          }
                        ],
                        "component": {
                            "type": "application",
                            "bom-ref": "${json-unit.matches:projectUuid}",
                            "author": "SampleAuthor",
                            "supplier": {
                              "name": "projectSupplier"
                            },
                            "name": "acme-app",
                            "version": ""
                        },
                        "manufacture": {
                          "name": "projectManufacturer"
                        },
                        "supplier": {
                          "name": "bomSupplier"
                        },
                        "tools": [
                            {
                                "vendor": "OWASP",
                                "name": "Dependency-Track",
                                "version": "${json-unit.any-string}"
                            }
                        ]
                    },
                    "components": [
                        {
                            "type": "library",
                            "bom-ref": "${json-unit.matches:componentWithoutVulnUuid}",
                            "supplier": {
                              "name": "componentSupplier"
                            },
                            "name": "acme-lib-a",
                            "version": "1.0.0",
                            "properties": [
                              {
                                "name": "foo:bar",
                                "value": "baz"
                              }
                            ]
                        },
                        {
                            "type": "library",
                            "bom-ref": "${json-unit.matches:componentWithVulnUuid}",
                            "name": "acme-lib-b",
                            "version": "1.0.0"
                        },
                        {
                            "type": "library",
                            "bom-ref": "${json-unit.matches:componentWithVulnAndAnalysisUuid}",
                            "name": "acme-lib-c",
                            "version": "1.0.0"
                        }
                    ],
                    "dependencies": [
                        {
                            "ref": "${json-unit.matches:projectUuid}",
                            "dependsOn": [
                                "${json-unit.matches:componentWithoutVulnUuid}",
                                "${json-unit.matches:componentWithVulnAndAnalysisUuid}"
                            ]
                        },
                        {
                            "ref": "${json-unit.matches:componentWithoutVulnUuid}",
                            "dependsOn": [
                                "${json-unit.matches:componentWithVulnUuid}"
                            ]
                        },
                        {
                            "ref": "${json-unit.matches:componentWithVulnUuid}",
                            "dependsOn": []
                        },
                        {
                            "ref": "${json-unit.matches:componentWithVulnAndAnalysisUuid}",
                            "dependsOn": []
                        }
                    ]
                }
                """));

        // Ensure the dependency graph did not get deleted during export.
        // https://github.com/DependencyTrack/dependency-track/issues/2494
        qm.getPersistenceManager().refreshAll(project, componentWithoutVuln, componentWithVuln, componentWithVulnAndAnalysis);
        assertThat(project.getDirectDependencies()).isNotNull();
        assertThat(componentWithoutVuln.getDirectDependencies()).isNotNull();
        assertThat(componentWithVuln.getDirectDependencies()).isNotNull();
        assertThat(componentWithVulnAndAnalysis.getDirectDependencies()).isNotNull();
    }

    @Test
    void exportProjectAsCycloneDxLicenseTest() {
        Project project = qm.createProject("Acme Example", null, "1.0", null, null, null, true, false);
        Component c = new Component();
        c.setProject(project);
        c.setName("sample-component");
        c.setVersion("1.0");
        org.dependencytrack.model.License license = new org.dependencytrack.model.License();
        license.setId(1234);
        license.setName("CustomName");
        license.setCustomLicense(true);
        c.setResolvedLicense(license);
        c.setDirectDependencies("[]");
        Component component = qm.createComponent(c, false);
        qm.persist(project);
        Response response = jersey.target(V1_BOM + "/cyclonedx/project/" + project.getUuid()).request()
                .header(X_API_KEY, apiKey)
                .get(Response.class);

        final String jsonResponse = getPlainTextBody(response);
        assertThatNoException().isThrownBy(() -> CycloneDxValidator.getInstance().validate(jsonResponse.getBytes()));
        assertThatJson(jsonResponse)
                .withMatcher("component", equalTo(component.getUuid().toString()))
                .withMatcher("projectUuid", equalTo(project.getUuid().toString()))
                .isEqualTo(json("""
                {
                    "bomFormat": "CycloneDX",
                    "specVersion": "1.5",
                    "serialNumber": "${json-unit.ignore}",
                    "version": 1,
                    "metadata": {
                        "timestamp": "${json-unit.any-string}",
                        "tools": [
                            {
                                "vendor": "OWASP",
                                "name": "Dependency-Track",
                                "version": "${json-unit.any-string}"
                            }
                        ],
                        "component": {
                            "type": "library",
                            "bom-ref": "${json-unit.matches:projectUuid}",
                            "name": "Acme Example",
                            "version": "1.0"
                        }
                    },
                    "components": [
                        {
                            "type": "library",
                            "bom-ref": "${json-unit.matches:component}",
                            "name": "sample-component",
                            "version": "1.0",
                            "licenses": [
                                {
                                    "license": {
                                        "name": "CustomName"
                                    }
                                }
                            ]
                        }
                    ],
                    "dependencies": [
                        {
                            "ref": "${json-unit.matches:projectUuid}",
                            "dependsOn": []
                        },
                        {
                            "ref": "${json-unit.matches:component}",
                            "dependsOn": []
                        }
                    ]
                }
                """));
    }

    @Test
    void exportProjectAsCycloneDxInventoryWithVulnerabilitiesTest() {
        var vulnerability = new Vulnerability();
        vulnerability.setVulnId("INT-001");
        vulnerability.setSource(Vulnerability.Source.INTERNAL);
        vulnerability.setSeverity(Severity.HIGH);
        vulnerability = qm.createVulnerability(vulnerability, false);

        var project = new Project();
        project.setName("acme-app");
        project.setClassifier(Classifier.APPLICATION);
        project = qm.createProject(project, null, false);

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
        qm.addVulnerability(vulnerability, componentWithVuln, AnalyzerIdentity.INTERNAL_ANALYZER);

        var componentWithVulnAndAnalysis = new Component();
        componentWithVulnAndAnalysis.setProject(project);
        componentWithVulnAndAnalysis.setName("acme-lib-c");
        componentWithVulnAndAnalysis.setVersion("1.0.0");
        componentWithVulnAndAnalysis.setDirectDependencies("[]");
        componentWithVulnAndAnalysis = qm.createComponent(componentWithVulnAndAnalysis, false);
        qm.addVulnerability(vulnerability, componentWithVulnAndAnalysis, AnalyzerIdentity.INTERNAL_ANALYZER);
        qm.makeAnalysis(componentWithVulnAndAnalysis, vulnerability, AnalysisState.RESOLVED, null, AnalysisResponse.UPDATE, null, true);

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

        final Response response = jersey.target(V1_BOM + "/cyclonedx/project/" + project.getUuid())
                .queryParam("variant", "withVulnerabilities")
                .request()
                .header(X_API_KEY, apiKey)
                .get(Response.class);
        assertThat(response.getStatus()).isEqualTo(HttpStatus.SC_OK);

        final String jsonResponse = getPlainTextBody(response);
        assertThatNoException().isThrownBy(() -> CycloneDxValidator.getInstance().validate(jsonResponse.getBytes()));
        assertThatJson(jsonResponse)
                .withMatcher("vulnUuid", equalTo(vulnerability.getUuid().toString()))
                .withMatcher("projectUuid", equalTo(project.getUuid().toString()))
                .withMatcher("componentWithoutVulnUuid", equalTo(componentWithoutVuln.getUuid().toString()))
                .withMatcher("componentWithVulnUuid", equalTo(componentWithVuln.getUuid().toString()))
                .withMatcher("componentWithVulnAndAnalysisUuid", equalTo(componentWithVulnAndAnalysis.getUuid().toString()))
                .isEqualTo(json("""
                {
                    "bomFormat": "CycloneDX",
                    "specVersion": "1.5",
                    "serialNumber": "${json-unit.ignore}",
                    "version": 1,
                    "metadata": {
                        "timestamp": "${json-unit.any-string}",
                        "component": {
                            "type": "application",
                            "bom-ref": "${json-unit.matches:projectUuid}",
                            "name": "acme-app",
                            "version": ""
                        },
                        "tools": [
                            {
                                "vendor": "OWASP",
                                "name": "Dependency-Track",
                                "version": "${json-unit.any-string}"
                            }
                        ]
                    },
                    "components": [
                        {
                            "type": "library",
                            "bom-ref": "${json-unit.matches:componentWithoutVulnUuid}",
                            "name": "acme-lib-a",
                            "version": "1.0.0"
                        },
                        {
                            "type": "library",
                            "bom-ref": "${json-unit.matches:componentWithVulnUuid}",
                            "name": "acme-lib-b",
                            "version": "1.0.0"
                        },
                        {
                            "type": "library",
                            "bom-ref": "${json-unit.matches:componentWithVulnAndAnalysisUuid}",
                            "name": "acme-lib-c",
                            "version": "1.0.0"
                        }
                    ],
                    "dependencies": [
                        {
                            "ref": "${json-unit.matches:projectUuid}",
                            "dependsOn": [
                                "${json-unit.matches:componentWithoutVulnUuid}",
                                "${json-unit.matches:componentWithVulnAndAnalysisUuid}"
                            ]
                        },
                        {
                            "ref": "${json-unit.matches:componentWithoutVulnUuid}",
                            "dependsOn": [
                                "${json-unit.matches:componentWithVulnUuid}"
                            ]
                        },
                        {
                            "ref": "${json-unit.matches:componentWithVulnUuid}",
                            "dependsOn": []
                        },
                        {
                            "ref": "${json-unit.matches:componentWithVulnAndAnalysisUuid}",
                            "dependsOn": []
                        }
                    ],
                    "vulnerabilities": [
                        {
                            "bom-ref": "${json-unit.matches:vulnUuid}",
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
                                    "ref": "${json-unit.matches:componentWithVulnUuid}"
                                }
                            ]
                        },
                        {
                            "bom-ref": "${json-unit.matches:vulnUuid}",
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
                                    "ref": "${json-unit.matches:componentWithVulnAndAnalysisUuid}"
                                }
                            ]
                        }
                    ]
                }
                """));

        // Ensure the dependency graph did not get deleted during export.
        // https://github.com/DependencyTrack/dependency-track/issues/2494
        qm.getPersistenceManager().refreshAll(project, componentWithoutVuln, componentWithVuln, componentWithVulnAndAnalysis);
        assertThat(project.getDirectDependencies()).isNotNull();
        assertThat(componentWithoutVuln.getDirectDependencies()).isNotNull();
        assertThat(componentWithVuln.getDirectDependencies()).isNotNull();
        assertThat(componentWithVulnAndAnalysis.getDirectDependencies()).isNotNull();
    }

    @Test
    void exportProjectAsCycloneDxVdrTest() {
        var vulnerability = new Vulnerability();
        vulnerability.setVulnId("INT-001");
        vulnerability.setSource(Vulnerability.Source.INTERNAL);
        vulnerability.setSeverity(Severity.HIGH);
        vulnerability = qm.createVulnerability(vulnerability, false);

        var project = new Project();
        project.setName("acme-app");
        project.setClassifier(Classifier.APPLICATION);
        project = qm.createProject(project, null, false);

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
        qm.addVulnerability(vulnerability, componentWithVuln, AnalyzerIdentity.INTERNAL_ANALYZER);

        var componentWithVulnAndAnalysis = new Component();
        componentWithVulnAndAnalysis.setProject(project);
        componentWithVulnAndAnalysis.setName("acme-lib-c");
        componentWithVulnAndAnalysis.setVersion("1.0.0");
        componentWithVulnAndAnalysis.setDirectDependencies("[]");
        componentWithVulnAndAnalysis = qm.createComponent(componentWithVulnAndAnalysis, false);
        qm.addVulnerability(vulnerability, componentWithVulnAndAnalysis, AnalyzerIdentity.INTERNAL_ANALYZER);
        qm.makeAnalysis(componentWithVulnAndAnalysis, vulnerability, AnalysisState.RESOLVED, null, AnalysisResponse.UPDATE, null, true);

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

        final Response response = jersey.target(V1_BOM + "/cyclonedx/project/" + project.getUuid())
                .queryParam("variant", "vdr")
                .request()
                .header(X_API_KEY, apiKey)
                .get(Response.class);
        assertThat(response.getStatus()).isEqualTo(HttpStatus.SC_OK);

        final String jsonResponse = getPlainTextBody(response);
        assertThatNoException().isThrownBy(() -> CycloneDxValidator.getInstance().validate(jsonResponse.getBytes()));
        assertThatJson(jsonResponse)
                .withMatcher("vulnUuid", equalTo(vulnerability.getUuid().toString()))
                .withMatcher("projectUuid", equalTo(project.getUuid().toString()))
                .withMatcher("componentWithoutVulnUuid", equalTo(componentWithoutVuln.getUuid().toString()))
                .withMatcher("componentWithVulnUuid", equalTo(componentWithVuln.getUuid().toString()))
                .withMatcher("componentWithVulnAndAnalysisUuid", equalTo(componentWithVulnAndAnalysis.getUuid().toString()))
                .isEqualTo(json("""
                {
                    "bomFormat": "CycloneDX",
                    "specVersion": "1.5",
                    "serialNumber": "${json-unit.ignore}",
                    "version": 1,
                    "metadata": {
                        "timestamp": "${json-unit.any-string}",
                        "component": {
                            "type": "application",
                            "bom-ref": "${json-unit.matches:projectUuid}",
                            "name": "acme-app",
                            "version": ""
                        },
                        "tools": [
                            {
                                "vendor": "OWASP",
                                "name": "Dependency-Track",
                                "version": "${json-unit.any-string}"
                            }
                        ]
                    },
                    "components": [
                        {
                            "type": "library",
                            "bom-ref": "${json-unit.matches:componentWithVulnUuid}",
                            "name": "acme-lib-b",
                            "version": "1.0.0"
                        },
                        {
                            "type": "library",
                            "bom-ref": "${json-unit.matches:componentWithVulnAndAnalysisUuid}",
                            "name": "acme-lib-c",
                            "version": "1.0.0"
                        }
                    ],
                    "dependencies": [
                        {
                            "ref": "${json-unit.matches:projectUuid}",
                            "dependsOn": [
                                "${json-unit.matches:componentWithVulnAndAnalysisUuid}"
                            ]
                        },
                        {
                            "ref": "${json-unit.matches:componentWithVulnUuid}",
                            "dependsOn": []
                        },
                        {
                            "ref": "${json-unit.matches:componentWithVulnAndAnalysisUuid}",
                            "dependsOn": []
                        }
                    ],
                    "vulnerabilities": [
                        {
                            "bom-ref": "${json-unit.matches:vulnUuid}",
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
                                    "ref": "${json-unit.matches:componentWithVulnUuid}"
                                }
                            ]
                        },
                        {
                            "bom-ref": "${json-unit.matches:vulnUuid}",
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
                                    "ref": "${json-unit.matches:componentWithVulnAndAnalysisUuid}"
                                }
                            ],
                            "analysis": {
                                "state": "resolved",
                                "response": [
                                    "update"
                                ]
                            }
                        }
                    ]
                }
                """));

        // Ensure the dependency graph did not get deleted during export.
        // https://github.com/DependencyTrack/dependency-track/issues/2494
        qm.getPersistenceManager().refreshAll(project, componentWithoutVuln, componentWithVuln, componentWithVulnAndAnalysis);
        assertThat(project.getDirectDependencies()).isNotNull();
        assertThat(componentWithoutVuln.getDirectDependencies()).isNotNull();
        assertThat(componentWithVuln.getDirectDependencies()).isNotNull();
        assertThat(componentWithVulnAndAnalysis.getDirectDependencies()).isNotNull();
    }

    @Test
    void exportComponentAsCycloneDx() {
        Project project = qm.createProject("Acme Example", null, null, null, null, null, false, false);
        Component c = new Component();
        c.setProject(project);
        c.setName("sample-component");
        c.setVersion("1.0");
        Component component = qm.createComponent(c, false);
        Response response = jersey.target(V1_BOM + "/cyclonedx/component/" + component.getUuid()).request()
                .header(X_API_KEY, apiKey)
                .get(Response.class);
        Assertions.assertEquals(200, response.getStatus(), 0);
        Assertions.assertNull(response.getHeaderString(TOTAL_COUNT_HEADER));
        String body = getPlainTextBody(response);
        Assertions.assertTrue(body.startsWith("{"));
    }

    @Test
    void exportComponentAsCycloneDxInvalid() {
        Response response = jersey.target(V1_BOM + "/cyclonedx/component/" + UUID.randomUUID()).request()
                .header(X_API_KEY, apiKey)
                .get(Response.class);
        Assertions.assertEquals(404, response.getStatus(), 0);
        Assertions.assertNull(response.getHeaderString(TOTAL_COUNT_HEADER));
        String body = getPlainTextBody(response);
        Assertions.assertEquals("The component could not be found.", body);
    }

    @Test
    void uploadBomTest() throws Exception {
        initializeWithPermissions(Permissions.BOM_UPLOAD);
        Project project = qm.createProject("Acme Example", null, "1.0", null, null, null, true, false);
        String bomString = Base64.getEncoder().encodeToString(resourceToByteArray("/unit/bom-1.xml"));
        BomSubmitRequest request = new BomSubmitRequest(project.getUuid().toString(), null, null, null, false, false, bomString);
        Response response = jersey.target(V1_BOM).request()
                .header(X_API_KEY, apiKey)
                .put(Entity.entity(request, MediaType.APPLICATION_JSON));
        Assertions.assertEquals(200, response.getStatus(), 0);
        JsonObject json = parseJsonObject(response);
        Assertions.assertNotNull(json);
        Assertions.assertNotNull(json.getString("token"));
        Assertions.assertTrue(UuidUtil.isValidUUID(json.getString("token")));
    }

    @Test
    void uploadBomInvalidProjectTest() throws Exception {
        initializeWithPermissions(Permissions.BOM_UPLOAD);
        String bomString = Base64.getEncoder().encodeToString(resourceToByteArray("/unit/bom-1.xml"));
        BomSubmitRequest request = new BomSubmitRequest(UUID.randomUUID().toString(), null, null, null, false, false, bomString);
        Response response = jersey.target(V1_BOM).request()
                .header(X_API_KEY, apiKey)
                .put(Entity.entity(request, MediaType.APPLICATION_JSON));
        Assertions.assertEquals(404, response.getStatus(), 0);
        Assertions.assertNull(response.getHeaderString(TOTAL_COUNT_HEADER));
        String body = getPlainTextBody(response);
        Assertions.assertEquals("The project could not be found.", body);
    }

    @Test
    void uploadBomAutoCreateTest() throws Exception {
        initializeWithPermissions(Permissions.BOM_UPLOAD, Permissions.PROJECT_CREATION_UPLOAD);
        String bomString = Base64.getEncoder().encodeToString(resourceToByteArray("/unit/bom-1.xml"));
        BomSubmitRequest request = new BomSubmitRequest(null, "Acme Example", "1.0", null, true, false, bomString);
        Response response = jersey.target(V1_BOM).request()
                .header(X_API_KEY, apiKey)
                .put(Entity.entity(request, MediaType.APPLICATION_JSON));
        Assertions.assertEquals(200, response.getStatus(), 0);
        JsonObject json = parseJsonObject(response);
        Assertions.assertNotNull(json);
        Assertions.assertNotNull(json.getString("token"));
        Assertions.assertTrue(UuidUtil.isValidUUID(json.getString("token")));
        Project project = qm.getProject("Acme Example", "1.0");
        Assertions.assertNotNull(project);
    }

    @Test
    void uploadBomAutoCreateWithTagsTest() throws Exception {
        initializeWithPermissions(Permissions.BOM_UPLOAD, Permissions.PROJECT_CREATION_UPLOAD);
        String bomString = Base64.getEncoder().encodeToString(resourceToByteArray("/unit/bom-1.xml"));
        List<Tag> tags = Stream.of("tag1", "tag2").map(name -> {
          Tag tag = new Tag();
          tag.setName(name);
          return tag;
        }).collect(Collectors.toList());
        BomSubmitRequest request = new BomSubmitRequest(null, "Acme Example", "1.0",
                tags, true, false, bomString);
        Response response = jersey.target(V1_BOM).request()
                .header(X_API_KEY, apiKey)
                .put(Entity.entity(request, MediaType.APPLICATION_JSON));
        Assertions.assertEquals(200, response.getStatus(), 0);
        JsonObject json = parseJsonObject(response);
        Assertions.assertNotNull(json);
        Assertions.assertNotNull(json.getString("token"));
        Assertions.assertTrue(UuidUtil.isValidUUID(json.getString("token")));
        Project project = qm.getProject("Acme Example", "1.0");
        Assertions.assertNotNull(project);
        assertThat(project.getTags())
          .extracting(Tag::getName)
          .containsExactlyInAnyOrder("tag1", "tag2");
    }

    @Test
    void uploadBomAutoCreateWithTagsMultipartTest() throws Exception {
        initializeWithPermissions(Permissions.BOM_UPLOAD, Permissions.PROJECT_CREATION_UPLOAD);

        final var multiPart = new FormDataMultiPart()
                .field("bom", resourceToString("/unit/bom-1.xml", StandardCharsets.UTF_8), MediaType.APPLICATION_XML_TYPE)
                .field("projectName", "Acme Example")
                .field("projectVersion", "1.0")
                .field("projectTags", "tag1,tag2")
                .field("autoCreate", "true");

        // NB: The GrizzlyConnectorProvider doesn't work with MultiPart requests.
        // https://github.com/eclipse-ee4j/jersey/issues/5094
        final var client = ClientBuilder.newClient(new ClientConfig()
                .connectorProvider(new HttpUrlConnectorProvider()));

        final Response response = client.target(jersey.target(V1_BOM).getUri()).request()
                .header(X_API_KEY, apiKey)
                .post(Entity.entity(multiPart, multiPart.getMediaType()));
        assertThat(response.getStatus()).isEqualTo(200);
        assertThatJson(getPlainTextBody(response)).isEqualTo("""
                {
                  "token": "${json-unit.any-string}"
                }
                """);

        final Project project = qm.getProject("Acme Example", "1.0");
        assertThat(project).isNotNull();
        assertThat(project.getTags())
                .extracting(Tag::getName)
                .containsExactlyInAnyOrder("tag1", "tag2");
    }

    @Test
    void uploadBomUnauthorizedTest() throws Exception {
        String bomString = Base64.getEncoder().encodeToString(resourceToByteArray("/unit/bom-1.xml"));
        BomSubmitRequest request = new BomSubmitRequest(null, "Acme Example", "1.0",
                null, true, false, bomString);
        Response response = jersey.target(V1_BOM).request()
                .header(X_API_KEY, apiKey)
                .put(Entity.entity(request, MediaType.APPLICATION_JSON));
        Assertions.assertEquals(401, response.getStatus(), 0);
        String body = getPlainTextBody(response);
        Assertions.assertEquals("The principal does not have permission to create project.", body);
    }

    @Test
    void uploadBomAutoCreateLatestWithAclTest() throws Exception {
        initializeWithPermissions(Permissions.BOM_UPLOAD, Permissions.PROJECT_CREATION_UPLOAD);
        enablePortfolioAccessControl();

        final var accessLatestProject = new Project();
        accessLatestProject.setName("acme-app-a");
        accessLatestProject.setVersion("1.0.0");
        accessLatestProject.setIsLatest(true);
        accessLatestProject.setAccessTeams(List.of(team));
        qm.persist(accessLatestProject);

        String bomString = Base64.getEncoder().encodeToString(resourceToByteArray("/unit/bom-1.xml"));
        BomSubmitRequest request = new BomSubmitRequest(null, accessLatestProject.getName(),
                "1.0.1", null, true, true, bomString);
        Response response = jersey.target(V1_BOM).request()
                .header(X_API_KEY, apiKey)
                .put(Entity.entity(request, MediaType.APPLICATION_JSON));
        Assertions.assertEquals(200, response.getStatus(), 0);
        JsonObject json = parseJsonObject(response);
        Assertions.assertNotNull(json);
        Assertions.assertNotNull(json.getString("token"));
    }

    @Test
    void uploadBomAutoCreateLatestWithAclNoAccessTest() throws Exception {
        initializeWithPermissions(Permissions.BOM_UPLOAD, Permissions.PROJECT_CREATION_UPLOAD);
        enablePortfolioAccessControl();

        final var noAccessLatestProject = new Project();
        noAccessLatestProject.setName("acme-app-a");
        noAccessLatestProject.setVersion("1.0.0");
        noAccessLatestProject.setIsLatest(true);
        qm.persist(noAccessLatestProject);

        String bomString = Base64.getEncoder().encodeToString(resourceToByteArray("/unit/bom-1.xml"));
        BomSubmitRequest request = new BomSubmitRequest(null, noAccessLatestProject.getName(),
                "1.0.1", null, true, true, bomString);
        Response response = jersey.target(V1_BOM).request()
                .header(X_API_KEY, apiKey)
                .put(Entity.entity(request, MediaType.APPLICATION_JSON));
        Assertions.assertEquals(403, response.getStatus(), 0);
    }

    @ParameterizedTest
    @MethodSource("uploadBomIsLatestTestParameters")
    void uploadBomIsLatestTest(Boolean isLatestProjectVersion, Boolean isLatest, boolean expectedIsLatest) throws Exception {
        initializeWithPermissions(Permissions.BOM_UPLOAD, Permissions.PROJECT_CREATION_UPLOAD);
        var project = new Project();
        project.setName("uploadBomIsLatest");
        project.setVersion("1.0.0");
        project.setIsLatest(true);
        qm.persist(project);
        
        String bomString = Base64.getEncoder().encodeToString(resourceToByteArray("/unit/bom-1.xml"));

        StringBuilder jsonBuilder = new StringBuilder();
        jsonBuilder.append("{");
        jsonBuilder.append("\"projectName\": \"uploadBomIsLatest\",");
        jsonBuilder.append("\"projectVersion\": \"1.0.1\",");
        jsonBuilder.append("\"autoCreate\": true,");
        jsonBuilder.append("\"bom\": \"").append(bomString).append("\"");
        if (isLatestProjectVersion != null) {
            jsonBuilder.append(",\"isLatestProjectVersion\": ").append(isLatestProjectVersion);
        }
        if (isLatest != null) {
            jsonBuilder.append(",\"isLatest\": ").append(isLatest);
        }
        jsonBuilder.append("}");
        String jsonRequest = jsonBuilder.toString();

        Response response = jersey.target(V1_BOM).request()
                .header(X_API_KEY, apiKey)
                .put(Entity.entity(jsonRequest, MediaType.APPLICATION_JSON));
        Assertions.assertEquals(200, response.getStatus(), 0);
        JsonObject json = parseJsonObject(response);
        Assertions.assertNotNull(json);
        Assertions.assertNotNull(json.getString("token"));
        project = qm.getProject("uploadBomIsLatest", "1.0.1");
        Assertions.assertNotNull(project);
        Assertions.assertEquals(expectedIsLatest, project.isLatest());
    }

    private static Object[] uploadBomIsLatestTestParameters() {
        return new Object[] {
            new Object[] { true, null, true },
            new Object[] { true, true, true },
            new Object[] { true, false, false },
            new Object[] { false, null, false },
            new Object[] { false, true, true },
            new Object[] { false, false, false },
            new Object[] { null, null, false },
            new Object[] { null, true, true },
            new Object[] { null, false, false },
        };
    }

    @Test
    void uploadBomAutoCreateTestWithParentTest() throws Exception {
        initializeWithPermissions(Permissions.BOM_UPLOAD, Permissions.PROJECT_CREATION_UPLOAD);
        String bomString = Base64.getEncoder().encodeToString(resourceToByteArray("/unit/bom-1.xml"));
        // Upload parent project
        BomSubmitRequest request = new BomSubmitRequest(null, "Acme Parent", "1.0",
                null, true, false, bomString);
        Response response = jersey.target(V1_BOM).request()
                .header(X_API_KEY, apiKey)
                .put(Entity.entity(request, MediaType.APPLICATION_JSON));
        Assertions.assertEquals(200, response.getStatus(), 0);
        JsonObject json = parseJsonObject(response);
        Assertions.assertNotNull(json);
        Project parent = qm.getProject("Acme Parent", "1.0");
        Assertions.assertNotNull(parent);
        String parentUUID = parent.getUuid().toString();

        // Upload first child, search parent by UUID
        request = new BomSubmitRequest(null, "Acme Example", "1.0", null, true, parentUUID, null, null, false, bomString);
        response = jersey.target(V1_BOM).request()
                .header(X_API_KEY, apiKey)
                .put(Entity.entity(request, MediaType.APPLICATION_JSON));
        Assertions.assertEquals(200, response.getStatus(), 0);
        json = parseJsonObject(response);
        Assertions.assertNotNull(json);
        Assertions.assertNotNull(json.getString("token"));
        Assertions.assertTrue(UuidUtil.isValidUUID(json.getString("token")));
        Project child = qm.getProject("Acme Example", "1.0");
        Assertions.assertNotNull(child);
        Assertions.assertNotNull(child.getParent());
        Assertions.assertEquals(parentUUID, child.getParent().getUuid().toString());


        // Upload second child, search parent by name+ver
        request = new BomSubmitRequest(null, "Acme Example", "2.0", null, true, null, "Acme Parent", "1.0", false, bomString);
        response = jersey.target(V1_BOM).request()
                .header(X_API_KEY, apiKey)
                .put(Entity.entity(request, MediaType.APPLICATION_JSON));
        Assertions.assertEquals(200, response.getStatus(), 0);
        json = parseJsonObject(response);
        Assertions.assertNotNull(json);
        Assertions.assertNotNull(json.getString("token"));
        Assertions.assertTrue(UuidUtil.isValidUUID(json.getString("token")));
        child = qm.getProject("Acme Example", "2.0");
        Assertions.assertNotNull(child);
        Assertions.assertNotNull(child.getParent());
        Assertions.assertEquals(parentUUID, child.getParent().getUuid().toString());

        // Upload third child, specify parent's UUID, name, ver. Name and ver are ignored when UUID is specified.
        request = new BomSubmitRequest(null, "Acme Example", "3.0", null, true, parentUUID, "Non-existent parent", "1.0", false, bomString);
        response = jersey.target(V1_BOM).request()
                .header(X_API_KEY, apiKey)
                .put(Entity.entity(request, MediaType.APPLICATION_JSON));
        Assertions.assertEquals(200, response.getStatus(), 0);
        json = parseJsonObject(response);
        Assertions.assertNotNull(json);
        Assertions.assertNotNull(json.getString("token"));
        Assertions.assertTrue(UuidUtil.isValidUUID(json.getString("token")));
        child = qm.getProject("Acme Example", "3.0");
        Assertions.assertNotNull(child);
        Assertions.assertNotNull(child.getParent());
        Assertions.assertEquals(parentUUID, child.getParent().getUuid().toString());
    }

    @Test
    void uploadBomInvalidParentTest() throws Exception {
        initializeWithPermissions(Permissions.BOM_UPLOAD, Permissions.PROJECT_CREATION_UPLOAD);
        String bomString = Base64.getEncoder().encodeToString(resourceToByteArray("/unit/bom-1.xml"));
        BomSubmitRequest request = new BomSubmitRequest(null, "Acme Example", "1.0", null, true, UUID.randomUUID().toString(), null, null, false, bomString);
        Response response = jersey.target(V1_BOM).request()
                .header(X_API_KEY, apiKey)
                .put(Entity.entity(request, MediaType.APPLICATION_JSON));
        Assertions.assertEquals(404, response.getStatus(), 0);
        String body = getPlainTextBody(response);
        Assertions.assertEquals("The parent component could not be found.", body);

        request = new BomSubmitRequest(null, "Acme Example", "2.0", null, true, null, "Non-existent parent", null, false, bomString);
        response = jersey.target(V1_BOM).request()
                .header(X_API_KEY, apiKey)
                .put(Entity.entity(request, MediaType.APPLICATION_JSON));
        Assertions.assertEquals(404, response.getStatus(), 0);
        body = getPlainTextBody(response);
        Assertions.assertEquals("The parent component could not be found.", body);
    }

    @Test
    void uploadBomInvalidJsonTest() {
        initializeWithPermissions(Permissions.BOM_UPLOAD);

        qm.createConfigProperty(
                BOM_VALIDATION_MODE.getGroupName(),
                BOM_VALIDATION_MODE.getPropertyName(),
                BomValidationMode.ENABLED.name(),
                BOM_VALIDATION_MODE.getPropertyType(),
                BOM_VALIDATION_MODE.getDescription()
        );

        final var project = new Project();
        project.setName("acme-app");
        project.setVersion("1.0.0");
        qm.persist(project);

        final String encodedBom = Base64.getEncoder().encodeToString("""
                {
                  "bomFormat": "CycloneDX",
                  "specVersion": "1.2",
                  "serialNumber": "urn:uuid:3e671687-395b-41f5-a30f-a58921a69b79",
                  "version": 1,
                  "components": [
                    {
                      "type": "foo",
                      "name": "acme-library",
                      "version": "1.0.0"
                    }
                  ]
                }
                """.getBytes());

        final Response response = jersey.target(V1_BOM).request()
                .header(X_API_KEY, apiKey)
                .put(Entity.entity("""
                        {
                          "projectName": "acme-app",
                          "projectVersion": "1.0.0",
                          "bom": "%s"
                        }
                        """.formatted(encodedBom), MediaType.APPLICATION_JSON));

        assertThat(response.getStatus()).isEqualTo(400);
        assertThatJson(getPlainTextBody(response)).isEqualTo("""
                {
                  "status": 400,
                  "title": "The uploaded BOM is invalid",
                  "detail": "Schema validation failed",
                  "errors": [
                    "$.components[0].type: does not have a value in the enumeration [\\"application\\", \\"framework\\", \\"library\\", \\"container\\", \\"operating-system\\", \\"device\\", \\"firmware\\", \\"file\\"]"
                  ]
                }
                """);
    }

    @Test
    void uploadBomInvalidXmlTest() {
        initializeWithPermissions(Permissions.BOM_UPLOAD);

        qm.createConfigProperty(
                BOM_VALIDATION_MODE.getGroupName(),
                BOM_VALIDATION_MODE.getPropertyName(),
                BomValidationMode.ENABLED.name(),
                BOM_VALIDATION_MODE.getPropertyType(),
                BOM_VALIDATION_MODE.getDescription()
        );

        final var project = new Project();
        project.setName("acme-app");
        project.setVersion("1.0.0");
        qm.persist(project);

        final String encodedBom = Base64.getEncoder().encodeToString("""
                <?xml version="1.0"?>
                <bom serialNumber="urn:uuid:3e671687-395b-41f5-a30f-a58921a69b79" version="1" xmlns="http://cyclonedx.org/schema/bom/1.2">
                    <components>
                        <component type="foo">
                            <name>acme-library</name>
                            <version>1.0.0</version>
                        </component>
                    </components>
                </bom>
                """.getBytes());

        final Response response = jersey.target(V1_BOM).request()
                .header(X_API_KEY, apiKey)
                .put(Entity.entity("""
                        {
                          "projectName": "acme-app",
                          "projectVersion": "1.0.0",
                          "bom": "%s"
                        }
                        """.formatted(encodedBom), MediaType.APPLICATION_JSON));

        assertThat(response.getStatus()).isEqualTo(400);
        assertThatJson(getPlainTextBody(response)).isEqualTo("""
                {
                  "status": 400,
                  "title": "The uploaded BOM is invalid",
                  "detail": "Schema validation failed",
                  "errors": [
                    "cvc-enumeration-valid: Value 'foo' is not facet-valid with respect to enumeration '[application, framework, library, container, operating-system, device, firmware, file]'. It must be a value from the enumeration.",
                    "cvc-attribute.3: The value 'foo' of attribute 'type' on element 'component' is not valid with respect to its type, 'classification'."
                  ]
                }
                """);
    }

    @Test
    void uploadBomWithValidationModeDisabledTest() {
        initializeWithPermissions(Permissions.BOM_UPLOAD);

        qm.createConfigProperty(
                BOM_VALIDATION_MODE.getGroupName(),
                BOM_VALIDATION_MODE.getPropertyName(),
                BomValidationMode.DISABLED.name(),
                BOM_VALIDATION_MODE.getPropertyType(),
                BOM_VALIDATION_MODE.getDescription()
        );

        final var project = new Project();
        project.setName("acme-app");
        project.setVersion("1.0.0");
        qm.persist(project);

        final String encodedBom = Base64.getEncoder().encodeToString("""
                {
                  "bomFormat": "CycloneDX",
                  "specVersion": "1.2",
                  "serialNumber": "urn:uuid:3e671687-395b-41f5-a30f-a58921a69b79",
                  "version": 1,
                  "components": [
                    {
                      "type": "foo",
                      "name": "acme-library",
                      "version": "1.0.0"
                    }
                  ]
                }
                """.getBytes());

        final Response response = jersey.target(V1_BOM).request()
                .header(X_API_KEY, apiKey)
                .put(Entity.entity("""
                        {
                          "projectName": "acme-app",
                          "projectVersion": "1.0.0",
                          "bom": "%s"
                        }
                        """.formatted(encodedBom), MediaType.APPLICATION_JSON));
        assertThat(response.getStatus()).isEqualTo(200);
    }

    @Test
    void uploadBomWithValidationModeEnabledForTagsTest() {
        initializeWithPermissions(Permissions.BOM_UPLOAD);

        qm.createConfigProperty(
                BOM_VALIDATION_MODE.getGroupName(),
                BOM_VALIDATION_MODE.getPropertyName(),
                BomValidationMode.ENABLED_FOR_TAGS.name(),
                BOM_VALIDATION_MODE.getPropertyType(),
                BOM_VALIDATION_MODE.getDescription()
        );
        qm.createConfigProperty(
                BOM_VALIDATION_TAGS_INCLUSIVE.getGroupName(),
                BOM_VALIDATION_TAGS_INCLUSIVE.getPropertyName(),
                "[\"foo\"]",
                BOM_VALIDATION_TAGS_INCLUSIVE.getPropertyType(),
                BOM_VALIDATION_TAGS_INCLUSIVE.getDescription()
        );

        final var project = new Project();
        project.setName("acme-app");
        project.setVersion("1.0.0");
        qm.persist(project);

        qm.bind(project, List.of(qm.createTag("foo")));

        final String encodedBom = Base64.getEncoder().encodeToString("""
                {
                  "bomFormat": "CycloneDX",
                  "specVersion": "1.2",
                  "serialNumber": "urn:uuid:3e671687-395b-41f5-a30f-a58921a69b79",
                  "version": 1,
                  "components": [
                    {
                      "type": "foo",
                      "name": "acme-library",
                      "version": "1.0.0"
                    }
                  ]
                }
                """.getBytes());

        Response response = jersey.target(V1_BOM).request()
                .header(X_API_KEY, apiKey)
                .put(Entity.entity("""
                        {
                          "projectName": "acme-app",
                          "projectVersion": "1.0.0",
                          "bom": "%s"
                        }
                        """.formatted(encodedBom), MediaType.APPLICATION_JSON));
        assertThat(response.getStatus()).isEqualTo(400);

        qm.bind(project, Collections.emptyList());

        response = jersey.target(V1_BOM).request()
                .header(X_API_KEY, apiKey)
                .put(Entity.entity("""
                        {
                          "projectName": "acme-app",
                          "projectVersion": "1.0.0",
                          "bom": "%s"
                        }
                        """.formatted(encodedBom), MediaType.APPLICATION_JSON));
        assertThat(response.getStatus()).isEqualTo(200);
    }

    @Test
    void uploadBomWithValidationModeDisabledForTagsTest() {
        initializeWithPermissions(Permissions.BOM_UPLOAD);

        qm.createConfigProperty(
                BOM_VALIDATION_MODE.getGroupName(),
                BOM_VALIDATION_MODE.getPropertyName(),
                BomValidationMode.DISABLED_FOR_TAGS.name(),
                BOM_VALIDATION_MODE.getPropertyType(),
                BOM_VALIDATION_MODE.getDescription()
        );
        qm.createConfigProperty(
                BOM_VALIDATION_TAGS_EXCLUSIVE.getGroupName(),
                BOM_VALIDATION_TAGS_EXCLUSIVE.getPropertyName(),
                "[\"foo\"]",
                BOM_VALIDATION_TAGS_EXCLUSIVE.getPropertyType(),
                BOM_VALIDATION_TAGS_EXCLUSIVE.getDescription()
        );

        final var project = new Project();
        project.setName("acme-app");
        project.setVersion("1.0.0");
        qm.persist(project);

        qm.bind(project, List.of(qm.createTag("foo")));

        final String encodedBom = Base64.getEncoder().encodeToString("""
                {
                  "bomFormat": "CycloneDX",
                  "specVersion": "1.2",
                  "serialNumber": "urn:uuid:3e671687-395b-41f5-a30f-a58921a69b79",
                  "version": 1,
                  "components": [
                    {
                      "type": "foo",
                      "name": "acme-library",
                      "version": "1.0.0"
                    }
                  ]
                }
                """.getBytes());

        Response response = jersey.target(V1_BOM).request()
                .header(X_API_KEY, apiKey)
                .put(Entity.entity("""
                        {
                          "projectName": "acme-app",
                          "projectVersion": "1.0.0",
                          "bom": "%s"
                        }
                        """.formatted(encodedBom), MediaType.APPLICATION_JSON));
        assertThat(response.getStatus()).isEqualTo(200);

        qm.bind(project, Collections.emptyList());

        response = jersey.target(V1_BOM).request()
                .header(X_API_KEY, apiKey)
                .put(Entity.entity("""
                        {
                          "projectName": "acme-app",
                          "projectVersion": "1.0.0",
                          "bom": "%s"
                        }
                        """.formatted(encodedBom), MediaType.APPLICATION_JSON));
        assertThat(response.getStatus()).isEqualTo(400);
    }

    @Test
    void uploadBomWithValidationTagsInvalidTest() {
        initializeWithPermissions(Permissions.BOM_UPLOAD);

        qm.createConfigProperty(
                BOM_VALIDATION_MODE.getGroupName(),
                BOM_VALIDATION_MODE.getPropertyName(),
                BomValidationMode.ENABLED_FOR_TAGS.name(),
                BOM_VALIDATION_MODE.getPropertyType(),
                BOM_VALIDATION_MODE.getDescription()
        );
        qm.createConfigProperty(
                BOM_VALIDATION_TAGS_INCLUSIVE.getGroupName(),
                BOM_VALIDATION_TAGS_INCLUSIVE.getPropertyName(),
                "invalid",
                BOM_VALIDATION_TAGS_INCLUSIVE.getPropertyType(),
                BOM_VALIDATION_TAGS_INCLUSIVE.getDescription()
        );

        final var project = new Project();
        project.setName("acme-app");
        project.setVersion("1.0.0");
        qm.persist(project);

        qm.bind(project, List.of(qm.createTag("foo")));

        final String encodedBom = Base64.getEncoder().encodeToString("""
                {
                  "bomFormat": "CycloneDX",
                  "specVersion": "1.2",
                  "serialNumber": "urn:uuid:3e671687-395b-41f5-a30f-a58921a69b79",
                  "version": 1,
                  "components": [
                    {
                      "type": "foo",
                      "name": "acme-library",
                      "version": "1.0.0"
                    }
                  ]
                }
                """.getBytes());

        // With validation mode ENABLED_FOR_TAGS, and invalid tags,
        // should fall back to NOT validating.
        Response response = jersey.target(V1_BOM).request()
                .header(X_API_KEY, apiKey)
                .put(Entity.entity("""
                        {
                          "projectName": "acme-app",
                          "projectVersion": "1.0.0",
                          "bom": "%s"
                        }
                        """.formatted(encodedBom), MediaType.APPLICATION_JSON));
        assertThat(response.getStatus()).isEqualTo(200);

        qm.bind(project, Collections.emptyList());

        // Removal of the project tag should not make a difference.
        response = jersey.target(V1_BOM).request()
                .header(X_API_KEY, apiKey)
                .put(Entity.entity("""
                        {
                          "projectName": "acme-app",
                          "projectVersion": "1.0.0",
                          "bom": "%s"
                        }
                        """.formatted(encodedBom), MediaType.APPLICATION_JSON));
        assertThat(response.getStatus()).isEqualTo(200);
    }

    @Test
    void uploadBomTooLargeViaPutTest() {
        initializeWithPermissions(Permissions.BOM_UPLOAD);

        final var project = new Project();
        project.setName("acme-app");
        project.setVersion("1.0.0");
        qm.persist(project);

        final String bom = "a".repeat(StreamReadConstraints.DEFAULT_MAX_STRING_LEN + 1);

        final Response response = jersey.target(V1_BOM).request()
                .header(X_API_KEY, apiKey)
                .put(Entity.entity("""
                        {
                          "projectName": "acme-app",
                          "projectVersion": "1.0.0",
                          "bom": "%s"
                        }
                        """.formatted(bom), MediaType.APPLICATION_JSON));
        assertThat(response.getStatus()).isEqualTo(400);
        assertThat(response.getHeaderString("Content-Type")).isEqualTo("application/problem+json");
        assertThatJson(getPlainTextBody(response)).isEqualTo("""
                {
                  "status": 400,
                  "title": "The provided JSON payload could not be mapped",
                  "detail": "The BOM is too large to be transmitted safely via Base64 encoded JSON value. Please use the \\"POST /api/v1/bom\\" endpoint with Content-Type \\"multipart/form-data\\" instead. Original cause: String value length (20000001) exceeds the maximum allowed (20000000, from `StreamReadConstraints.getMaxStringLength()`) (through reference chain: org.dependencytrack.resources.v1.vo.BomSubmitRequest[\\"bom\\"])"
                }
                """);
    }

    @Test
    void uploadBomUpdateTagsOfExistingProjectWithoutTagsTest() {
        initializeWithPermissions(Permissions.BOM_UPLOAD, Permissions.PORTFOLIO_MANAGEMENT);

        final var project = new Project();
        project.setName("acme-app");
        project.setVersion("1.0.0");
        qm.persist(project);

        final String encodedBom = Base64.getEncoder().encodeToString("""
                {
                  "bomFormat": "CycloneDX",
                  "specVersion": "1.5",
                  "version": 1
                }
                """.getBytes());

        final Response response = jersey.target(V1_BOM).request()
                .header(X_API_KEY, apiKey)
                .put(Entity.json(/* language=JSON */ """
                        {
                          "projectName": "acme-app",
                          "projectVersion": "1.0.0",
                          "projectTags": [
                            {
                              "name": "foo"
                            },
                            {
                              "name": "bar"
                            }
                          ],
                          "bom": "%s"
                        }
                        """.formatted(encodedBom)));
        assertThat(response.getStatus()).isEqualTo(200);

        qm.getPersistenceManager().evictAll();
        assertThat(project.getTags()).satisfiesExactlyInAnyOrder(
                tag -> assertThat(tag.getName()).isEqualTo("foo"),
                tag -> assertThat(tag.getName()).isEqualTo("bar"));
    }

    @Test
    void uploadBomUpdateTagsOfExistingProjectWithTagsTest() {
        initializeWithPermissions(Permissions.BOM_UPLOAD, Permissions.PORTFOLIO_MANAGEMENT);

        final var project = new Project();
        project.setName("acme-app");
        project.setVersion("1.0.0");
        qm.persist(project);

        qm.bind(project, List.of(
                qm.createTag("foo"),
                qm.createTag("bar")));

        final String encodedBom = Base64.getEncoder().encodeToString("""
                {
                  "bomFormat": "CycloneDX",
                  "specVersion": "1.5",
                  "version": 1
                }
                """.getBytes());

        final Response response = jersey.target(V1_BOM).request()
                .header(X_API_KEY, apiKey)
                .put(Entity.json(/* language=JSON */ """
                        {
                          "projectName": "acme-app",
                          "projectVersion": "1.0.0",
                          "projectTags": [
                            {
                              "name": "foo"
                            },
                            {
                              "name": "baz"
                            }
                          ],
                          "bom": "%s"
                        }
                        """.formatted(encodedBom)));
        assertThat(response.getStatus()).isEqualTo(200);

        qm.getPersistenceManager().evictAll();
        assertThat(project.getTags()).satisfiesExactlyInAnyOrder(
                tag -> assertThat(tag.getName()).isEqualTo("foo"),
                tag -> assertThat(tag.getName()).isEqualTo("baz"));
    }

    @Test
    void uploadBomNoUpdateTagsOfExistingProjectWithTagsTest() {
        initializeWithPermissions(Permissions.BOM_UPLOAD, Permissions.PORTFOLIO_MANAGEMENT);

        final var project = new Project();
        project.setName("acme-app");
        project.setVersion("1.0.0");
        qm.persist(project);

        qm.bind(project, List.of(
                qm.createTag("foo"),
                qm.createTag("bar")));

        final String encodedBom = Base64.getEncoder().encodeToString("""
                {
                  "bomFormat": "CycloneDX",
                  "specVersion": "1.5",
                  "version": 1
                }
                """.getBytes());

        final Response response = jersey.target(V1_BOM).request()
                .header(X_API_KEY, apiKey)
                .put(Entity.json(/* language=JSON */ """
                        {
                          "projectName": "acme-app",
                          "projectVersion": "1.0.0",
                          "bom": "%s"
                        }
                        """.formatted(encodedBom)));
        assertThat(response.getStatus()).isEqualTo(200);

        qm.getPersistenceManager().evictAll();
        assertThat(project.getTags()).satisfiesExactlyInAnyOrder(
                tag -> assertThat(tag.getName()).isEqualTo("foo"),
                tag -> assertThat(tag.getName()).isEqualTo("bar"));
    }

    @Test
    void uploadBomNoUpdateTagsOfExistingProjectWithTagsWithoutPortfolioManagementPermissionTest() {
        initializeWithPermissions(Permissions.BOM_UPLOAD);

        final var project = new Project();
        project.setName("acme-app");
        project.setVersion("1.0.0");
        qm.persist(project);

        qm.bind(project, List.of(
                qm.createTag("foo"),
                qm.createTag("bar")));

        final String encodedBom = Base64.getEncoder().encodeToString("""
                {
                  "bomFormat": "CycloneDX",
                  "specVersion": "1.5",
                  "version": 1
                }
                """.getBytes());

        final Response response = jersey.target(V1_BOM).request()
                .header(X_API_KEY, apiKey)
                .put(Entity.json(/* language=JSON */ """
                        {
                          "projectName": "acme-app",
                          "projectVersion": "1.0.0",
                          "projectTags": [
                            {
                              "name": "baz"
                            }
                          ],
                          "bom": "%s"
                        }
                        """.formatted(encodedBom)));
        assertThat(response.getStatus()).isEqualTo(200);

        qm.getPersistenceManager().evictAll();
        assertThat(project.getTags()).satisfiesExactlyInAnyOrder(
                tag -> assertThat(tag.getName()).isEqualTo("foo"),
                tag -> assertThat(tag.getName()).isEqualTo("bar"));
    }

    @Test
    void validateCycloneDxBomWithMultipleNamespacesTest() throws Exception {
        byte[] bom = resourceToByteArray("/unit/bom-issue4008.xml");
        assertThatNoException().isThrownBy(() -> CycloneDxValidator.getInstance().validate(bom));
    }

    @Test
    void uploadBomCollectionProjectTest() throws Exception {
        initializeWithPermissions(Permissions.BOM_UPLOAD);
        Project project = qm.createProject("Acme Example", null, "1.0", null, null, null, true, false);

        // make project a collection project
        project.setCollectionLogic(ProjectCollectionLogic.AGGREGATE_DIRECT_CHILDREN);
        qm.updateProject(project, false);

        String bomString = Base64.getEncoder().encodeToString(resourceToByteArray("/unit/bom-1.xml"));
        BomSubmitRequest request = new BomSubmitRequest(project.getUuid().toString(), null, null, null, false, false, bomString);
        Response response = jersey.target(V1_BOM).request()
                .header(X_API_KEY, apiKey)
                .put(Entity.entity(request, MediaType.APPLICATION_JSON));
        Assertions.assertEquals(400, response.getStatus(), 0);
        Assertions.assertNull(response.getHeaderString(TOTAL_COUNT_HEADER));
        String body = getPlainTextBody(response);
        Assertions.assertEquals("BOM cannot be uploaded to collection project.", body);
    }

}
