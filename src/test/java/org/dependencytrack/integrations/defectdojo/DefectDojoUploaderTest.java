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
package org.dependencytrack.integrations.defectdojo;

import alpine.model.IConfigProperty;
import com.github.tomakehurst.wiremock.junit.WireMockRule;
import org.apache.http.HttpHeaders;
import org.dependencytrack.PersistenceCapableTest;
import org.dependencytrack.model.Component;
import org.dependencytrack.model.Finding;
import org.dependencytrack.model.Project;
import org.dependencytrack.model.Severity;
import org.dependencytrack.model.Vulnerability;
import org.dependencytrack.tasks.scanners.AnalyzerIdentity;
import org.junit.Assert;
import org.junit.Ignore;
import org.junit.Rule;
import org.junit.Test;

import javax.ws.rs.core.MediaType;
import java.io.InputStream;
import java.util.List;

import static com.github.tomakehurst.wiremock.client.WireMock.aMultipart;
import static com.github.tomakehurst.wiremock.client.WireMock.aResponse;
import static com.github.tomakehurst.wiremock.client.WireMock.equalTo;
import static com.github.tomakehurst.wiremock.client.WireMock.equalToJson;
import static com.github.tomakehurst.wiremock.client.WireMock.get;
import static com.github.tomakehurst.wiremock.client.WireMock.getRequestedFor;
import static com.github.tomakehurst.wiremock.client.WireMock.matching;
import static com.github.tomakehurst.wiremock.client.WireMock.post;
import static com.github.tomakehurst.wiremock.client.WireMock.postRequestedFor;
import static com.github.tomakehurst.wiremock.client.WireMock.stubFor;
import static com.github.tomakehurst.wiremock.client.WireMock.urlPathEqualTo;
import static com.github.tomakehurst.wiremock.client.WireMock.verify;
import static com.github.tomakehurst.wiremock.core.WireMockConfiguration.options;
import static org.dependencytrack.model.ConfigPropertyConstants.DEFECTDOJO_API_KEY;
import static org.dependencytrack.model.ConfigPropertyConstants.DEFECTDOJO_ENABLED;
import static org.dependencytrack.model.ConfigPropertyConstants.DEFECTDOJO_REIMPORT_ENABLED;
import static org.dependencytrack.model.ConfigPropertyConstants.DEFECTDOJO_URL;

public class DefectDojoUploaderTest extends PersistenceCapableTest {

    @Rule
    public WireMockRule wireMockRule = new WireMockRule(options().dynamicPort());

    @Test
    public void testIntegrationMetadata() {
        DefectDojoUploader extension = new DefectDojoUploader();
        Assert.assertEquals("DefectDojo", extension.name());
        Assert.assertEquals("Pushes Dependency-Track findings to DefectDojo", extension.description());
    }

    @Test
    public void testIntegrationEnabledCases() {
        qm.createConfigProperty(
                DEFECTDOJO_ENABLED.getGroupName(),
                DEFECTDOJO_ENABLED.getPropertyName(),
                "true",
                IConfigProperty.PropertyType.BOOLEAN,
                null
        );
        Project project = qm.createProject("ACME Example", null, "1.0", null, null, null, true, false);
        qm.createProjectProperty(
                project,
                DEFECTDOJO_ENABLED.getGroupName(),
                "defectdojo.engagementId",
                "12345",
                IConfigProperty.PropertyType.STRING,
                null
        );
        DefectDojoUploader extension = new DefectDojoUploader();
        extension.setQueryManager(qm);
        Assert.assertTrue(extension.isEnabled());
        Assert.assertTrue(extension.isProjectConfigured(project));
    }

    @Test
    public void testIntegrationDisabledCases() {
        Project project = qm.createProject("ACME Example", null, "1.0", null, null, null, true, false);
        DefectDojoUploader extension = new DefectDojoUploader();
        extension.setQueryManager(qm);
        Assert.assertFalse(extension.isEnabled());
        Assert.assertFalse(extension.isProjectConfigured(project));
    }

    @Test
    public void testUpload() {
        qm.createConfigProperty(
                DEFECTDOJO_ENABLED.getGroupName(),
                DEFECTDOJO_ENABLED.getPropertyName(),
                "true",
                DEFECTDOJO_ENABLED.getPropertyType(),
                null
        );
        qm.createConfigProperty(
                DEFECTDOJO_URL.getGroupName(),
                DEFECTDOJO_URL.getPropertyName(),
                wireMockRule.baseUrl(),
                DEFECTDOJO_URL.getPropertyType(),
                null
        );
        qm.createConfigProperty(
                DEFECTDOJO_API_KEY.getGroupName(),
                DEFECTDOJO_API_KEY.getPropertyName(),
                "dojoApiKey",
                DEFECTDOJO_API_KEY.getPropertyType(),
                null
        );
        qm.createConfigProperty(
                DEFECTDOJO_REIMPORT_ENABLED.getGroupName(),
                DEFECTDOJO_REIMPORT_ENABLED.getPropertyName(),
                DEFECTDOJO_REIMPORT_ENABLED.getDefaultPropertyValue(),
                DEFECTDOJO_REIMPORT_ENABLED.getPropertyType(),
                null
        );

        stubFor(post(urlPathEqualTo("/api/v2/import-scan/"))
                .willReturn(aResponse()
                        .withStatus(201)));

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

        qm.createProjectProperty(project, "integrations", "defectdojo.engagementId",
                "666", IConfigProperty.PropertyType.STRING, null);

        final var uploader = new DefectDojoUploader();
        uploader.setQueryManager(qm);

        final List<Finding> findings = qm.getFindings(project);
        final InputStream inputStream = uploader.process(project, findings);
        uploader.upload(project, inputStream);

        verify(postRequestedFor(urlPathEqualTo("/api/v2/import-scan/"))
                .withHeader(HttpHeaders.AUTHORIZATION, equalTo("Token dojoApiKey"))
                .withAnyRequestBodyPart(aMultipart()
                        .withName("engagement")
                        .withBody(equalTo("666")))
                .withAnyRequestBodyPart(aMultipart()
                        .withName("scan_type")
                        .withBody(equalTo("Dependency Track Finding Packaging Format (FPF) Export")))
                .withAnyRequestBodyPart(aMultipart()
                        .withName("verified")
                        .withBody(equalTo("true")))
                .withAnyRequestBodyPart(aMultipart()
                        .withName("minimum_severity")
                        .withBody(equalTo("Info")))
                .withAnyRequestBodyPart(aMultipart()
                        .withName("close_old_findings")
                        .withBody(equalTo("true")))
                .withAnyRequestBodyPart(aMultipart()
                        .withName("push_to_jira")
                        .withBody(equalTo("false")))
                .withAnyRequestBodyPart(aMultipart()
                        .withName("scan_date")
                        .withBody(matching("\\d{4}-\\d{2}-\\d{2}")))
                .withAnyRequestBodyPart(aMultipart()
                        .withName("file")
                        .withBody(equalToJson("""
                                {
                                  "version": "1.2",
                                  "meta": {
                                    "application": "Dependency-Track",
                                    "version": "${json-unit.any-string}",
                                    "timestamp": "${json-unit.any-string}"
                                  },
                                  "project": {
                                    "uuid": "${json-unit.any-string}",
                                    "name": "acme-app",
                                    "version": "1.0.0"
                                  },
                                  "findings": [
                                    {
                                      "component": {
                                        "uuid": "${json-unit.any-string}",
                                        "name": "acme-lib",
                                        "version": "1.2.3",
                                        "project": "${json-unit.any-string}"
                                      },
                                      "attribution": {
                                        "analyzerIdentity": "INTERNAL_ANALYZER",
                                        "attributedOn": "${json-unit.any-string}"
                                      },
                                      "vulnerability": {
                                        "uuid": "${json-unit.any-string}",
                                        "vulnId": "INT-123",
                                        "source": "INTERNAL",
                                        "aliases": [],
                                        "severity": "HIGH",
                                        "severityRank": 1
                                      },
                                      "analysis": {
                                        "isSuppressed": false
                                      },
                                      "matrix": "${json-unit.any-string}"
                                    }
                                  ]
                                }
                                """, true, false))));
    }

    @Test
    public void testUploadWithGlobalReimport() {
        qm.createConfigProperty(
                DEFECTDOJO_ENABLED.getGroupName(),
                DEFECTDOJO_ENABLED.getPropertyName(),
                "true",
                DEFECTDOJO_ENABLED.getPropertyType(),
                null
        );
        qm.createConfigProperty(
                DEFECTDOJO_URL.getGroupName(),
                DEFECTDOJO_URL.getPropertyName(),
                wireMockRule.baseUrl(),
                DEFECTDOJO_URL.getPropertyType(),
                null
        );
        qm.createConfigProperty(
                DEFECTDOJO_API_KEY.getGroupName(),
                DEFECTDOJO_API_KEY.getPropertyName(),
                "dojoApiKey",
                DEFECTDOJO_API_KEY.getPropertyType(),
                null
        );
        qm.createConfigProperty(
                DEFECTDOJO_REIMPORT_ENABLED.getGroupName(),
                DEFECTDOJO_REIMPORT_ENABLED.getPropertyName(),
                "true",
                DEFECTDOJO_REIMPORT_ENABLED.getPropertyType(),
                null
        );

        stubFor(get(urlPathEqualTo("/api/v2/tests/"))
                .withQueryParam("engagement", equalTo("666"))
                .withQueryParam("limit", equalTo("100"))
                .withHeader(HttpHeaders.AUTHORIZATION, equalTo("Token dojoApiKey"))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_JSON)
                        .withBody("""
                                {
                                  "count": 3,
                                  "next": "%s/api/v2/tests/?engagement=666&limit=100&offset=100",
                                  "previous": null,
                                  "results": [
                                    {
                                      "id": 1,
                                      "tags": [],
                                      "test_type_name": "CycloneDX Scan",
                                      "finding_groups": [],
                                      "scan_type": "CycloneDX Scan",
                                      "title": null,
                                      "description": null,
                                      "target_start": "2023-04-29T00:00:00Z",
                                      "target_end": "2023-04-29T21:36:22.798765Z",
                                      "estimated_time": null,
                                      "actual_time": null,
                                      "percent_complete": 100,
                                      "updated": "2023-04-29T21:36:22.858597Z",
                                      "created": "2023-04-29T21:36:22.802993Z",
                                      "version": "",
                                      "build_id": "",
                                      "commit_hash": "",
                                      "branch_tag": "",
                                      "engagement": 666,
                                      "lead": 1,
                                      "test_type": 54,
                                      "environment": 7,
                                      "api_scan_configuration": null,
                                      "notes": [],
                                      "files": []
                                    },
                                    {
                                      "id": 2,
                                      "tags": [],
                                      "test_type_name": "API Test",
                                      "finding_groups": [],
                                      "title": null,
                                      "description": null,
                                      "target_start": "2023-04-29T00:00:00Z",
                                      "target_end": "2023-04-29T21:36:22.798765Z",
                                      "estimated_time": null,
                                      "actual_time": null,
                                      "percent_complete": 100,
                                      "updated": "2023-04-29T21:36:22.858597Z",
                                      "created": "2023-04-29T21:36:22.802993Z",
                                      "version": "",
                                      "build_id": "",
                                      "commit_hash": "",
                                      "branch_tag": "",
                                      "engagement": 666,
                                      "lead": 1,
                                      "test_type": 1,
                                      "environment": 7,
                                      "api_scan_configuration": null,
                                      "notes": [],
                                      "files": []
                                    }
                                  ],
                                  "prefetch": {}
                                }
                                """.formatted(wireMockRule.baseUrl()))));

        stubFor(get(urlPathEqualTo("/api/v2/tests/"))
                .withQueryParam("engagement", equalTo("666"))
                .withQueryParam("limit", equalTo("100"))
                .withQueryParam("offset", equalTo("100"))
                .withHeader(HttpHeaders.AUTHORIZATION, equalTo("Token dojoApiKey"))
                .willReturn(aResponse()
                        .withHeader(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_JSON)
                        .withBody("""
                                {
                                   "count": 3,
                                   "next": null,
                                   "previous": "%s/api/v2/tests/?engagement=666&limit=100",
                                   "results": [
                                     {
                                       "id": 3,
                                       "tags": [],
                                       "test_type_name": "Dependency Track Finding Packaging Format (FPF) Export",
                                       "finding_groups": [],
                                       "scan_type": "Dependency Track Finding Packaging Format (FPF) Export",
                                       "title": null,
                                       "description": null,
                                       "target_start": "2023-04-29T00:00:00Z",
                                       "target_end": "2023-04-29T21:39:21.513481Z",
                                       "estimated_time": null,
                                       "actual_time": null,
                                       "percent_complete": 100,
                                       "updated": "2023-04-29T21:39:21.617857Z",
                                       "created": "2023-04-29T21:39:21.516206Z",
                                       "version": "",
                                       "build_id": "",
                                       "commit_hash": "",
                                       "branch_tag": "",
                                       "engagement": 666,
                                       "lead": 1,
                                       "test_type": 63,
                                       "environment": 7,
                                       "api_scan_configuration": null,
                                       "notes": [],
                                       "files": []
                                     }
                                   ],
                                   "prefetch": {}
                                 }
                                """.formatted(wireMockRule.baseUrl()))));

        stubFor(post(urlPathEqualTo("/api/v2/reimport-scan/"))
                .willReturn(aResponse()
                        .withStatus(201)));

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

        qm.createProjectProperty(project, "integrations", "defectdojo.engagementId",
                "666", IConfigProperty.PropertyType.STRING, null);

        final var uploader = new DefectDojoUploader();
        uploader.setQueryManager(qm);

        final List<Finding> findings = qm.getFindings(project);
        final InputStream inputStream = uploader.process(project, findings);
        uploader.upload(project, inputStream);

        verify(2, getRequestedFor(urlPathEqualTo("/api/v2/tests/")));

        verify(postRequestedFor(urlPathEqualTo("/api/v2/reimport-scan/"))
                .withHeader(HttpHeaders.AUTHORIZATION, equalTo("Token dojoApiKey"))
                .withAnyRequestBodyPart(aMultipart()
                        .withName("engagement")
                        .withBody(equalTo("666")))
                .withAnyRequestBodyPart(aMultipart()
                        .withName("test")
                        .withBody(equalTo("3")))
                .withAnyRequestBodyPart(aMultipart()
                        .withName("scan_type")
                        .withBody(equalTo("Dependency Track Finding Packaging Format (FPF) Export")))
                .withAnyRequestBodyPart(aMultipart()
                        .withName("verified")
                        .withBody(equalTo("true")))
                .withAnyRequestBodyPart(aMultipart()
                        .withName("minimum_severity")
                        .withBody(equalTo("Info")))
                .withAnyRequestBodyPart(aMultipart()
                        .withName("close_old_findings")
                        .withBody(equalTo("true")))
                .withAnyRequestBodyPart(aMultipart()
                        .withName("push_to_jira")
                        .withBody(equalTo("false")))
                .withAnyRequestBodyPart(aMultipart()
                        .withName("scan_date")
                        .withBody(matching("\\d{4}-\\d{2}-\\d{2}")))
                .withAnyRequestBodyPart(aMultipart()
                        .withName("file")
                        .withBody(equalToJson("""
                                {
                                  "version": "1.2",
                                  "meta": {
                                    "application": "Dependency-Track",
                                    "version": "${json-unit.any-string}",
                                    "timestamp": "${json-unit.any-string}"
                                  },
                                  "project": {
                                    "uuid": "${json-unit.any-string}",
                                    "name": "acme-app",
                                    "version": "1.0.0"
                                  },
                                  "findings": [
                                    {
                                      "component": {
                                        "uuid": "${json-unit.any-string}",
                                        "name": "acme-lib",
                                        "version": "1.2.3",
                                        "project": "${json-unit.any-string}"
                                      },
                                      "attribution": {
                                        "analyzerIdentity": "INTERNAL_ANALYZER",
                                        "attributedOn": "${json-unit.any-string}"
                                      },
                                      "vulnerability": {
                                        "uuid": "${json-unit.any-string}",
                                        "vulnId": "INT-123",
                                        "source": "INTERNAL",
                                        "aliases": [],
                                        "severity": "HIGH",
                                        "severityRank": 1
                                      },
                                      "analysis": {
                                        "isSuppressed": false
                                      },
                                      "matrix": "${json-unit.any-string}"
                                    }
                                  ]
                                }
                                """, true, false))));
    }

    @Test
    public void testUploadWithProjectLevelReimport() {
        qm.createConfigProperty(
                DEFECTDOJO_ENABLED.getGroupName(),
                DEFECTDOJO_ENABLED.getPropertyName(),
                "true",
                DEFECTDOJO_ENABLED.getPropertyType(),
                null
        );
        qm.createConfigProperty(
                DEFECTDOJO_URL.getGroupName(),
                DEFECTDOJO_URL.getPropertyName(),
                wireMockRule.baseUrl(),
                DEFECTDOJO_URL.getPropertyType(),
                null
        );
        qm.createConfigProperty(
                DEFECTDOJO_API_KEY.getGroupName(),
                DEFECTDOJO_API_KEY.getPropertyName(),
                "dojoApiKey",
                DEFECTDOJO_API_KEY.getPropertyType(),
                null
        );
        qm.createConfigProperty(
                DEFECTDOJO_REIMPORT_ENABLED.getGroupName(),
                DEFECTDOJO_REIMPORT_ENABLED.getPropertyName(),
                "false",
                DEFECTDOJO_REIMPORT_ENABLED.getPropertyType(),
                null
        );

        stubFor(get(urlPathEqualTo("/api/v2/tests/"))
                .withQueryParam("engagement", equalTo("666"))
                .withQueryParam("limit", equalTo("100"))
                .withHeader(HttpHeaders.AUTHORIZATION, equalTo("Token dojoApiKey"))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_JSON)
                        .withBody("""
                                {
                                   "count": 1,
                                   "next": null,
                                   "previous": null,
                                   "results": [
                                     {
                                       "id": 1,
                                       "tags": [],
                                       "test_type_name": "Dependency Track Finding Packaging Format (FPF) Export",
                                       "finding_groups": [],
                                       "scan_type": "Dependency Track Finding Packaging Format (FPF) Export",
                                       "title": null,
                                       "description": null,
                                       "target_start": "2023-04-29T00:00:00Z",
                                       "target_end": "2023-04-29T21:39:21.513481Z",
                                       "estimated_time": null,
                                       "actual_time": null,
                                       "percent_complete": 100,
                                       "updated": "2023-04-29T21:39:21.617857Z",
                                       "created": "2023-04-29T21:39:21.516206Z",
                                       "version": "",
                                       "build_id": "",
                                       "commit_hash": "",
                                       "branch_tag": "",
                                       "engagement": 666,
                                       "lead": 1,
                                       "test_type": 63,
                                       "environment": 7,
                                       "api_scan_configuration": null,
                                       "notes": [],
                                       "files": []
                                     }
                                   ],
                                   "prefetch": {}
                                 }
                                """)));

        stubFor(post(urlPathEqualTo("/api/v2/reimport-scan/"))
                .willReturn(aResponse()
                        .withStatus(201)));

        final var project = new Project();
        project.setName("acme-app");
        project.setVersion("1.0.0");
        qm.persist(project);

        final var component = new Component();
        component.setProject(project);
        component.setName("acme-lib");
        component.setVersion("1.2.3");
        qm.persist(component);

        qm.createProjectProperty(project, "integrations", "defectdojo.engagementId",
                "666", IConfigProperty.PropertyType.STRING, null);
        qm.createProjectProperty(project, "integrations", "defectdojo.reimport",
                "true", IConfigProperty.PropertyType.BOOLEAN, null);

        final var uploader = new DefectDojoUploader();
        uploader.setQueryManager(qm);

        final List<Finding> findings = qm.getFindings(project);
        final InputStream inputStream = uploader.process(project, findings);
        uploader.upload(project, inputStream);

        verify(1, getRequestedFor(urlPathEqualTo("/api/v2/tests/")));

        verify(postRequestedFor(urlPathEqualTo("/api/v2/reimport-scan/"))
                .withHeader(HttpHeaders.AUTHORIZATION, equalTo("Token dojoApiKey"))
                .withAnyRequestBodyPart(aMultipart()
                        .withName("file")
                        .withBody(equalToJson("""
                                {
                                  "version": "1.2",
                                  "meta": {
                                    "application": "Dependency-Track",
                                    "version": "${json-unit.any-string}",
                                    "timestamp": "${json-unit.any-string}"
                                  },
                                  "project": {
                                    "uuid": "${json-unit.any-string}",
                                    "name": "acme-app",
                                    "version": "1.0.0"
                                  },
                                  "findings": []
                                }
                                """, true, false))));
    }

    @Test
    public void testUploadWithReimportAndNoExistingTest() {
        qm.createConfigProperty(
                DEFECTDOJO_ENABLED.getGroupName(),
                DEFECTDOJO_ENABLED.getPropertyName(),
                "true",
                DEFECTDOJO_ENABLED.getPropertyType(),
                null
        );
        qm.createConfigProperty(
                DEFECTDOJO_URL.getGroupName(),
                DEFECTDOJO_URL.getPropertyName(),
                wireMockRule.baseUrl(),
                DEFECTDOJO_URL.getPropertyType(),
                null
        );
        qm.createConfigProperty(
                DEFECTDOJO_API_KEY.getGroupName(),
                DEFECTDOJO_API_KEY.getPropertyName(),
                "dojoApiKey",
                DEFECTDOJO_API_KEY.getPropertyType(),
                null
        );
        qm.createConfigProperty(
                DEFECTDOJO_REIMPORT_ENABLED.getGroupName(),
                DEFECTDOJO_REIMPORT_ENABLED.getPropertyName(),
                "true",
                DEFECTDOJO_REIMPORT_ENABLED.getPropertyType(),
                null
        );

        stubFor(get(urlPathEqualTo("/api/v2/tests/"))
                .withQueryParam("engagement", equalTo("666"))
                .withQueryParam("limit", equalTo("100"))
                .withHeader(HttpHeaders.AUTHORIZATION, equalTo("Token dojoApiKey"))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_JSON)
                        .withBody("""
                                {
                                   "count": 0,
                                   "next": null,
                                   "previous": null,
                                   "results": [],
                                   "prefetch": {}
                                 }
                                """)));

        stubFor(post(urlPathEqualTo("/api/v2/import-scan/"))
                .willReturn(aResponse()
                        .withStatus(201)));

        final var project = new Project();
        project.setName("acme-app");
        project.setVersion("1.0.0");
        qm.persist(project);

        final var component = new Component();
        component.setProject(project);
        component.setName("acme-lib");
        component.setVersion("1.2.3");
        qm.persist(component);

        qm.createProjectProperty(project, "integrations", "defectdojo.engagementId",
                "666", IConfigProperty.PropertyType.STRING, null);

        final var uploader = new DefectDojoUploader();
        uploader.setQueryManager(qm);

        final List<Finding> findings = qm.getFindings(project);
        final InputStream inputStream = uploader.process(project, findings);
        uploader.upload(project, inputStream);

        verify(1, getRequestedFor(urlPathEqualTo("/api/v2/tests/")));

        verify(postRequestedFor(urlPathEqualTo("/api/v2/import-scan/"))
                .withHeader(HttpHeaders.AUTHORIZATION, equalTo("Token dojoApiKey"))
                .withAnyRequestBodyPart(aMultipart()
                        .withName("file")
                        .withBody(equalToJson("""
                                {
                                  "version": "1.2",
                                  "meta": {
                                    "application": "Dependency-Track",
                                    "version": "${json-unit.any-string}",
                                    "timestamp": "${json-unit.any-string}"
                                  },
                                  "project": {
                                    "uuid": "${json-unit.any-string}",
                                    "name": "acme-app",
                                    "version": "1.0.0"
                                  },
                                  "findings": []
                                }
                                """, true, false))));
    }

    /**
     * Un-ignore this test to test the integration against a local DefectDojo deployment.
     * <p>
     * Consult the <a href="https://defectdojo.github.io/django-DefectDojo/getting_started/installation/">documentation</a>
     * for instructions on how to set it up.
     */
    @Test
    @Ignore
    public void testUploadIntegration() {
        final var baseUrl = "http://localhost:8080";
        final var apiKey = "";
        final var engagementId = "";
        final var globalReimport = false;
        final var projectReimport = false;

        qm.createConfigProperty(
                DEFECTDOJO_URL.getGroupName(),
                DEFECTDOJO_URL.getPropertyName(),
                baseUrl,
                DEFECTDOJO_URL.getPropertyType(),
                null
        );
        qm.createConfigProperty(
                DEFECTDOJO_API_KEY.getGroupName(),
                DEFECTDOJO_API_KEY.getPropertyName(),
                apiKey,
                DEFECTDOJO_API_KEY.getPropertyType(),
                null
        );
        qm.createConfigProperty(
                DEFECTDOJO_REIMPORT_ENABLED.getGroupName(),
                DEFECTDOJO_REIMPORT_ENABLED.getPropertyName(),
                Boolean.toString(globalReimport),
                DEFECTDOJO_REIMPORT_ENABLED.getPropertyType(),
                null
        );

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

        qm.createProjectProperty(project, "integrations", "defectdojo.engagementId",
                engagementId, IConfigProperty.PropertyType.STRING, null);
        qm.createProjectProperty(project, "integrations", "defectdojo.reimport",
                Boolean.toString(projectReimport), IConfigProperty.PropertyType.BOOLEAN, null);

        final var uploader = new DefectDojoUploader();
        uploader.setQueryManager(qm);

        final List<Finding> findings = qm.getFindings(project);
        final InputStream inputStream = uploader.process(project, findings);
        uploader.upload(project, inputStream);
    }

}
