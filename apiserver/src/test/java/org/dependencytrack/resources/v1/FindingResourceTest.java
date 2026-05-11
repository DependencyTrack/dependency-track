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

import alpine.config.AlpineConfigKeys;
import alpine.model.About;
import alpine.model.ApiKey;
import alpine.model.ConfigProperty;
import alpine.model.Team;
import alpine.server.filters.ApiFilter;
import alpine.server.filters.AuthenticationFeature;
import alpine.server.filters.AuthorizationFeature;
import jakarta.json.JsonArray;
import jakarta.json.JsonObject;
import jakarta.ws.rs.client.Entity;
import jakarta.ws.rs.core.HttpHeaders;
import jakarta.ws.rs.core.Response;
import org.dependencytrack.JerseyTestExtension;
import org.dependencytrack.ResourceTest;
import org.dependencytrack.auth.Permissions;
import org.dependencytrack.dex.engine.api.DexEngine;
import org.dependencytrack.dex.engine.api.request.CreateWorkflowRunRequest;
import org.dependencytrack.model.Analysis;
import org.dependencytrack.model.AnalysisState;
import org.dependencytrack.model.Component;
import org.dependencytrack.model.ComponentOccurrence;
import org.dependencytrack.model.ConfigPropertyConstants;
import org.dependencytrack.model.Epss;
import org.dependencytrack.model.PackageMetadata;
import org.dependencytrack.model.Project;
import org.dependencytrack.model.Severity;
import org.dependencytrack.model.Vulnerability;
import org.dependencytrack.persistence.command.MakeAnalysisCommand;
import org.dependencytrack.persistence.jdbi.PackageMetadataDao;
import org.eclipse.microprofile.config.ConfigProvider;
import org.glassfish.hk2.utilities.binding.AbstractBinder;
import org.glassfish.jersey.server.ResourceConfig;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.mockito.ArgumentCaptor;
import org.mockito.ArgumentMatchers;
import org.mockito.Mockito;

import java.math.BigDecimal;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.Date;
import java.util.List;
import java.util.UUID;
import java.util.function.Supplier;
import java.util.stream.Stream;

import static net.javacrumbs.jsonunit.assertj.JsonAssertions.assertThatJson;
import static org.assertj.core.api.Assertions.assertThat;
import static org.dependencytrack.persistence.jdbi.JdbiFactory.useJdbiHandle;
import static org.dependencytrack.resources.v1.FindingResource.MEDIA_TYPE_SARIF_JSON;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static wiremock.org.apache.commons.io.IOUtils.resourceToString;

public class FindingResourceTest extends ResourceTest {

    private static final DexEngine DEX_ENGINE_MOCK = mock(DexEngine.class);

    @RegisterExtension
    static JerseyTestExtension jersey = new JerseyTestExtension(
            new ResourceConfig(FindingResource.class)
                    .register(ApiFilter.class)
                    .register(AuthenticationFeature.class)
                    .register(AuthorizationFeature.class)
                    .register(new AbstractBinder() {
                        @Override
                        protected void configure() {
                            bind(DEX_ENGINE_MOCK).to(DexEngine.class);
                        }
                    }));

    @AfterEach
    void afterEach() {
        Mockito.reset(DEX_ENGINE_MOCK);
    }

    @Test
    public void getFindingsByProjectTest() {
        initializeWithPermissions(Permissions.VIEW_VULNERABILITY);

        Project p1 = qm.createProject("Acme Example", null, "1.0", null, null, null, null, false);
        Project p2 = qm.createProject("Acme Example", null, "2.0", null, null, null, null, false);
        Component c1 = createComponent(p1, "Component A", "1.0");
        Component c2 = createComponent(p1, "Component B", "1.0");
        createComponent(p1, "Component C", "1.0");
        createComponent(p2, "Component D", "1.0");
        Component c5 = createComponent(p2, "Component E", "1.0");
        createComponent(p2, "Component F", "1.0");
        Vulnerability v1 = createVulnerability("Vuln-1", Severity.CRITICAL);
        Vulnerability v2 = createVulnerability("Vuln-2", Severity.HIGH);
        Vulnerability v3 = createVulnerability("Vuln-3", Severity.MEDIUM);
        Vulnerability v4 = createVulnerability("Vuln-4", Severity.LOW);
        qm.addVulnerability(v1, c1, "none");
        qm.addVulnerability(v2, c1, "none");
        qm.addVulnerability(v3, c2, "none");
        qm.addVulnerability(v4, c5, "none");
        Response response = jersey.target(V1_FINDING + "/project/" + p1.getUuid().toString()).request()
                .header(X_API_KEY, apiKey)
                .get(Response.class);
        assertEquals(200, response.getStatus(), 0);
        assertEquals(String.valueOf(3), response.getHeaderString(TOTAL_COUNT_HEADER));
        JsonArray json = parseJsonArray(response);
        assertNotNull(json);
        assertThat(json).satisfiesExactlyInAnyOrder(
                jsonValue -> {
                    final JsonObject finding = jsonValue.asJsonObject();
                    assertEquals("Component A", finding.getJsonObject("component").getString("name"));
                    assertEquals("1.0", finding.getJsonObject("component").getString("version"));
                    assertEquals("Vuln-1", finding.getJsonObject("vulnerability").getString("vulnId"));
                    assertEquals(Severity.CRITICAL.name(), finding.getJsonObject("vulnerability").getString("severity"));
                    assertEquals(2, finding.getJsonObject("vulnerability").getJsonArray("cwes").size());
                    assertEquals(80, finding.getJsonObject("vulnerability").getJsonArray("cwes").getJsonObject(0).getInt("cweId"));
                    assertEquals(666, finding.getJsonObject("vulnerability").getJsonArray("cwes").getJsonObject(1).getInt("cweId"));
                    assertFalse(finding.getJsonObject("analysis").getBoolean("isSuppressed"));
                    assertEquals(p1.getUuid().toString() + ":" + c1.getUuid().toString() + ":" + v1.getUuid().toString(), finding.getString("matrix"));
                },
                jsonValue -> {
                    final JsonObject finding = jsonValue.asJsonObject();
                    assertEquals("Component A", finding.getJsonObject("component").getString("name"));
                    assertEquals("1.0", finding.getJsonObject("component").getString("version"));
                    assertEquals("Vuln-2", finding.getJsonObject("vulnerability").getString("vulnId"));
                    assertEquals(Severity.HIGH.name(), finding.getJsonObject("vulnerability").getString("severity"));
                    assertEquals(2, finding.getJsonObject("vulnerability").getJsonArray("cwes").size());
                    assertEquals(80, finding.getJsonObject("vulnerability").getJsonArray("cwes").getJsonObject(0).getInt("cweId"));
                    assertEquals(666, finding.getJsonObject("vulnerability").getJsonArray("cwes").getJsonObject(1).getInt("cweId"));
                    assertFalse(finding.getJsonObject("analysis").getBoolean("isSuppressed"));
                    assertEquals(p1.getUuid().toString() + ":" + c1.getUuid().toString() + ":" + v2.getUuid().toString(), finding.getString("matrix"));
                },
                jsonValue -> {
                    final JsonObject finding = jsonValue.asJsonObject();
                    assertEquals("Component B", finding.getJsonObject("component").getString("name"));
                    assertEquals("1.0", finding.getJsonObject("component").getString("version"));
                    assertEquals("Vuln-3", finding.getJsonObject("vulnerability").getString("vulnId"));
                    assertEquals(Severity.MEDIUM.name(), finding.getJsonObject("vulnerability").getString("severity"));
                    assertEquals(2, finding.getJsonObject("vulnerability").getJsonArray("cwes").size());
                    assertEquals(80, finding.getJsonObject("vulnerability").getJsonArray("cwes").getJsonObject(0).getInt("cweId"));
                    assertEquals(666, finding.getJsonObject("vulnerability").getJsonArray("cwes").getJsonObject(1).getInt("cweId"));
                    assertFalse(finding.getJsonObject("analysis").getBoolean("isSuppressed"));
                    assertEquals(p1.getUuid().toString() + ":" + c2.getUuid().toString() + ":" + v3.getUuid().toString(), finding.getString("matrix"));
                }
        );
    }

    @Test
    public void getFindingsByProjectEmptyTest() throws Exception {
        initializeWithPermissions(Permissions.VIEW_VULNERABILITY);

        useJdbiHandle(handle -> new PackageMetadataDao(handle).upsertAll(List.of(
                new PackageMetadata(
                        new com.github.packageurl.PackageURL("pkg:maven/com.acme/acme-lib"),
                        "1.2.3",
                        null,
                        Instant.now(),
                        null,
                        null))));

        final var project = new Project();
        project.setName("acme-app");
        qm.persist(project);

        final Response response = jersey.target(V1_FINDING + "/project/" + project.getUuid())
                .request()
                .header(X_API_KEY, apiKey)
                .get();
        assertThat(response.getStatus()).isEqualTo(200);
        assertThat(response.getHeaderString(TOTAL_COUNT_HEADER)).isEqualTo("0");
        assertThat(getPlainTextBody(response)).isEqualTo("[]");
    }

    @Test
    public void getFindingsByProjectInvalidTest() {
        initializeWithPermissions(Permissions.VIEW_VULNERABILITY);

        Response response = jersey.target(V1_FINDING + "/project/" + UUID.randomUUID()).request()
                .header(X_API_KEY, apiKey)
                .get(Response.class);
        assertEquals(404, response.getStatus(), 0);
        assertNull(response.getHeaderString(TOTAL_COUNT_HEADER));
        String body = getPlainTextBody(response);
        assertEquals("The project could not be found.", body);
    }

    @Test
    public void getFindingsByProjectAclTest() {
        initializeWithPermissions(Permissions.VIEW_VULNERABILITY);
        enablePortfolioAccessControl();

        final var project = new Project();
        project.setName("acme-app");
        qm.persist(project);

        final Supplier<Response> responseSupplier = () -> jersey
                .target(V1_FINDING + "/project/" + project.getUuid()).request()
                .header(X_API_KEY, apiKey)
                .get();

        Response response = responseSupplier.get();
        assertThat(response.getStatus()).isEqualTo(403);
        assertThatJson(getPlainTextBody(response)).isEqualTo(/* language=JSON */ """
                {
                  "status": 403,
                  "title": "Project access denied",
                  "detail": "Access to the requested project is forbidden"
                }
                """);

        project.addAccessTeam(super.team);

        response = responseSupplier.get();
        assertThat(response.getStatus()).isEqualTo(200);
    }

    @Test
    public void getFindingsByProjectWithAnalysisTest() {
        initializeWithPermissions(Permissions.VIEW_VULNERABILITY);

        Project p1 = qm.createProject("Acme Example 1", null, "1.0", null, null, null, null, false);

        Component c1 = createComponent(p1, "Component A", "1.0"); // with analysis
        Component c2 = createComponent(p1, "Component B", "1.0"); // without analysis

        Vulnerability v1 = createVulnerability("Vuln-1", Severity.CRITICAL);
        Vulnerability v2 = createVulnerability("Vuln-2", Severity.CRITICAL);

        qm.addVulnerability(v1, c1, "none");
        qm.addVulnerability(v2, c2, "none");

        qm.makeAnalysis(
                new MakeAnalysisCommand(c1, v1)
                        .withState(AnalysisState.FALSE_POSITIVE));

        // Should include all findings with or without analysis.
        Response response = jersey.target(V1_FINDING + "/project/" + p1.getUuid().toString()).request()
                .header(X_API_KEY, apiKey)
                .get(Response.class);
        assertThat(response.getStatus()).isEqualTo(200);
        assertThat(response.getHeaderString(TOTAL_COUNT_HEADER)).isEqualTo("2");

        // Should only include project with existing analysis.
        response = jersey.target(V1_FINDING + "/project/" + p1.getUuid().toString())
                .queryParam("hasAnalysis", true)
                .request()
                .header(X_API_KEY, apiKey)
                .get(Response.class);
        assertThat(response.getStatus()).isEqualTo(200);
        assertThat(response.getHeaderString(TOTAL_COUNT_HEADER)).isEqualTo("1");
        JsonArray json = parseJsonArray(response);
        assertNotNull(json);
        assertThat(json).satisfiesExactly(
                jsonValue -> {
                    final JsonObject finding = jsonValue.asJsonObject();
                    assertEquals("Component A", finding.getJsonObject("component").getString("name"));
                    assertEquals("FALSE_POSITIVE", finding.getJsonObject("analysis").getString("state"));
                }
        );

        // Should only include project without existing analysis.
        response = jersey.target(V1_FINDING + "/project/" + p1.getUuid().toString())
                .queryParam("hasAnalysis", false)
                .request()
                .header(X_API_KEY, apiKey)
                .get(Response.class);
        assertThat(response.getStatus()).isEqualTo(200);
        assertThat(response.getHeaderString(TOTAL_COUNT_HEADER)).isEqualTo("1");
        json = parseJsonArray(response);
        assertNotNull(json);
        assertThat(json).satisfiesExactly(
                jsonValue -> {
                    final JsonObject finding = jsonValue.asJsonObject();
                    assertEquals("Component B", finding.getJsonObject("component").getString("name"));
                }
        );
    }

    @Test
    public void exportFindingsByProjectTest() {
        initializeWithPermissions(Permissions.VIEW_VULNERABILITY);

        Project p1 = qm.createProject("Acme Example", null, "1.0", null, null, null, null, false);
        Project p2 = qm.createProject("Acme Example", null, "2.0", null, null, null, null, false);
        Component c1 = createComponent(p1, "Component A", "1.0");
        Component c2 = createComponent(p1, "Component B", "1.0");
        createComponent(p1, "Component C", "1.0");
        createComponent(p2, "Component D", "1.0");
        Component c5 = createComponent(p2, "Component E", "1.0");
        createComponent(p2, "Component F", "1.0");
        Vulnerability v1 = createVulnerability("Vuln-1", Severity.CRITICAL);
        Vulnerability v2 = createVulnerability("Vuln-2", Severity.HIGH);
        Vulnerability v3 = createVulnerability("Vuln-3", Severity.MEDIUM);
        Vulnerability v4 = createVulnerability("Vuln-4", Severity.LOW);
        qm.addVulnerability(v1, c1, "none");
        qm.addVulnerability(v2, c1, "none");
        qm.addVulnerability(v3, c2, "none");
        qm.addVulnerability(v4, c5, "none");
        Response response = jersey.target(V1_FINDING + "/project/" + p1.getUuid().toString() + "/export").request()
                .header(X_API_KEY, apiKey)
                .get(Response.class);
        assertEquals(200, response.getStatus(), 0);
        assertNull(response.getHeaderString(TOTAL_COUNT_HEADER));
        JsonObject json = parseJsonObject(response);
        assertNotNull(json);
        assertEquals(ConfigProvider.getConfig().getValue(AlpineConfigKeys.BUILD_INFO_APPLICATION_NAME, String.class), json.getJsonObject("meta").getString("application"));
        assertEquals(ConfigProvider.getConfig().getValue(AlpineConfigKeys.BUILD_INFO_APPLICATION_VERSION, String.class), json.getJsonObject("meta").getString("version"));
        assertNotNull(json.getJsonObject("meta").getString("timestamp"));
        assertEquals("Acme Example", json.getJsonObject("project").getString("name"));
        assertEquals("1.0", json.getJsonObject("project").getString("version"));
        assertEquals(p1.getUuid().toString(), json.getJsonObject("project").getString("uuid"));
        assertEquals("1.3", json.getString("version")); // FPF version
        JsonArray findings = json.getJsonArray("findings");
        assertThat(findings).satisfiesExactlyInAnyOrder(
                jsonValue -> {
                    final JsonObject finding = jsonValue.asJsonObject();
                    assertEquals("Component A", finding.getJsonObject("component").getString("name"));
                    assertEquals("1.0", finding.getJsonObject("component").getString("version"));
                    assertEquals("Vuln-1", finding.getJsonObject("vulnerability").getString("vulnId"));
                    assertEquals(Severity.CRITICAL.name(), finding.getJsonObject("vulnerability").getString("severity"));
                    assertEquals(2, finding.getJsonObject("vulnerability").getJsonArray("cwes").size());
                    assertEquals(80, finding.getJsonObject("vulnerability").getJsonArray("cwes").getJsonObject(0).getInt("cweId"));
                    assertEquals(666, finding.getJsonObject("vulnerability").getJsonArray("cwes").getJsonObject(1).getInt("cweId"));
                    assertFalse(finding.getJsonObject("analysis").getBoolean("isSuppressed"));
                    assertEquals(p1.getUuid().toString() + ":" + c1.getUuid().toString() + ":" + v1.getUuid().toString(), finding.getString("matrix"));
                },
                jsonValue -> {
                    final JsonObject finding = jsonValue.asJsonObject();
                    assertEquals("Component A", finding.getJsonObject("component").getString("name"));
                    assertEquals("1.0", finding.getJsonObject("component").getString("version"));
                    assertEquals("Vuln-2", finding.getJsonObject("vulnerability").getString("vulnId"));
                    assertEquals(Severity.HIGH.name(), finding.getJsonObject("vulnerability").getString("severity"));
                    assertEquals(2, finding.getJsonObject("vulnerability").getJsonArray("cwes").size());
                    assertEquals(80, finding.getJsonObject("vulnerability").getJsonArray("cwes").getJsonObject(0).getInt("cweId"));
                    assertEquals(666, finding.getJsonObject("vulnerability").getJsonArray("cwes").getJsonObject(1).getInt("cweId"));
                    assertFalse(finding.getJsonObject("analysis").getBoolean("isSuppressed"));
                    assertEquals(p1.getUuid().toString() + ":" + c1.getUuid().toString() + ":" + v2.getUuid().toString(), finding.getString("matrix"));
                },
                jsonValue -> {
                    final JsonObject finding = jsonValue.asJsonObject();
                    assertEquals("Component B", finding.getJsonObject("component").getString("name"));
                    assertEquals("1.0", finding.getJsonObject("component").getString("version"));
                    assertEquals("Vuln-3", finding.getJsonObject("vulnerability").getString("vulnId"));
                    assertEquals(Severity.MEDIUM.name(), finding.getJsonObject("vulnerability").getString("severity"));
                    assertEquals(2, findings.getJsonObject(1).getJsonObject("vulnerability").getJsonArray("cwes").size());
                    assertEquals(80, findings.getJsonObject(1).getJsonObject("vulnerability").getJsonArray("cwes").getJsonObject(0).getInt("cweId"));
                    assertEquals(666, findings.getJsonObject(1).getJsonObject("vulnerability").getJsonArray("cwes").getJsonObject(1).getInt("cweId"));
                    assertFalse(findings.getJsonObject(0).getJsonObject("analysis").getBoolean("isSuppressed"));
                    assertEquals(p1.getUuid().toString() + ":" + c2.getUuid().toString() + ":" + v3.getUuid().toString(), finding.getString("matrix"));
                }
        );
    }

    @Test
    public void exportFindingsByProjectInvalidTest() {
        initializeWithPermissions(Permissions.VIEW_VULNERABILITY);

        Response response = jersey.target(V1_FINDING + "/project/" + UUID.randomUUID() + "/export").request()
                .header(X_API_KEY, apiKey)
                .get(Response.class);
        assertEquals(404, response.getStatus(), 0);
        assertNull(response.getHeaderString(TOTAL_COUNT_HEADER));
        String body = getPlainTextBody(response);
        assertEquals("The project could not be found.", body);
    }

    @Test
    public void exportFindingsByProjectAclTest() {
        initializeWithPermissions(Permissions.VIEW_VULNERABILITY);
        enablePortfolioAccessControl();

        final var project = new Project();
        project.setName("acme-app");
        qm.persist(project);

        final Supplier<Response> responseSupplier = () -> jersey
                .target(V1_FINDING + "/project/" + project.getUuid() + "/export").request()
                .header(X_API_KEY, apiKey)
                .get();

        Response response = responseSupplier.get();
        assertThat(response.getStatus()).isEqualTo(403);
        assertThatJson(getPlainTextBody(response)).isEqualTo(/* language=JSON */ """
                {
                  "status": 403,
                  "title": "Project access denied",
                  "detail": "Access to the requested project is forbidden"
                }
                """);

        project.addAccessTeam(super.team);

        response = responseSupplier.get();
        assertThat(response.getStatus()).isEqualTo(200);
    }

    @Test
    public void getFindingsByProjectWithComponentLatestVersionTest() throws Exception {
        initializeWithPermissions(Permissions.VIEW_VULNERABILITY);

        Project p1 = qm.createProject("Acme Example", null, "1.0", null, null, null, null, false);
        Project p2 = qm.createProject("Acme Example", null, "2.0", null, null, null, null, false);
        Component c1 = createComponent(p1, "Component A", "1.0");
        c1.setPurl("pkg:/maven/org.acme/component-a@1.0.0");

        Component c2 = createComponent(p1, "Component B", "1.0");
        c2.setPurl("pkg:/maven/org.acme/component-b@1.0.0");

        createComponent(p1, "Component C", "1.0");
        createComponent(p2, "Component D", "1.0");

        Component c5 = createComponent(p2, "Component E", "1.0");
        c5.setPurl("pkg:/maven/org.acme/component-e@1.0.0");

        useJdbiHandle(handle -> new PackageMetadataDao(handle).upsertAll(List.of(
                new PackageMetadata(
                        new com.github.packageurl.PackageURL("pkg:maven/org.acme/component-a"),
                        "2.0.0",
                        Instant.now(),
                        Instant.now(),
                        null,
                        null),
                new PackageMetadata(
                        new com.github.packageurl.PackageURL("pkg:maven/org.acme/component-b"),
                        "3.0.0",
                        Instant.now(),
                        Instant.now(),
                        null,
                        null),
                new PackageMetadata(
                        new com.github.packageurl.PackageURL("pkg:maven/org.acme/component-e"),
                        "4.0.0",
                        Instant.now(),
                        Instant.now(),
                        null,
                        null))));

        createComponent(p2, "Component F", "1.0");
        Vulnerability v1 = createVulnerability("Vuln-1", Severity.CRITICAL);
        Vulnerability v2 = createVulnerability("Vuln-2", Severity.HIGH);
        Vulnerability v3 = createVulnerability("Vuln-3", Severity.MEDIUM);
        Vulnerability v4 = createVulnerability("Vuln-4", Severity.LOW);
        qm.addVulnerability(v1, c1, "none");
        qm.addVulnerability(v2, c1, "none");
        qm.addVulnerability(v3, c2, "none");
        qm.addVulnerability(v4, c5, "none");
        Response response = jersey.target(V1_FINDING + "/project/" + p1.getUuid().toString()).request()
                .header(X_API_KEY, apiKey)
                .get(Response.class);
        assertEquals(200, response.getStatus(), 0);
        assertEquals(String.valueOf(3), response.getHeaderString(TOTAL_COUNT_HEADER));
        JsonArray json = parseJsonArray(response);
        assertNotNull(json);
        assertThat(json).satisfiesExactlyInAnyOrder(
                jsonValue -> {
                    final JsonObject finding = jsonValue.asJsonObject();
                    assertEquals("Component A", finding.getJsonObject("component").getString("name"));
                    assertEquals("1.0", finding.getJsonObject("component").getString("version"));
                    assertEquals("Vuln-1", finding.getJsonObject("vulnerability").getString("vulnId"));
                    assertEquals(Severity.CRITICAL.name(), finding.getJsonObject("vulnerability").getString("severity"));
                    assertEquals(2, finding.getJsonObject("vulnerability").getJsonArray("cwes").size());
                    assertEquals(80, finding.getJsonObject("vulnerability").getJsonArray("cwes").getJsonObject(0).getInt("cweId"));
                    assertEquals(666, finding.getJsonObject("vulnerability").getJsonArray("cwes").getJsonObject(1).getInt("cweId"));
                    assertFalse(finding.getJsonObject("analysis").getBoolean("isSuppressed"));
                    assertEquals(p1.getUuid().toString() + ":" + c1.getUuid().toString() + ":" + v1.getUuid().toString(), finding.getString("matrix"));
                    assertEquals("2.0.0", finding.getJsonObject("component").getString("latestVersion"));
                },
                jsonValue -> {
                    final JsonObject finding = jsonValue.asJsonObject();
                    assertEquals("Component A", finding.getJsonObject("component").getString("name"));
                    assertEquals("1.0", finding.getJsonObject("component").getString("version"));
                    assertEquals("Vuln-2", finding.getJsonObject("vulnerability").getString("vulnId"));
                    assertEquals(Severity.HIGH.name(), finding.getJsonObject("vulnerability").getString("severity"));
                    assertEquals(2, finding.getJsonObject("vulnerability").getJsonArray("cwes").size());
                    assertEquals(80, finding.getJsonObject("vulnerability").getJsonArray("cwes").getJsonObject(0).getInt("cweId"));
                    assertEquals(666, finding.getJsonObject("vulnerability").getJsonArray("cwes").getJsonObject(1).getInt("cweId"));
                    assertFalse(finding.getJsonObject("analysis").getBoolean("isSuppressed"));
                    assertEquals(p1.getUuid().toString() + ":" + c1.getUuid().toString() + ":" + v2.getUuid().toString(), finding.getString("matrix"));
                    assertEquals("2.0.0", finding.getJsonObject("component").getString("latestVersion"));
                },
                jsonValue -> {
                    final JsonObject finding = jsonValue.asJsonObject();
                    assertEquals("Component B", finding.getJsonObject("component").getString("name"));
                    assertEquals("1.0", finding.getJsonObject("component").getString("version"));
                    assertEquals("Vuln-3", finding.getJsonObject("vulnerability").getString("vulnId"));
                    assertEquals(Severity.MEDIUM.name(), finding.getJsonObject("vulnerability").getString("severity"));
                    assertEquals(2, finding.getJsonObject("vulnerability").getJsonArray("cwes").size());
                    assertEquals(80, finding.getJsonObject("vulnerability").getJsonArray("cwes").getJsonObject(0).getInt("cweId"));
                    assertEquals(666, finding.getJsonObject("vulnerability").getJsonArray("cwes").getJsonObject(1).getInt("cweId"));
                    assertFalse(json.getJsonObject(0).getJsonObject("analysis").getBoolean("isSuppressed"));
                    assertEquals(p1.getUuid().toString() + ":" + c2.getUuid().toString() + ":" + v3.getUuid().toString(), finding.getString("matrix"));
                    assertEquals("3.0.0", finding.getJsonObject("component").getString("latestVersion"));
                }
        );
    }

    @Test
    public void getFindingsByProjectWithComponentLatestVersionWithoutRepositoryMetaComponent() {
        initializeWithPermissions(Permissions.VIEW_VULNERABILITY);

        Project p1 = qm.createProject("Acme Example", null, "1.0", null, null, null, null, false);
        Component c1 = createComponent(p1, "Component A", "1.0");
        c1.setPurl("pkg:/maven/org.acme/component-a@1.0.0");

        Vulnerability v1 = createVulnerability("Vuln-1", Severity.CRITICAL);
        qm.addVulnerability(v1, c1, "none");
        Response response = jersey.target(V1_FINDING + "/project/" + p1.getUuid().toString()).request()
                .header(X_API_KEY, apiKey)
                .get(Response.class);
        assertEquals(200, response.getStatus(), 0);
        assertEquals(String.valueOf(1), response.getHeaderString(TOTAL_COUNT_HEADER));
        JsonArray json = parseJsonArray(response);
        assertNotNull(json);
        assertEquals(1, json.size());
        assertEquals("Component A", json.getJsonObject(0).getJsonObject("component").getString("name"));
        assertEquals("1.0", json.getJsonObject(0).getJsonObject("component").getString("version"));
        assertEquals("Vuln-1", json.getJsonObject(0).getJsonObject("vulnerability").getString("vulnId"));
        assertEquals(Severity.CRITICAL.name(), json.getJsonObject(0).getJsonObject("vulnerability").getString("severity"));
        assertEquals(2, json.getJsonObject(0).getJsonObject("vulnerability").getJsonArray("cwes").size());
        assertEquals(80, json.getJsonObject(0).getJsonObject("vulnerability").getJsonArray("cwes").getJsonObject(0).getInt("cweId"));
        assertEquals(666, json.getJsonObject(0).getJsonObject("vulnerability").getJsonArray("cwes").getJsonObject(1).getInt("cweId"));
        assertFalse(json.getJsonObject(0).getJsonObject("analysis").getBoolean("isSuppressed"));
        assertEquals(p1.getUuid().toString() + ":" + c1.getUuid().toString() + ":" + v1.getUuid().toString(), json.getJsonObject(0).getString("matrix"));
        assertNull(json.getJsonObject(0).getJsonObject("component").get("latestVersion"));
    }

    @Test
    public void getFindingsByProjectWithCvssAndOwaspData() {
        initializeWithPermissions(Permissions.VIEW_VULNERABILITY);

        Project p1 = qm.createProject("Acme Example", null, "1.0", null, null, null, null, false);
        Component c1 = createComponent(p1, "Component A", "1.0");
        c1.setPurl("pkg:/maven/org.acme/component-a@1.0.0");

        Vulnerability v1 = createVulnerability("Vuln-1", Severity.CRITICAL);
        v1.setCvssV2BaseScore(BigDecimal.valueOf(0.2));
        v1.setCvssV3BaseScore(BigDecimal.valueOf(0.3));
        v1.setOwaspRRBusinessImpactScore(BigDecimal.valueOf(0.4));
        v1.setCvssV2Vector("cvssV2-vector");
        v1.setCvssV3Vector("cvssV3-vector");
        v1.setOwaspRRVector("owasp-vector");
        qm.addVulnerability(v1, c1, "none");

        Response response = jersey.target(V1_FINDING + "/project/" + p1.getUuid().toString()).request()
                .header(X_API_KEY, apiKey)
                .get(Response.class);
        assertEquals(200, response.getStatus(), 0);
        assertEquals(String.valueOf(1), response.getHeaderString(TOTAL_COUNT_HEADER));
        JsonArray json = parseJsonArray(response);
        assertNotNull(json);
        assertEquals(1, json.size());
        assertEquals(0.2, json.getJsonObject(0).getJsonObject("vulnerability").getJsonNumber("cvssV2BaseScore").doubleValue(), 0);
        assertEquals(0.3, json.getJsonObject(0).getJsonObject("vulnerability").getJsonNumber("cvssV3BaseScore").doubleValue(), 0);
        assertEquals(0.4, json.getJsonObject(0).getJsonObject("vulnerability").getJsonNumber("owaspBusinessImpactScore").doubleValue(), 0);
        assertEquals("cvssV2-vector", json.getJsonObject(0).getJsonObject("vulnerability").getString("cvssV2Vector"));
        assertEquals("cvssV3-vector", json.getJsonObject(0).getJsonObject("vulnerability").getString("cvssV3Vector"));
        assertEquals("owasp-vector", json.getJsonObject(0).getJsonObject("vulnerability").getString("owaspRRVector"));
    }

    @Test
    public void getFindingsByProjectWithComponentOccurrence() {
        initializeWithPermissions(Permissions.VIEW_VULNERABILITY);

        Project p1 = qm.createProject("Acme Example", null, "1.0", null, null, null, null, false);
        Component c1 = createComponent(p1, "Component A", "1.0");
        Component c2 = createComponent(p1, "Component B", "1.0");

        var componentOccurrence = new ComponentOccurrence();
        componentOccurrence.setComponent(c2);
        componentOccurrence.setLocation("/foo/bar");
        componentOccurrence.setLine(666);
        componentOccurrence.setOffset(123);
        componentOccurrence.setSymbol("someSymbol");
        qm.persist(componentOccurrence);

        Vulnerability v1 = createVulnerability("Vuln-1", Severity.CRITICAL);
        qm.addVulnerability(v1, c1, "none");
        qm.addVulnerability(v1, c2, "none");

        Response response = jersey.target(V1_FINDING + "/project/" + p1.getUuid().toString()).request()
                .header(X_API_KEY, apiKey)
                .get(Response.class);
        assertEquals(200, response.getStatus(), 0);
        assertEquals(String.valueOf(2), response.getHeaderString(TOTAL_COUNT_HEADER));
        JsonArray jsonArray = parseJsonArray(response);
        assertNotNull(jsonArray);
        assertEquals(2, jsonArray.size());
        JsonObject json  = jsonArray.getJsonObject(0);
        assertEquals("Component A", json.getJsonObject("component").getString("name"));
        assertEquals(false, json.getJsonObject("component").getBoolean("hasOccurrences"));
        json  = jsonArray.getJsonObject(1);
        assertEquals("Component B", json.getJsonObject("component").getString("name"));
        assertEquals(true, json.getJsonObject("component").getBoolean("hasOccurrences"));
    }

    @Test
    public void getFindingsByProjectWithRatingOverride() {
        initializeWithPermissions(Permissions.VIEW_VULNERABILITY);

        Project p1 = qm.createProject("Acme Example", null, "1.0", null, null, null, null, false);
        Component c1 = createComponent(p1, "Component A", "1.0");
        c1.setPurl("pkg:/maven/org.acme/component-a@1.0.0");

        Vulnerability v1 = createVulnerability("Vuln-1", Severity.CRITICAL);
        v1.setCvssV2BaseScore(BigDecimal.valueOf(0.2));
        v1.setCvssV2Vector("v-cvssV2-vector");
        qm.addVulnerability(v1, c1, "none");

        var analysis = new Analysis();
        analysis.setVulnerability(v1);
        analysis.setComponent(c1);
        analysis.setAnalysisState(AnalysisState.NOT_AFFECTED);
        analysis.setCvssV2Score(BigDecimal.valueOf(0.4));
        analysis.setCvssV2Vector("a-cvssV2-vector");
        analysis.setSeverity(Severity.HIGH);
        qm.persist(analysis);

        Response response = jersey.target(V1_FINDING + "/project/" + p1.getUuid().toString()).request()
                .header(X_API_KEY, apiKey)
                .get(Response.class);
        assertEquals(200, response.getStatus(), 0);
        assertEquals(String.valueOf(1), response.getHeaderString(TOTAL_COUNT_HEADER));
        JsonArray json = parseJsonArray(response);
        assertNotNull(json);
        assertEquals(1, json.size());
        assertEquals(0.4, json.getJsonObject(0).getJsonObject("vulnerability").getJsonNumber("cvssV2BaseScore").doubleValue(), 0);
        assertEquals(analysis.getCvssV2Vector(), json.getJsonObject(0).getJsonObject("vulnerability").getString("cvssV2Vector"));
        assertEquals(analysis.getSeverity().name(), json.getJsonObject(0).getJsonObject("vulnerability").getString("severity"));
    }

    @Test
    public void analyzeProjectShouldCreateAnalyzeProjectWorkflowRun() {
        initializeWithPermissions(Permissions.VULNERABILITY_ANALYSIS);

        var project = new Project();
        project.setName("Acme Example");
        project = qm.persist(project);

        doReturn(UUID.fromString("d93df5a0-f29e-4ee1-9c98-cee4dd243750"))
                .when(DEX_ENGINE_MOCK).createRun(ArgumentMatchers.<CreateWorkflowRunRequest<?>>any());

        Response response = jersey
                .target("%s/project/%s/analyze".formatted(V1_FINDING, project.getUuid()))
                .request()
                .header(X_API_KEY, apiKey)
                .post(Entity.json("{}"));
        assertThat(response.getStatus()).isEqualTo(200);
        assertThatJson(getPlainTextBody(response)).isEqualTo(/* language=JSON */ """
                {
                  "token": "d93df5a0-f29e-4ee1-9c98-cee4dd243750"
                }
                """);

        //noinspection unchecked
        ArgumentCaptor<CreateWorkflowRunRequest<?>> dexCreateRunCaptor =
                ArgumentCaptor.forClass(CreateWorkflowRunRequest.class);
        verify(DEX_ENGINE_MOCK, times(2)).createRun(dexCreateRunCaptor.capture());

        CreateWorkflowRunRequest<?> createDexRunRequest = dexCreateRunCaptor.getAllValues().getFirst();
        assertThat(createDexRunRequest.workflowName()).isEqualTo("analyze-project");
        assertThat(createDexRunRequest.workflowVersion()).isEqualTo(1);
        assertThat(createDexRunRequest.workflowInstanceId()).isEqualTo("analyze-project-manual:" + project.getUuid());
        assertThat(createDexRunRequest.concurrencyKey()).isEqualTo("analyze-project:" + project.getUuid());
        assertThat(createDexRunRequest.labels()).containsEntry("project_uuid", project.getUuid().toString());
        assertThat(createDexRunRequest.labels()).hasEntrySatisfying("triggered_by", value -> assertThat(value).startsWith("odt_"));
        assertThat(createDexRunRequest.priority()).isEqualTo(75);
    }

    @Test
    public void getAllFindings() {
        initializeWithPermissions(Permissions.VIEW_VULNERABILITY);

        Project p1 = qm.createProject("Acme Example 1", null, "1.0", null, null, null, null, false);
        Project p1_child = qm.createProject("Acme Example 2", null, "1.0", null, p1, null, null, false);
        Project p2 = qm.createProject("Acme Example 3", null, "1.0", null, null, null, null, false);
        Component c1 = createComponent(p1, "Component A", "1.0");
        Component c2 = createComponent(p1, "Component B", "1.0");
        Component c3 = createComponent(p1_child, "Component C", "1.0");
        createComponent(p2, "Component D", "1.0");
        Component c5 = createComponent(p2, "Component E", "1.0");
        createComponent(p2, "Component F", "1.0");
        Vulnerability v1 = createVulnerability("Vuln-1", Severity.CRITICAL);
        Vulnerability v2 = createVulnerability("Vuln-2", Severity.HIGH);
        Vulnerability v3 = createVulnerability("Vuln-3", Severity.MEDIUM);
        Vulnerability v4 = createVulnerability("Vuln-4", Severity.LOW);
        Date date = new Date();
        v1.setPublished(date);
        v2.setPublished(date);
        v3.setPublished(date);
        v4.setPublished(date);
        qm.addVulnerability(v1, c1, "none");
        qm.addVulnerability(v2, c1, "none");
        qm.addVulnerability(v2, c3, "none");
        qm.addVulnerability(v3, c2, "none");
        qm.addVulnerability(v4, c5, "none");
        Response response = jersey.target(V1_FINDING)
                .queryParam("sortName", "component.projectName")
                .queryParam("sortOrder", "asc")
                .request()
                .header(X_API_KEY, apiKey)
                .get(Response.class);
        assertEquals(200, response.getStatus(), 0);
        assertEquals(String.valueOf(5), response.getHeaderString(TOTAL_COUNT_HEADER));
        JsonArray json = parseJsonArray(response);
        assertNotNull(json);
        assertEquals(5, json.size());
        assertEquals(date.getTime(), json.getJsonObject(0).getJsonObject("vulnerability").getJsonNumber("published").longValue());
        assertEquals(p1.getName() ,json.getJsonObject(0).getJsonObject("component").getString("projectName"));
        assertEquals(p1.getVersion() ,json.getJsonObject(0).getJsonObject("component").getString("projectVersion"));
        assertEquals(p1.getUuid().toString(), json.getJsonObject(0).getJsonObject("component").getString("project"));
        assertEquals(date.getTime(), json.getJsonObject(1).getJsonObject("vulnerability").getJsonNumber("published").longValue());
        assertEquals(p1.getName() ,json.getJsonObject(1).getJsonObject("component").getString("projectName"));
        assertEquals(p1.getVersion() ,json.getJsonObject(1).getJsonObject("component").getString("projectVersion"));
        assertEquals(p1.getUuid().toString(), json.getJsonObject(1).getJsonObject("component").getString("project"));
        assertEquals(date.getTime(), json.getJsonObject(2).getJsonObject("vulnerability").getJsonNumber("published").longValue());
        assertEquals(p1.getName() ,json.getJsonObject(2).getJsonObject("component").getString("projectName"));
        assertEquals(p1.getVersion() ,json.getJsonObject(2).getJsonObject("component").getString("projectVersion"));
        assertEquals(p1.getUuid().toString(), json.getJsonObject(2).getJsonObject("component").getString("project"));
        assertEquals(date.getTime(), json.getJsonObject(3).getJsonObject("vulnerability").getJsonNumber("published").longValue());
        assertEquals(p1_child.getName() ,json.getJsonObject(3).getJsonObject("component").getString("projectName"));
        assertEquals(p1_child.getVersion() ,json.getJsonObject(3).getJsonObject("component").getString("projectVersion"));
        assertEquals(p1_child.getUuid().toString(), json.getJsonObject(3).getJsonObject("component").getString("project"));
        assertEquals(date.getTime(), json.getJsonObject(4).getJsonObject("vulnerability").getJsonNumber("published").longValue());
        assertEquals(p2.getName() ,json.getJsonObject(4).getJsonObject("component").getString("projectName"));
        assertEquals(p2.getVersion() ,json.getJsonObject(4).getJsonObject("component").getString("projectVersion"));
        assertEquals(p2.getUuid().toString(), json.getJsonObject(4).getJsonObject("component").getString("project"));
    }

    @Test
    public void getAllFindingsSortedBySeverity() {
        initializeWithPermissions(Permissions.VIEW_VULNERABILITY);

        Project p1 = qm.createProject("Acme Example 1", null, "1.0", null, null, null, null, false);
        Component c1 = createComponent(p1, "Component A", "1.0");
        Vulnerability v1 = createVulnerability("Vuln-1", Severity.CRITICAL);
        Vulnerability v2 = createVulnerability("Vuln-2", Severity.MEDIUM);
        Vulnerability v3 = createVulnerability("Vuln-3", Severity.HIGH);
        Date date = new Date();
        v1.setPublished(date);
        v2.setPublished(date);
        v3.setPublished(date);
        qm.addVulnerability(v1, c1, "none");
        qm.addVulnerability(v2, c1, "none");
        qm.addVulnerability(v3, c1, "none");
        Response response = jersey.target(V1_FINDING)
                .queryParam("sortName", "vulnerability.severity")
                .queryParam("sortOrder", "desc")
                .request()
                .header(X_API_KEY, apiKey)
                .get(Response.class);
        assertEquals(200, response.getStatus(), 0);
        assertEquals(String.valueOf(3), response.getHeaderString(TOTAL_COUNT_HEADER));
        JsonArray json = parseJsonArray(response);
        assertNotNull(json);
        assertEquals(3, json.size());
        assertEquals(v1.getSeverity().name(), json.getJsonObject(0).getJsonObject("vulnerability").getString("severity"));
        assertEquals(v3.getSeverity().name(), json.getJsonObject(1).getJsonObject("vulnerability").getString("severity"));
        assertEquals(v2.getSeverity().name(), json.getJsonObject(2).getJsonObject("vulnerability").getString("severity"));
    }

    @Test
    public void getAllFindingsFilteredBySeverity() {
        initializeWithPermissions(Permissions.VIEW_VULNERABILITY);

        Project p1 = qm.createProject("Acme Example 1", null, "1.0", null, null, null, null, false);
        Component c1 = createComponent(p1, "Component A", "1.0");
        Vulnerability v1 = createVulnerability("Vuln-1", Severity.CRITICAL);
        Vulnerability v2 = createVulnerability("Vuln-2", Severity.MEDIUM);
        Vulnerability v3 = createVulnerability("Vuln-3", Severity.HIGH);
        Date date = new Date();
        v1.setPublished(date);
        v2.setPublished(date);
        v3.setPublished(date);
        qm.addVulnerability(v1, c1, "none");
        qm.addVulnerability(v2, c1, "none");
        qm.addVulnerability(v3, c1, "none");

        // Filter by single severity
        Response response = jersey.target(V1_FINDING)
                .queryParam("severity", "CRITICAL")
                .request()
                .header(X_API_KEY, apiKey)
                .get(Response.class);
        assertEquals(200, response.getStatus(), 0);
        assertEquals(String.valueOf(1), response.getHeaderString(TOTAL_COUNT_HEADER));
        JsonArray json = parseJsonArray(response);
        assertNotNull(json);
        assertEquals(1, json.size());
        assertEquals("CRITICAL", json.getJsonObject(0).getJsonObject("vulnerability").getString("severity"));

        // Filter by multiple severities
        response = jersey.target(V1_FINDING)
                .queryParam("severity", "CRITICAL,HIGH")
                .request()
                .header(X_API_KEY, apiKey)
                .get(Response.class);
        assertEquals(200, response.getStatus(), 0);
        assertEquals(String.valueOf(2), response.getHeaderString(TOTAL_COUNT_HEADER));
        json = parseJsonArray(response);
        assertNotNull(json);
        assertEquals(2, json.size());
    }

    @Test
    public void getAllFindingsWithAclEnabled() {
        Project p1 = qm.createProject("Acme Example", null, "1.0", null, null, null, null, false);
        Project p1_child = qm.createProject("Acme Example Child", null, "1.0", null, p1, null, null, false);
        Project p2 = qm.createProject("Acme Example", null, "2.0", null, null, null, null, false);
        Team team = qm.createTeam("Team Acme");
        team.setPermissions(List.of(qm.createPermission(Permissions.VIEW_VULNERABILITY.name(), null)));
        ApiKey apiKey = qm.createApiKey(team);
        p1.addAccessTeam(team);
        Component c1 = createComponent(p1, "Component A", "1.0");
        Component c2 = createComponent(p1, "Component B", "1.0");
        Component c3 = createComponent(p1_child, "Component C", "1.0");
        createComponent(p2, "Component D", "1.0");
        Component c5 = createComponent(p2, "Component E", "1.0");
        createComponent(p2, "Component F", "1.0");
        Vulnerability v1 = createVulnerability("Vuln-1", Severity.CRITICAL);
        Vulnerability v2 = createVulnerability("Vuln-2", Severity.HIGH);
        Vulnerability v3 = createVulnerability("Vuln-3", Severity.MEDIUM);
        Vulnerability v4 = createVulnerability("Vuln-4", Severity.LOW);
        Date date = new Date();
        v1.setPublished(date);
        v2.setPublished(date);
        v3.setPublished(date);
        v4.setPublished(date);
        qm.addVulnerability(v1, c1, "none");
        qm.addVulnerability(v2, c1, "none");
        qm.addVulnerability(v2, c3, "none");
        qm.addVulnerability(v3, c2, "none");
        qm.addVulnerability(v4, c5, "none");
        ConfigProperty aclToggle = qm.getConfigProperty(ConfigPropertyConstants.ACCESS_MANAGEMENT_ACL_ENABLED.getGroupName(), ConfigPropertyConstants.ACCESS_MANAGEMENT_ACL_ENABLED.getPropertyName());
        if (aclToggle == null) {
            qm.createConfigProperty(ConfigPropertyConstants.ACCESS_MANAGEMENT_ACL_ENABLED.getGroupName(), ConfigPropertyConstants.ACCESS_MANAGEMENT_ACL_ENABLED.getPropertyName(), "true", ConfigPropertyConstants.ACCESS_MANAGEMENT_ACL_ENABLED.getPropertyType(), ConfigPropertyConstants.ACCESS_MANAGEMENT_ACL_ENABLED.getDescription());
        } else {
            aclToggle.setPropertyValue("true");
            qm.persist(aclToggle);
        }
        Response response = jersey.target(V1_FINDING).request()
                .header(X_API_KEY, apiKey.getKey())
                .get(Response.class);
        assertEquals(200, response.getStatus(), 0);
        assertEquals(String.valueOf(4), response.getHeaderString(TOTAL_COUNT_HEADER));
        JsonArray json = parseJsonArray(response);
        assertNotNull(json);
        assertEquals(4, json.size());
        assertEquals(date.getTime(), json.getJsonObject(0).getJsonObject("vulnerability").getJsonNumber("published").longValue());
        assertEquals(p1.getName() ,json.getJsonObject(0).getJsonObject("component").getString("projectName"));
        assertEquals(p1.getVersion() ,json.getJsonObject(0).getJsonObject("component").getString("projectVersion"));
        assertEquals(p1.getUuid().toString(), json.getJsonObject(0).getJsonObject("component").getString("project"));
        assertEquals(date.getTime(), json.getJsonObject(1).getJsonObject("vulnerability").getJsonNumber("published").longValue());
        assertEquals(p1.getName() ,json.getJsonObject(1).getJsonObject("component").getString("projectName"));
        assertEquals(p1.getVersion() ,json.getJsonObject(1).getJsonObject("component").getString("projectVersion"));
        assertEquals(p1.getUuid().toString(), json.getJsonObject(1).getJsonObject("component").getString("project"));
        assertEquals(date.getTime(), json.getJsonObject(2).getJsonObject("vulnerability").getJsonNumber("published").longValue());
        assertEquals(p1.getName() ,json.getJsonObject(2).getJsonObject("component").getString("projectName"));
        assertEquals(p1.getVersion() ,json.getJsonObject(2).getJsonObject("component").getString("projectVersion"));
        assertEquals(p1.getUuid().toString(), json.getJsonObject(2).getJsonObject("component").getString("project"));

        // Findings of p1_child are returned because team was given access to its parent project p1.
        assertEquals(date.getTime(), json.getJsonObject(3).getJsonObject("vulnerability").getJsonNumber("published").longValue());
        assertEquals(p1_child.getName(), json.getJsonObject(3).getJsonObject("component").getString("projectName"));
        assertEquals(p1_child.getVersion(), json.getJsonObject(3).getJsonObject("component").getString("projectVersion"));
        assertEquals(p1_child.getUuid().toString(), json.getJsonObject(3).getJsonObject("component").getString("project"));
    }

    @Test
    public void getAllFindingsWithComponentOccurrence() {
        initializeWithPermissions(Permissions.VIEW_VULNERABILITY);

        Project p1 = qm.createProject("Acme Example", null, "1.0", null, null, null, null, false);
        Component c1 = createComponent(p1, "Component A", "1.0");
        Component c2 = createComponent(p1, "Component B", "1.0");

        var componentOccurrence = new ComponentOccurrence();
        componentOccurrence.setComponent(c2);
        componentOccurrence.setLocation("/foo/bar");
        componentOccurrence.setLine(666);
        componentOccurrence.setOffset(123);
        componentOccurrence.setSymbol("someSymbol");
        qm.persist(componentOccurrence);

        Vulnerability v1 = createVulnerability("Vuln-1", Severity.CRITICAL);
        qm.addVulnerability(v1, c1, "none");
        qm.addVulnerability(v1, c2, "none");

        Response response = jersey.target(V1_FINDING)
                .request()
                .header(X_API_KEY, apiKey)
                .get(Response.class);
        assertEquals(200, response.getStatus(), 0);
        assertEquals(String.valueOf(2), response.getHeaderString(TOTAL_COUNT_HEADER));
        JsonArray jsonArray = parseJsonArray(response);
        assertNotNull(jsonArray);
        assertEquals(2, jsonArray.size());
        JsonObject json  = jsonArray.getJsonObject(0);
        assertEquals("Component A", json.getJsonObject("component").getString("name"));
        assertEquals(false, json.getJsonObject("component").getBoolean("hasOccurrences"));
        json  = jsonArray.getJsonObject(1);
        assertEquals("Component B", json.getJsonObject("component").getString("name"));
        assertEquals(true, json.getJsonObject("component").getBoolean("hasOccurrences"));
    }

    @Test
    public void getAllFindingsGroupedByVulnerability() {
        initializeWithPermissions(Permissions.VIEW_VULNERABILITY);

        Project p1 = qm.createProject("Acme Example", null, "1.0", null, null, null, null, false);
        Project p1_child = qm.createProject("Acme Example Child", null, "1.0", null, p1, null, null, false);
        Project p2 = qm.createProject("Acme Example", null, "2.0", null, null, null, null, false);
        Component c1 = createComponent(p1, "Component A", "1.0");
        Component c2 = createComponent(p1, "Component B", "1.0");
        Component c3 = createComponent(p1_child, "Component C", "1.0");
        Component c4 = createComponent(p2, "Component D", "1.0");
        Component c5 = createComponent(p2, "Component E", "1.0");
        Component c6 = createComponent(p2, "Component F", "1.0");
        Vulnerability v1 = createVulnerability("Vuln-1", Severity.CRITICAL);
        Vulnerability v2 = createVulnerability("Vuln-2", Severity.HIGH);
        Vulnerability v3 = createVulnerability("Vuln-3", Severity.MEDIUM);
        Vulnerability v4 = createVulnerability("Vuln-4", Severity.LOW);
        Date date = new Date();
        v1.setPublished(date);
        v2.setPublished(date);
        v3.setPublished(date);
        v4.setPublished(date);
        qm.addVulnerability(v1, c1, "none");
        qm.addVulnerability(v2, c1, "none");
        qm.addVulnerability(v2, c3, "none");
        qm.addVulnerability(v2, c4, "none");
        qm.addVulnerability(v3, c2, "none");
        qm.addVulnerability(v3, c6, "none");
        qm.addVulnerability(v4, c5, "none");
        Response response = jersey.target(V1_FINDING + "/grouped").request()
                .header(X_API_KEY, apiKey)
                .get(Response.class);
        assertEquals(200, response.getStatus(), 0);
        assertEquals(String.valueOf(4), response.getHeaderString(TOTAL_COUNT_HEADER));
        JsonArray json = parseJsonArray(response);
        assertNotNull(json);
        assertEquals(4, json.size());
        assertEquals("INTERNAL", json.getJsonObject(0).getJsonObject("vulnerability").getString("source"));
        assertEquals("Vuln-1", json.getJsonObject(0).getJsonObject("vulnerability").getString("vulnId"));
        assertEquals(Severity.CRITICAL.name(), json.getJsonObject(0).getJsonObject("vulnerability").getString("severity"));
        assertEquals("none", json.getJsonObject(0).getJsonObject("attribution").getString("analyzerIdentity"));
        assertEquals(date.getTime(), json.getJsonObject(0).getJsonObject("vulnerability").getJsonNumber("published").longValue());
        assertEquals(2, json.getJsonObject(0).getJsonObject("vulnerability").getJsonArray("cwes").size());
        assertEquals(80, json.getJsonObject(0).getJsonObject("vulnerability").getJsonArray("cwes").getInt(0));
        assertEquals(666, json.getJsonObject(0).getJsonObject("vulnerability").getJsonArray("cwes").getInt(1));
        assertEquals(1, json.getJsonObject(0).getJsonObject("vulnerability").getInt("affectedProjectCount"));

        assertEquals("INTERNAL", json.getJsonObject(1).getJsonObject("vulnerability").getString("source"));
        assertEquals("Vuln-2", json.getJsonObject(1).getJsonObject("vulnerability").getString("vulnId"));
        assertEquals(Severity.HIGH.name(), json.getJsonObject(1).getJsonObject("vulnerability").getString("severity"));
        assertEquals("none", json.getJsonObject(1).getJsonObject("attribution").getString("analyzerIdentity"));
        assertEquals(date.getTime(), json.getJsonObject(1).getJsonObject("vulnerability").getJsonNumber("published").longValue());
        assertEquals(2, json.getJsonObject(1).getJsonObject("vulnerability").getJsonArray("cwes").size());
        assertEquals(80, json.getJsonObject(1).getJsonObject("vulnerability").getJsonArray("cwes").getInt(0));
        assertEquals(666, json.getJsonObject(1).getJsonObject("vulnerability").getJsonArray("cwes").getInt(1));
        assertEquals(3, json.getJsonObject(1).getJsonObject("vulnerability").getInt("affectedProjectCount"));

        assertEquals("INTERNAL", json.getJsonObject(2).getJsonObject("vulnerability").getString("source"));
        assertEquals("Vuln-3", json.getJsonObject(2).getJsonObject("vulnerability").getString("vulnId"));
        assertEquals(Severity.MEDIUM.name(), json.getJsonObject(2).getJsonObject("vulnerability").getString("severity"));
        assertEquals("none", json.getJsonObject(2).getJsonObject("attribution").getString("analyzerIdentity"));
        assertEquals(date.getTime(), json.getJsonObject(2).getJsonObject("vulnerability").getJsonNumber("published").longValue());
        assertEquals(2, json.getJsonObject(2).getJsonObject("vulnerability").getJsonArray("cwes").size());
        assertEquals(80, json.getJsonObject(2).getJsonObject("vulnerability").getJsonArray("cwes").getInt(0));
        assertEquals(666, json.getJsonObject(2).getJsonObject("vulnerability").getJsonArray("cwes").getInt(1));
        assertEquals(2, json.getJsonObject(2).getJsonObject("vulnerability").getInt("affectedProjectCount"));

        assertEquals("INTERNAL", json.getJsonObject(3).getJsonObject("vulnerability").getString("source"));
        assertEquals("Vuln-4", json.getJsonObject(3).getJsonObject("vulnerability").getString("vulnId"));
        assertEquals(Severity.LOW.name(), json.getJsonObject(3).getJsonObject("vulnerability").getString("severity"));
        assertEquals("none", json.getJsonObject(3).getJsonObject("attribution").getString("analyzerIdentity"));
        assertEquals(date.getTime(), json.getJsonObject(3).getJsonObject("vulnerability").getJsonNumber("published").longValue());
        assertEquals(2, json.getJsonObject(3).getJsonObject("vulnerability").getJsonArray("cwes").size());
        assertEquals(80, json.getJsonObject(3).getJsonObject("vulnerability").getJsonArray("cwes").getInt(0));
        assertEquals(666, json.getJsonObject(3).getJsonObject("vulnerability").getJsonArray("cwes").getInt(1));
        assertEquals(1, json.getJsonObject(3).getJsonObject("vulnerability").getInt("affectedProjectCount"));
    }

    @Test
    public void getAllFindingsGroupedByVulnerabilityWithAclEnabled() {
        Project p1 = qm.createProject("Acme Example", null, "1.0", null, null, null, null, false);
        Project p1_child = qm.createProject("Acme Example Child", null, "1.0", null, p1, null, null, false);
        Project p2 = qm.createProject("Acme Example", null, "2.0", null, null, null, null, false);
        Team team = qm.createTeam("Team Acme");
        team.setPermissions(List.of(qm.createPermission(Permissions.VIEW_VULNERABILITY.name(), null)));
        ApiKey apiKey = qm.createApiKey(team);
        p1.addAccessTeam(team);
        Component c1 = createComponent(p1, "Component A", "1.0");
        Component c2 = createComponent(p1, "Component B", "1.0");
        Component c3 = createComponent(p1_child, "Component C", "1.0");
        Component c4 = createComponent(p2, "Component D", "1.0");
        Component c5 = createComponent(p2, "Component E", "1.0");
        Component c6 = createComponent(p2, "Component F", "1.0");
        Vulnerability v1 = createVulnerability("Vuln-1", Severity.CRITICAL);
        Vulnerability v2 = createVulnerability("Vuln-2", Severity.HIGH);
        Vulnerability v3 = createVulnerability("Vuln-3", Severity.MEDIUM);
        Vulnerability v4 = createVulnerability("Vuln-4", Severity.LOW);
        Date date = new Date();
        v1.setPublished(date);
        v2.setPublished(date);
        v3.setPublished(date);
        v4.setPublished(date);
        qm.addVulnerability(v1, c1, "none");
        qm.addVulnerability(v2, c1, "none");
        qm.addVulnerability(v2, c3, "none");
        qm.addVulnerability(v2, c4, "none");
        qm.addVulnerability(v3, c2, "none");
        qm.addVulnerability(v3, c6, "none");
        qm.addVulnerability(v4, c5, "none");
        ConfigProperty aclToggle = qm.getConfigProperty(ConfigPropertyConstants.ACCESS_MANAGEMENT_ACL_ENABLED.getGroupName(), ConfigPropertyConstants.ACCESS_MANAGEMENT_ACL_ENABLED.getPropertyName());
        if (aclToggle == null) {
            qm.createConfigProperty(ConfigPropertyConstants.ACCESS_MANAGEMENT_ACL_ENABLED.getGroupName(), ConfigPropertyConstants.ACCESS_MANAGEMENT_ACL_ENABLED.getPropertyName(), "true", ConfigPropertyConstants.ACCESS_MANAGEMENT_ACL_ENABLED.getPropertyType(), ConfigPropertyConstants.ACCESS_MANAGEMENT_ACL_ENABLED.getDescription());
        } else {
            aclToggle.setPropertyValue("true");
            qm.persist(aclToggle);
        }
        Response response = jersey.target(V1_FINDING + "/grouped").request()
                .header(X_API_KEY, apiKey.getKey())
                .get(Response.class);
        assertEquals(200, response.getStatus(), 0);
        assertEquals(String.valueOf(3), response.getHeaderString(TOTAL_COUNT_HEADER));
        JsonArray json = parseJsonArray(response);
        assertNotNull(json);
        assertEquals(3, json.size());
        assertEquals("INTERNAL", json.getJsonObject(0).getJsonObject("vulnerability").getString("source"));
        assertEquals("Vuln-1", json.getJsonObject(0).getJsonObject("vulnerability").getString("vulnId"));
        assertEquals(Severity.CRITICAL.name(), json.getJsonObject(0).getJsonObject("vulnerability").getString("severity"));
        assertEquals("none", json.getJsonObject(0).getJsonObject("attribution").getString("analyzerIdentity"));
        assertEquals(date.getTime(), json.getJsonObject(0).getJsonObject("vulnerability").getJsonNumber("published").longValue());
        assertEquals(2, json.getJsonObject(0).getJsonObject("vulnerability").getJsonArray("cwes").size());
        assertEquals(80, json.getJsonObject(0).getJsonObject("vulnerability").getJsonArray("cwes").getInt(0));
        assertEquals(666, json.getJsonObject(0).getJsonObject("vulnerability").getJsonArray("cwes").getInt(1));
        assertEquals(1, json.getJsonObject(0).getJsonObject("vulnerability").getInt("affectedProjectCount"));

        assertEquals("INTERNAL", json.getJsonObject(1).getJsonObject("vulnerability").getString("source"));
        assertEquals("Vuln-2", json.getJsonObject(1).getJsonObject("vulnerability").getString("vulnId"));
        assertEquals(Severity.HIGH.name(), json.getJsonObject(1).getJsonObject("vulnerability").getString("severity"));
        assertEquals("none", json.getJsonObject(1).getJsonObject("attribution").getString("analyzerIdentity"));
        assertEquals(date.getTime(), json.getJsonObject(1).getJsonObject("vulnerability").getJsonNumber("published").longValue());
        assertEquals(2, json.getJsonObject(1).getJsonObject("vulnerability").getJsonArray("cwes").size());
        assertEquals(80, json.getJsonObject(1).getJsonObject("vulnerability").getJsonArray("cwes").getInt(0));
        assertEquals(666, json.getJsonObject(1).getJsonObject("vulnerability").getJsonArray("cwes").getInt(1));
        assertEquals(2, json.getJsonObject(1).getJsonObject("vulnerability").getInt("affectedProjectCount")); // p1 and p1_child.

        assertEquals("INTERNAL", json.getJsonObject(2).getJsonObject("vulnerability").getString("source"));
        assertEquals("Vuln-3", json.getJsonObject(2).getJsonObject("vulnerability").getString("vulnId"));
        assertEquals(Severity.MEDIUM.name(), json.getJsonObject(2).getJsonObject("vulnerability").getString("severity"));
        assertEquals("none", json.getJsonObject(2).getJsonObject("attribution").getString("analyzerIdentity"));
        assertEquals(date.getTime(), json.getJsonObject(2).getJsonObject("vulnerability").getJsonNumber("published").longValue());
        assertEquals(2, json.getJsonObject(2).getJsonObject("vulnerability").getJsonArray("cwes").size());
        assertEquals(80, json.getJsonObject(2).getJsonObject("vulnerability").getJsonArray("cwes").getInt(0));
        assertEquals(666, json.getJsonObject(2).getJsonObject("vulnerability").getJsonArray("cwes").getInt(1));
        assertEquals(1, json.getJsonObject(2).getJsonObject("vulnerability").getInt("affectedProjectCount"));
    }

    @Test
    void getAllFindingsWithEpssFilterTest() {
        initializeWithPermissions(Permissions.VIEW_VULNERABILITY);

        Project p1 = qm.createProject("Acme Example", null, "1.0", null, null, null, null, false);
        Component c1 = createComponent(p1, "Component A", "1.0");
        Component c2 = createComponent(p1, "Component B", "1.0");
        Component c3 = createComponent(p1, "Component C", "1.0");

        // Create vulnerabilities with different EPSS scores
        Vulnerability v1 = createVulnerabilityWithEpss("Vuln-1", Severity.CRITICAL, new BigDecimal("0.1"));
        Vulnerability v2 = createVulnerabilityWithEpss("Vuln-2", Severity.HIGH, new BigDecimal("0.5"));
        Vulnerability v3 = createVulnerabilityWithEpss("Vuln-3", Severity.MEDIUM, new BigDecimal("0.9"));

        qm.addVulnerability(v1, c1, "none");
        qm.addVulnerability(v2, c2, "none");
        qm.addVulnerability(v3, c3, "none");

        // Test filtering by epssFrom
        Response response = jersey.target(V1_FINDING)
                .queryParam("epssFrom", "0.3")
                .request()
                .header(X_API_KEY, apiKey)
                .get(Response.class);
        Assertions.assertEquals(200, response.getStatus());
        Assertions.assertEquals("2", response.getHeaderString(TOTAL_COUNT_HEADER));
        JsonArray json = parseJsonArray(response);
        Assertions.assertNotNull(json);
        Assertions.assertEquals(2, json.size());

        // Test filtering by epssTo
        response = jersey.target(V1_FINDING)
                .queryParam("epssTo", "0.7")
                .request()
                .header(X_API_KEY, apiKey)
                .get(Response.class);
        Assertions.assertEquals(200, response.getStatus());
        Assertions.assertEquals("2", response.getHeaderString(TOTAL_COUNT_HEADER));

        // Test filtering by epssFrom and epssTo range
        response = jersey.target(V1_FINDING)
                .queryParam("epssFrom", "0.3")
                .queryParam("epssTo", "0.7")
                .request()
                .header(X_API_KEY, apiKey)
                .get(Response.class);
        Assertions.assertEquals(200, response.getStatus());
        Assertions.assertEquals("1", response.getHeaderString(TOTAL_COUNT_HEADER));
        json = parseJsonArray(response);
        Assertions.assertNotNull(json);
        Assertions.assertEquals(1, json.size());
        Assertions.assertEquals("Vuln-2", json.getJsonObject(0).getJsonObject("vulnerability").getString("vulnId"));
    }

    @Test
    void getAllFindingsGroupedByVulnerabilityWithEpssFilterTest() {
        initializeWithPermissions(Permissions.VIEW_VULNERABILITY);

        Project p1 = qm.createProject("Acme Example", null, "1.0", null, null, null, null, false);
        Component c1 = createComponent(p1, "Component A", "1.0");
        Component c2 = createComponent(p1, "Component B", "1.0");
        Component c3 = createComponent(p1, "Component C", "1.0");

        // Create vulnerabilities with different EPSS scores
        Vulnerability v1 = createVulnerabilityWithEpss("Vuln-1", Severity.CRITICAL, new BigDecimal("0.2"));
        Vulnerability v2 = createVulnerabilityWithEpss("Vuln-2", Severity.HIGH, new BigDecimal("0.6"));
        Vulnerability v3 = createVulnerabilityWithEpss("Vuln-3", Severity.MEDIUM, new BigDecimal("0.8"));

        qm.addVulnerability(v1, c1, "none");
        qm.addVulnerability(v2, c2, "none");
        qm.addVulnerability(v3, c3, "none");

        // Test filtering grouped findings by EPSS range
        Response response = jersey.target(V1_FINDING + "/grouped")
                .queryParam("epssFrom", "0.5")
                .queryParam("epssTo", "0.7")
                .request()
                .header(X_API_KEY, apiKey)
                .get(Response.class);
        Assertions.assertEquals(200, response.getStatus());
        Assertions.assertEquals("1", response.getHeaderString(TOTAL_COUNT_HEADER));
        JsonArray json = parseJsonArray(response);
        Assertions.assertNotNull(json);
        Assertions.assertEquals(1, json.size());
        Assertions.assertEquals("Vuln-2", json.getJsonObject(0).getJsonObject("vulnerability").getString("vulnId"));
    }

    @Test
    void getAllFindingsWithEpssPercentileFilterTest() {
        initializeWithPermissions(Permissions.VIEW_VULNERABILITY);

        Project p1 = qm.createProject("Acme Example", null, "1.0", null, null, null, null, false);
        Component c1 = createComponent(p1, "Component A", "1.0");
        Component c2 = createComponent(p1, "Component B", "1.0");
        Component c3 = createComponent(p1, "Component C", "1.0");

        // Create vulnerabilities with different EPSS percentiles
        Vulnerability v1 = createVulnerabilityWithEpssPercentile("Vuln-1", Severity.CRITICAL, new BigDecimal("0.1"));
        Vulnerability v2 = createVulnerabilityWithEpssPercentile("Vuln-2", Severity.HIGH, new BigDecimal("0.5"));
        Vulnerability v3 = createVulnerabilityWithEpssPercentile("Vuln-3", Severity.MEDIUM, new BigDecimal("0.9"));

        qm.addVulnerability(v1, c1, "none");
        qm.addVulnerability(v2, c2, "none");
        qm.addVulnerability(v3, c3, "none");

        // Test filtering by epssPercentileFrom
        Response response = jersey.target(V1_FINDING)
                .queryParam("epssPercentileFrom", "0.3")
                .request()
                .header(X_API_KEY, apiKey)
                .get(Response.class);
        Assertions.assertEquals(200, response.getStatus());
        Assertions.assertEquals("2", response.getHeaderString(TOTAL_COUNT_HEADER));
        JsonArray json = parseJsonArray(response);
        Assertions.assertNotNull(json);
        Assertions.assertEquals(2, json.size());

        // Test filtering by epssPercentileTo
        response = jersey.target(V1_FINDING)
                .queryParam("epssPercentileTo", "0.7")
                .request()
                .header(X_API_KEY, apiKey)
                .get(Response.class);
        Assertions.assertEquals(200, response.getStatus());
        Assertions.assertEquals("2", response.getHeaderString(TOTAL_COUNT_HEADER));

        // Test filtering by epssPercentileFrom and epssPercentileTo range
        response = jersey.target(V1_FINDING)
                .queryParam("epssPercentileFrom", "0.3")
                .queryParam("epssPercentileTo", "0.7")
                .request()
                .header(X_API_KEY, apiKey)
                .get(Response.class);
        Assertions.assertEquals(200, response.getStatus());
        Assertions.assertEquals("1", response.getHeaderString(TOTAL_COUNT_HEADER));
        json = parseJsonArray(response);
        Assertions.assertNotNull(json);
        Assertions.assertEquals(1, json.size());
        Assertions.assertEquals("Vuln-2", json.getJsonObject(0).getJsonObject("vulnerability").getString("vulnId"));
    }

    @Test
    void getAllFindingsGroupedByVulnerabilityWithEpssPercentileFilterTest() {
        initializeWithPermissions(Permissions.VIEW_VULNERABILITY);

        Project p1 = qm.createProject("Acme Example", null, "1.0", null, null, null, null, false);
        Component c1 = createComponent(p1, "Component A", "1.0");
        Component c2 = createComponent(p1, "Component B", "1.0");
        Component c3 = createComponent(p1, "Component C", "1.0");

        // Create vulnerabilities with different EPSS percentiles
        Vulnerability v1 = createVulnerabilityWithEpssPercentile("Vuln-1", Severity.CRITICAL, new BigDecimal("0.2"));
        Vulnerability v2 = createVulnerabilityWithEpssPercentile("Vuln-2", Severity.HIGH, new BigDecimal("0.6"));
        Vulnerability v3 = createVulnerabilityWithEpssPercentile("Vuln-3", Severity.MEDIUM, new BigDecimal("0.8"));

        qm.addVulnerability(v1, c1, "none");
        qm.addVulnerability(v2, c2, "none");
        qm.addVulnerability(v3, c3, "none");

        // Test filtering grouped findings by EPSS percentile range
        Response response = jersey.target(V1_FINDING + "/grouped")
                .queryParam("epssPercentileFrom", "0.5")
                .queryParam("epssPercentileTo", "0.7")
                .request()
                .header(X_API_KEY, apiKey)
                .get(Response.class);
        Assertions.assertEquals(200, response.getStatus());
        Assertions.assertEquals("1", response.getHeaderString(TOTAL_COUNT_HEADER));
        JsonArray json = parseJsonArray(response);
        Assertions.assertNotNull(json);
        Assertions.assertEquals(1, json.size());
        Assertions.assertEquals("Vuln-2", json.getJsonObject(0).getJsonObject("vulnerability").getString("vulnId"));
    }

    @ParameterizedTest
    @MethodSource("getSARIFFindingsByProjectTestParameters")
    public void getSARIFFindingsByProjectTest(String query, String expectedResponsePath) throws Exception {
        initializeWithPermissions(Permissions.VIEW_VULNERABILITY);

        Project project = qm.createProject("Acme Example", null, "1.0", null, null, null, null, false);
        Component c1 = createComponent(project, "Component 1", "1.1.4");
        Component c2 = createComponent(project, "Component 2", "2.78.123");
        c1.setGroup("org.acme");
        c2.setGroup("com.xyz");
        c1.setPurl("pkg:maven/org.acme/component1@1.1.4?type=jar");
        c2.setPurl("pkg:maven/com.xyz/component2@2.78.123?type=jar");

        Vulnerability v1 = createVulnerability("Vuln-1", Severity.CRITICAL, "Vuln Title 1", "This is a description", null, 80, Vulnerability.Source.INTERNAL);
        Vulnerability v2 = createVulnerability("Vuln-2", Severity.HIGH, "Vuln Title 2", "   Yet another description but with surrounding whitespaces   ", "", 46, Vulnerability.Source.INTERNAL);
        Vulnerability v3 = createVulnerability("Vuln-3", Severity.LOW, "Vuln Title 3", "A description-with-hyphens-(and parentheses)", "  Recommendation with whitespaces  ", 23, Vulnerability.Source.INTERNAL);
        Vulnerability v4 = createVulnerability("Vuln-4", Severity.MEDIUM, "Vuln Title 4", "This is a vulnerability that has GITHUB Advisory as a source", null, 20, Vulnerability.Source.GITHUB);

        qm.addVulnerability(v1, c1, "none");
        qm.addVulnerability(v2, c1, "none");
        qm.addVulnerability(v3, c1, "none");
        qm.addVulnerability(v3, c2, "none");
        qm.addVulnerability(v4, c2, "none");

        var target = jersey.target(V1_FINDING + "/project/" + project.getUuid().toString());
        if (query != null) {
            target = target.queryParam("source", query);
        }
        Response response = target.request()
                .header(HttpHeaders.ACCEPT, MEDIA_TYPE_SARIF_JSON)
                .header(X_API_KEY, apiKey)
                .get(Response.class);

        assertEquals(200, response.getStatus(), 0);
        assertEquals(MEDIA_TYPE_SARIF_JSON, response.getHeaderString(HttpHeaders.CONTENT_TYPE));
        final String jsonResponse = getPlainTextBody(response);
        final String version = new About().getVersion();
        final String fullName = "OWASP Dependency-Track - " + version;
        String expectedTemplate = resourceToString(expectedResponsePath, StandardCharsets.UTF_8);
        String expected = expectedTemplate
                .replace("{{VERSION}}", version)
                .replace("{{FULL_NAME}}", fullName);
        assertThatJson(jsonResponse).isEqualTo(expected);
    }

    @Test
    public void getFindingsByProjectWithPaginationTest() {
        initializeWithPermissions(Permissions.VIEW_VULNERABILITY);

        Project p1 = qm.createProject("Acme Example", null, "1.0", null, null, null, null, false);

        for (int i = 0; i < 5; i++) {
            Component component = createComponent(p1, "Component "+i, "1.0."+i);
            Vulnerability vulnerability = createVulnerability("Vuln-"+i, Severity.LOW);
            qm.addVulnerability(vulnerability, component, "none");
        }

        Response response = jersey.target(V1_FINDING  + "/project/" + p1.getUuid())
                .queryParam("pageNumber", "1")
                .queryParam("pageSize", "3")
                .request()
                .header(X_API_KEY, apiKey)
                .get();
        assertThat(response.getStatus()).isEqualTo(200);
        assertThat(response.getHeaderString(TOTAL_COUNT_HEADER)).isEqualTo("5");
        JsonArray json = parseJsonArray(response);
        assertThat(json.size()).isEqualTo(3);
        assertThat(json.get(0).asJsonObject().getJsonObject("vulnerability").getString("vulnId")).isEqualTo("Vuln-0");
        assertThat(json.get(1).asJsonObject().getJsonObject("vulnerability").getString("vulnId")).isEqualTo("Vuln-1");
        assertThat(json.get(2).asJsonObject().getJsonObject("vulnerability").getString("vulnId")).isEqualTo("Vuln-2");

        response = jersey.target(V1_FINDING)
                .queryParam("pageNumber", "2")
                .queryParam("pageSize", "3")
                .request()
                .header(X_API_KEY, apiKey)
                .get();
        assertThat(response.getStatus()).isEqualTo(200);
        assertThat(response.getHeaderString(TOTAL_COUNT_HEADER)).isEqualTo("5");
        json = parseJsonArray(response);
        assertThat(json.size()).isEqualTo(2);
        assertThat(json.get(0).asJsonObject().getJsonObject("vulnerability").getString("vulnId")).isEqualTo("Vuln-3");
        assertThat(json.get(1).asJsonObject().getJsonObject("vulnerability").getString("vulnId")).isEqualTo("Vuln-4");

    }

    @Test
    public void getAllFindingsWithPaginationTest() {
        initializeWithPermissions(Permissions.VIEW_VULNERABILITY);

        Project p1 = qm.createProject("Acme Example", null, "1.0", null, null, null, null, false);

        for (int i = 0; i < 5; i++) {
            Component component = createComponent(p1, "Component "+i, "1.0."+i);
            Vulnerability vulnerability = createVulnerability("Vuln-"+i, Severity.LOW);
            qm.addVulnerability(vulnerability, component, "none");
        }

        Response response = jersey.target(V1_FINDING)
                .queryParam("pageNumber", "1")
                .queryParam("pageSize", "3")
                .request()
                .header(X_API_KEY, apiKey)
                .get();
        assertThat(response.getStatus()).isEqualTo(200);
        assertThat(response.getHeaderString(TOTAL_COUNT_HEADER)).isEqualTo("5");
        JsonArray json = parseJsonArray(response);
        assertThat(json.size()).isEqualTo(3);
        assertThat(json.get(0).asJsonObject().getJsonObject("vulnerability").getString("vulnId")).isEqualTo("Vuln-0");
        assertThat(json.get(1).asJsonObject().getJsonObject("vulnerability").getString("vulnId")).isEqualTo("Vuln-1");
        assertThat(json.get(2).asJsonObject().getJsonObject("vulnerability").getString("vulnId")).isEqualTo("Vuln-2");

        response = jersey.target(V1_FINDING)
                .queryParam("pageNumber", "2")
                .queryParam("pageSize", "3")
                .request()
                .header(X_API_KEY, apiKey)
                .get();
        assertThat(response.getStatus()).isEqualTo(200);
        assertThat(response.getHeaderString(TOTAL_COUNT_HEADER)).isEqualTo("5");
        json = parseJsonArray(response);
        assertThat(json.size()).isEqualTo(2);
        assertThat(json.get(0).asJsonObject().getJsonObject("vulnerability").getString("vulnId")).isEqualTo("Vuln-3");
        assertThat(json.get(1).asJsonObject().getJsonObject("vulnerability").getString("vulnId")).isEqualTo("Vuln-4");

    }

    @Test
    public void getAllGroupedFindingsWithPaginationTest() {
        initializeWithPermissions(Permissions.VIEW_VULNERABILITY);

        Project p1 = qm.createProject("Acme Example", null, "1.0", null, null, null, null, false);

        for (int i = 0; i < 5; i++) {
            Component component = createComponent(p1, "Component "+i, "1.0."+i);
            Vulnerability vulnerability = createVulnerability("Vuln-"+i, Severity.LOW);
            qm.addVulnerability(vulnerability, component, "none");
        }

        Response response = jersey.target(V1_FINDING + "/grouped")
                .queryParam("pageNumber", "1")
                .queryParam("pageSize", "3")
                .request()
                .header(X_API_KEY, apiKey)
                .get();
        assertThat(response.getStatus()).isEqualTo(200);
        assertThat(response.getHeaderString(TOTAL_COUNT_HEADER)).isEqualTo("5");
        JsonArray json = parseJsonArray(response);
        assertThat(json.size()).isEqualTo(3);
        assertThat(json.get(0).asJsonObject().getJsonObject("vulnerability").getString("vulnId")).isEqualTo("Vuln-0");
        assertThat(json.get(1).asJsonObject().getJsonObject("vulnerability").getString("vulnId")).isEqualTo("Vuln-1");
        assertThat(json.get(2).asJsonObject().getJsonObject("vulnerability").getString("vulnId")).isEqualTo("Vuln-2");

        response = jersey.target(V1_FINDING)
                .queryParam("pageNumber", "2")
                .queryParam("pageSize", "3")
                .request()
                .header(X_API_KEY, apiKey)
                .get();
        assertThat(response.getStatus()).isEqualTo(200);
        assertThat(response.getHeaderString(TOTAL_COUNT_HEADER)).isEqualTo("5");
        json = parseJsonArray(response);
        assertThat(json.size()).isEqualTo(2);
        assertThat(json.get(0).asJsonObject().getJsonObject("vulnerability").getString("vulnId")).isEqualTo("Vuln-3");
        assertThat(json.get(1).asJsonObject().getJsonObject("vulnerability").getString("vulnId")).isEqualTo("Vuln-4");

    }

    private static Stream<Arguments> getSARIFFindingsByProjectTestParameters() {
        return Stream.of(
                Arguments.of("INTERNAL", "/unit/sarif/expected-internal.sarif.json"),
                Arguments.of(null, "/unit/sarif/expected-all.sarif.json")
        );
    }

    private Component createComponent(Project project, String name, String version) {
        Component component = new Component();
        component.setProject(project);
        component.setName(name);
        component.setVersion(version);
        return qm.createComponent(component, false);
    }

    private Vulnerability createVulnerability(String vulnId, Severity severity) {
        Vulnerability vulnerability = new Vulnerability();
        vulnerability.setVulnId(vulnId);
        vulnerability.setSource(Vulnerability.Source.INTERNAL);
        vulnerability.setSeverity(severity);
        vulnerability.setCwes(List.of(80, 666));
        return qm.createVulnerability(vulnerability);
    }

    private Vulnerability createVulnerability(String vulnId, Severity severity, String title, String description, String recommendation, Integer cweId, Vulnerability.Source source) {
        Vulnerability vulnerability = new Vulnerability();
        vulnerability.setVulnId(vulnId);
        vulnerability.setSource(source);
        vulnerability.setSeverity(severity);
        vulnerability.setTitle(title);
        vulnerability.setDescription(description);
        vulnerability.setRecommendation(recommendation);
        vulnerability.setCwes(List.of(cweId));
        return qm.createVulnerability(vulnerability);
    }

    private Vulnerability createVulnerabilityWithEpss(String vulnId, Severity severity, BigDecimal epssScore) {
        Vulnerability vulnerability = new Vulnerability();
        vulnerability.setVulnId(vulnId);
        vulnerability.setSource(Vulnerability.Source.INTERNAL);
        vulnerability.setSeverity(severity);
        vulnerability.setCwes(List.of(80, 666));
        vulnerability = qm.createVulnerability(vulnerability);

        var epss = new Epss();
        epss.setCve(vulnId);
        epss.setScore(epssScore);
        qm.persist(epss);

        return vulnerability;
    }

    private Vulnerability createVulnerabilityWithEpssPercentile(String vulnId, Severity severity, BigDecimal epssPercentile) {
        Vulnerability vulnerability = new Vulnerability();
        vulnerability.setVulnId(vulnId);
        vulnerability.setSource(Vulnerability.Source.INTERNAL);
        vulnerability.setSeverity(severity);
        vulnerability.setCwes(List.of(80, 666));
        vulnerability = qm.createVulnerability(vulnerability);

        var epss = new Epss();
        epss.setCve(vulnId);
        epss.setPercentile(epssPercentile);
        qm.persist(epss);

        return vulnerability;
    }

}
