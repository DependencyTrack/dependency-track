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

import alpine.model.ManagedUser;
import alpine.server.auth.SessionTokenService;
import alpine.server.filters.ApiFilter;
import alpine.server.filters.AuthFeature;
import jakarta.json.Json;
import jakarta.json.JsonArray;
import jakarta.json.JsonObject;
import jakarta.ws.rs.client.Entity;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import org.apache.http.HttpStatus;
import org.dependencytrack.JerseyTestExtension;
import org.dependencytrack.ResourceTest;
import org.dependencytrack.auth.Permissions;
import org.dependencytrack.model.AnalysisJustification;
import org.dependencytrack.model.AnalysisResponse;
import org.dependencytrack.model.AnalysisState;
import org.dependencytrack.model.Component;
import org.dependencytrack.model.Project;
import org.dependencytrack.model.Severity;
import org.dependencytrack.model.Vulnerability;
import org.dependencytrack.notification.NotificationScope;
import org.dependencytrack.persistence.command.MakeAnalysisCommand;
import org.dependencytrack.persistence.jdbi.VulnerabilityPolicyDao;
import org.dependencytrack.persistence.jdbi.VulnerabilityPolicyDao.VulnPolicyIdentityRow;
import org.dependencytrack.policy.vulnerability.VulnerabilityPolicy;
import org.dependencytrack.policy.vulnerability.VulnerabilityPolicyAnalysis;
import org.dependencytrack.resources.v1.vo.AnalysisRequest;
import org.glassfish.jersey.server.ResourceConfig;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;

import java.util.EnumSet;
import java.util.List;
import java.util.UUID;
import java.util.function.Supplier;

import static net.javacrumbs.jsonunit.assertj.JsonAssertions.assertThatJson;
import static org.assertj.core.api.Assertions.assertThat;
import static org.dependencytrack.notification.NotificationTestUtil.createCatchAllNotificationRule;
import static org.dependencytrack.notification.proto.v1.Group.GROUP_PROJECT_AUDIT_CHANGE;
import static org.dependencytrack.notification.proto.v1.Level.LEVEL_INFORMATIONAL;
import static org.dependencytrack.notification.proto.v1.Scope.SCOPE_PORTFOLIO;
import static org.dependencytrack.persistence.jdbi.JdbiFactory.useJdbiHandle;
import static org.dependencytrack.persistence.jdbi.JdbiFactory.withJdbiHandle;

class AnalysisResourceTest extends ResourceTest {

    @RegisterExtension
    static JerseyTestExtension jersey = new JerseyTestExtension(
            new ResourceConfig(AnalysisResource.class)
                    .register(ApiFilter.class)
                    .register(AuthFeature.class));

    @Test
    void retrieveAnalysisTest() {
        initializeWithPermissions(Permissions.VIEW_VULNERABILITY);

        final Project project = qm.createProject("Acme Example", null, "1.0", null, null, null, null, false);

        var component = new Component();
        component.setProject(project);
        component.setName("Acme Component");
        component.setVersion("1.0");
        qm.createComponent(component, false);

        var vulnerability = new Vulnerability();
        vulnerability.setVulnId("INT-001");
        vulnerability.setSource(Vulnerability.Source.INTERNAL);
        vulnerability.setSeverity(Severity.HIGH);
        vulnerability.setComponents(List.of(component));
        vulnerability = qm.createVulnerability(vulnerability);

        qm.makeAnalysis(
                new MakeAnalysisCommand(component, vulnerability)
                        .withState(AnalysisState.NOT_AFFECTED)
                        .withJustification(AnalysisJustification.CODE_NOT_REACHABLE)
                        .withResponse(AnalysisResponse.WILL_NOT_FIX)
                        .withDetails("Analysis details here")
                        .withSuppress(true)
                        .withCommenter("Jane Doe")
                        .withComment("Analysis comment here")
                        .withOptions(EnumSet.of(
                                MakeAnalysisCommand.Option.OMIT_AUDIT_TRAIL,
                                MakeAnalysisCommand.Option.OMIT_NOTIFICATION)));

        final Response response = jersey.target(V1_ANALYSIS)
                .queryParam("project", project.getUuid())
                .queryParam("component", component.getUuid())
                .queryParam("vulnerability", vulnerability.getUuid())
                .request()
                .header(X_API_KEY, apiKey)
                .get(Response.class);
        assertThat(response.getStatus()).isEqualTo(HttpStatus.SC_OK);
        assertThat(response.getHeaderString(TOTAL_COUNT_HEADER)).isNull();

        final JsonObject responseJson = parseJsonObject(response);
        assertThat(responseJson).isNotNull();
        assertThat(responseJson.getString("analysisState")).isEqualTo(AnalysisState.NOT_AFFECTED.name());
        assertThat(responseJson.getString("analysisJustification")).isEqualTo(AnalysisJustification.CODE_NOT_REACHABLE.name());
        assertThat(responseJson.getString("analysisResponse")).isEqualTo(AnalysisResponse.WILL_NOT_FIX.name());
        assertThat(responseJson.getString("analysisDetails")).isEqualTo("Analysis details here");
        assertThat(responseJson.getJsonArray("analysisComments")).hasSize(1);
        assertThat(responseJson.getJsonArray("analysisComments").getJsonObject(0))
                .hasFieldOrPropertyWithValue("comment", Json.createValue("Analysis comment here"))
                .hasFieldOrPropertyWithValue("commenter", Json.createValue("Jane Doe"));
        assertThat(responseJson.getBoolean("isSuppressed")).isTrue();
    }

    @Test
    void retrieveAnalysisWithoutExistingAnalysisTest() {
        initializeWithPermissions(Permissions.VIEW_VULNERABILITY);

        final Project project = qm.createProject("Acme Example", null, "1.0", null, null, null, null, false);

        var component = new Component();
        component.setProject(project);
        component.setName("Acme Component");
        component.setVersion("1.0");
        component = qm.createComponent(component, false);

        var vulnerability = new Vulnerability();
        vulnerability.setVulnId("INT-001");
        vulnerability.setSource(Vulnerability.Source.INTERNAL);
        vulnerability.setSeverity(Severity.HIGH);
        vulnerability.setComponents(List.of(component));
        vulnerability = qm.createVulnerability(vulnerability);

        final Response response = jersey.target(V1_ANALYSIS)
                .queryParam("project", project.getUuid())
                .queryParam("component", component.getUuid())
                .queryParam("vulnerability", vulnerability.getUuid())
                .request()
                .header(X_API_KEY, apiKey)
                .get(Response.class);
        assertThat(response.getStatus()).isEqualTo(HttpStatus.SC_NOT_FOUND);
        assertThat(response.getHeaderString(TOTAL_COUNT_HEADER)).isNull();
        assertThat(getPlainTextBody(response)).isEqualTo("No analysis exists.");
    }

    @Test
    void noAnalysisExists() {
        initializeWithPermissions(Permissions.VIEW_VULNERABILITY);
        final Project project = qm.createProject("Acme Example", null, "1.0", null, null, null, null, false);

        var component = new Component();
        component.setProject(project);
        component.setName("Acme Component");
        component.setVersion("2.0");
        component = qm.createComponent(component, false);

        var vulnerability = new Vulnerability();
        vulnerability.setVulnId("INT-003");
        vulnerability.setSource(Vulnerability.Source.INTERNAL);
        vulnerability.setSeverity(Severity.HIGH);
        vulnerability.setComponents(List.of(component));
        vulnerability = qm.createVulnerability(vulnerability);

        final Response response = jersey.target(V1_ANALYSIS)
                .queryParam("component", component.getUuid())
                .queryParam("vulnerability", vulnerability.getUuid())
                .request()
                .header(X_API_KEY, apiKey)
                .get(Response.class);
        assertThat(response.getStatus()).isEqualTo(HttpStatus.SC_NOT_FOUND);
        assertThat(getPlainTextBody(response)).isEqualTo("No analysis exists.");
    }

    @Test
    void retrieveAnalysisWithProjectNotFoundTest() {
        initializeWithPermissions(Permissions.VIEW_VULNERABILITY);

        final Project project = qm.createProject("Acme Example", null, "1.0", null, null, null, null, false);

        var component = new Component();
        component.setProject(project);
        component.setName("Acme Component");
        component.setVersion("1.0");
        component = qm.createComponent(component, false);

        var vulnerability = new Vulnerability();
        vulnerability.setVulnId("INT-001");
        vulnerability.setSource(Vulnerability.Source.INTERNAL);
        vulnerability.setSeverity(Severity.HIGH);
        vulnerability.setComponents(List.of(component));
        vulnerability = qm.createVulnerability(vulnerability);

        final Response response = jersey.target(V1_ANALYSIS)
                .queryParam("project", UUID.randomUUID())
                .queryParam("component", component.getUuid())
                .queryParam("vulnerability", vulnerability.getUuid())
                .request()
                .header(X_API_KEY, apiKey)
                .get(Response.class);
        assertThat(response.getStatus()).isEqualTo(HttpStatus.SC_NOT_FOUND);
        assertThat(response.getHeaderString(TOTAL_COUNT_HEADER)).isNull();
        assertThat(getPlainTextBody(response)).isEqualTo("The project could not be found.");
    }

    @Test
    void retrieveAnalysisWithComponentNotFoundTest() {
        initializeWithPermissions(Permissions.VIEW_VULNERABILITY);

        final Project project = qm.createProject("Acme Example", null, "1.0", null, null, null, null, false);

        var component = new Component();
        component.setProject(project);
        component.setName("Acme Component");
        component.setVersion("1.0");
        component = qm.createComponent(component, false);

        var vulnerability = new Vulnerability();
        vulnerability.setVulnId("INT-001");
        vulnerability.setSource(Vulnerability.Source.INTERNAL);
        vulnerability.setSeverity(Severity.HIGH);
        vulnerability.setComponents(List.of(component));
        vulnerability = qm.createVulnerability(vulnerability);

        final Response response = jersey.target(V1_ANALYSIS)
                .queryParam("project", project.getUuid())
                .queryParam("component", UUID.randomUUID())
                .queryParam("vulnerability", vulnerability.getUuid())
                .request()
                .header(X_API_KEY, apiKey)
                .get(Response.class);
        assertThat(response.getStatus()).isEqualTo(HttpStatus.SC_NOT_FOUND);
        assertThat(response.getHeaderString(TOTAL_COUNT_HEADER)).isNull();
        assertThat(getPlainTextBody(response)).isEqualTo("The component could not be found.");
    }

    @Test
    void retrieveAnalysisWithVulnerabilityNotFoundTest() {
        initializeWithPermissions(Permissions.VIEW_VULNERABILITY);

        final Project project = qm.createProject("Acme Example", null, "1.0", null, null, null, null, false);

        var component = new Component();
        component.setProject(project);
        component.setName("Acme Component");
        component.setVersion("1.0");
        component = qm.createComponent(component, false);

        var vulnerability = new Vulnerability();
        vulnerability.setVulnId("INT-001");
        vulnerability.setSource(Vulnerability.Source.INTERNAL);
        vulnerability.setSeverity(Severity.HIGH);
        vulnerability.setComponents(List.of(component));
        vulnerability = qm.createVulnerability(vulnerability);

        final Response response = jersey.target(V1_ANALYSIS)
                .queryParam("project", project.getUuid())
                .queryParam("component", component.getUuid())
                .queryParam("vulnerability", UUID.randomUUID())
                .request()
                .header(X_API_KEY, apiKey)
                .get(Response.class);
        assertThat(response.getStatus()).isEqualTo(HttpStatus.SC_NOT_FOUND);
        assertThat(response.getHeaderString(TOTAL_COUNT_HEADER)).isNull();
        assertThat(getPlainTextBody(response)).isEqualTo("The vulnerability could not be found.");
    }

    @Test
    void retrieveAnalysisUnauthorizedTest() {
        final Response response = jersey.target(V1_ANALYSIS)
                .queryParam("project", UUID.randomUUID())
                .queryParam("component", UUID.randomUUID())
                .queryParam("vulnerability", UUID.randomUUID())
                .request()
                .header(X_API_KEY, apiKey)
                .get();
        assertThat(response.getStatus()).isEqualTo(HttpStatus.SC_FORBIDDEN);
        assertThat(response.getHeaderString(TOTAL_COUNT_HEADER)).isNull();
    }

    @Test
    void retrieveAnalysisWithAclTest() {
        enablePortfolioAccessControl();

        initializeWithPermissions(Permissions.VIEW_VULNERABILITY);

        final var project = new Project();
        project.setName("acme-app");
        qm.persist(project);

        final var component = new Component();
        component.setProject(project);
        component.setName("acme-lib");
        qm.persist(component);

        final var vuln = new Vulnerability();
        vuln.setVulnId("INT-001");
        vuln.setSource(Vulnerability.Source.INTERNAL);
        qm.persist(vuln);

        qm.makeAnalysis(
                new MakeAnalysisCommand(component, vuln)
                        .withState(AnalysisState.NOT_AFFECTED)
                        .withJustification(AnalysisJustification.CODE_NOT_REACHABLE)
                        .withResponse(AnalysisResponse.WILL_NOT_FIX)
                        .withDetails("Analysis details here")
                        .withSuppress(true));

        final Supplier<Response> responseSupplier = () -> jersey
                .target(V1_ANALYSIS)
                .queryParam("component", component.getUuid())
                .queryParam("vulnerability", vuln.getUuid())
                .request()
                .header(X_API_KEY, apiKey)
                .get();

        Response response = responseSupplier.get();
        assertThat(response.getStatus()).isEqualTo(HttpStatus.SC_FORBIDDEN);
        assertThat(response.getHeaderString(TOTAL_COUNT_HEADER)).isNull();
        assertThatJson(getPlainTextBody(response)).isEqualTo(/* language=JSON */ """
                {
                  "status": 403,
                  "title": "Project access denied",
                  "detail": "Access to the requested project is forbidden"
                }
                """);

        project.addAccessTeam(super.team);

        response = responseSupplier.get();
        assertThat(response.getStatus()).isEqualTo(HttpStatus.SC_OK);
        assertThat(response.getHeaderString(TOTAL_COUNT_HEADER)).isNull();
    }

    @Test
    void updateAnalysisCreateNewTest() {
        createCatchAllNotificationRule(qm, NotificationScope.PORTFOLIO);

        initializeWithPermissions(Permissions.VULNERABILITY_ANALYSIS);

        final Project project = qm.createProject("Acme Example", null, "1.0", null, null, null, null, false);

        var component = new Component();
        component.setProject(project);
        component.setName("Acme Component");
        component.setVersion("1.0");
        component = qm.createComponent(component, false);

        var vulnerability = new Vulnerability();
        vulnerability.setVulnId("INT-001");
        vulnerability.setSource(Vulnerability.Source.INTERNAL);
        vulnerability.setSeverity(Severity.HIGH);
        vulnerability.setComponents(List.of(component));
        vulnerability = qm.createVulnerability(vulnerability);

        final var analysisRequest = new AnalysisRequest(project.getUuid().toString(), component.getUuid().toString(),
                vulnerability.getUuid().toString(), AnalysisState.NOT_AFFECTED, AnalysisJustification.CODE_NOT_REACHABLE,
                AnalysisResponse.WILL_NOT_FIX, "Analysis details here", "Analysis comment here", true);

        final Response response = jersey.target(V1_ANALYSIS)
                .request()
                .header(X_API_KEY, apiKey)
                .put(Entity.entity(analysisRequest, MediaType.APPLICATION_JSON));
        assertThat(response.getStatus()).isEqualTo(HttpStatus.SC_OK);
        assertThat(response.getHeaderString(TOTAL_COUNT_HEADER)).isNull();

        final JsonObject responseJson = parseJsonObject(response);
        assertThat(responseJson).isNotNull();
        assertThat(responseJson.getString("analysisState")).isEqualTo(AnalysisState.NOT_AFFECTED.name());
        assertThat(responseJson.getString("analysisJustification")).isEqualTo(AnalysisJustification.CODE_NOT_REACHABLE.name());
        assertThat(responseJson.getString("analysisResponse")).isEqualTo(AnalysisResponse.WILL_NOT_FIX.name());
        assertThat(responseJson.getString("analysisDetails")).isEqualTo("Analysis details here");
        assertThat(responseJson.getJsonArray("analysisComments")).hasSize(6);
        assertThat(responseJson.getJsonArray("analysisComments").getJsonObject(0))
                .hasFieldOrPropertyWithValue("comment", Json.createValue("Analysis: NOT_SET → NOT_AFFECTED"))
                .hasFieldOrPropertyWithValue("commenter", Json.createValue("Test Users"));
        assertThat(responseJson.getJsonArray("analysisComments").getJsonObject(1))
                .hasFieldOrPropertyWithValue("comment", Json.createValue("Justification: NOT_SET → CODE_NOT_REACHABLE"))
                .hasFieldOrPropertyWithValue("commenter", Json.createValue("Test Users"));
        assertThat(responseJson.getJsonArray("analysisComments").getJsonObject(2))
                .hasFieldOrPropertyWithValue("comment", Json.createValue("Vendor Response: NOT_SET → WILL_NOT_FIX"))
                .hasFieldOrPropertyWithValue("commenter", Json.createValue("Test Users"));
        assertThat(responseJson.getJsonArray("analysisComments").getJsonObject(3))
                .hasFieldOrPropertyWithValue("comment", Json.createValue("Details: Analysis details here"))
                .hasFieldOrPropertyWithValue("commenter", Json.createValue("Test Users"));
        assertThat(responseJson.getJsonArray("analysisComments").getJsonObject(4))
                .hasFieldOrPropertyWithValue("comment", Json.createValue("Suppressed"))
                .hasFieldOrPropertyWithValue("commenter", Json.createValue("Test Users"));
        assertThat(responseJson.getJsonArray("analysisComments").getJsonObject(5))
                .hasFieldOrPropertyWithValue("comment", Json.createValue("Analysis comment here"))
                .hasFieldOrPropertyWithValue("commenter", Json.createValue("Test Users"));
        assertThat(responseJson.getBoolean("isSuppressed")).isTrue();

        assertThat(qm.getNotificationOutbox()).satisfiesExactly(notification -> {
            assertThat(notification.getScope()).isEqualTo(SCOPE_PORTFOLIO);
            assertThat(notification.getGroup()).isEqualTo(GROUP_PROJECT_AUDIT_CHANGE);
            assertThat(notification.getLevel()).isEqualTo(LEVEL_INFORMATIONAL);
            assertThat(notification.getTitle()).isEqualTo("Analysis Decision: NOT_AFFECTED");
            assertThat(notification.getContent()).isEqualTo("An analysis decision was made to a finding affecting a project");
        });
    }

    @Test
    void updateAnalysisCreateNewWithUserTest() {
        createCatchAllNotificationRule(qm, NotificationScope.PORTFOLIO);

        initializeWithPermissions(Permissions.VULNERABILITY_ANALYSIS);

        ManagedUser testUser = qm.createManagedUser("testuser", TEST_USER_PASSWORD_HASH);
        String sessionToken = new SessionTokenService().createSession(testUser.getId());
        qm.addUserToTeam(testUser, team);

        final Project project = qm.createProject("Acme Example", null, "1.0", null, null, null, null, false);

        var component = new Component();
        component.setProject(project);
        component.setName("Acme Component");
        component.setVersion("1.0");
        component = qm.createComponent(component, false);

        var vulnerability = new Vulnerability();
        vulnerability.setVulnId("INT-001");
        vulnerability.setSource(Vulnerability.Source.INTERNAL);
        vulnerability.setSeverity(Severity.HIGH);
        vulnerability.setComponents(List.of(component));
        vulnerability = qm.createVulnerability(vulnerability);

        final var analysisRequest = new AnalysisRequest(project.getUuid().toString(), component.getUuid().toString(),
                vulnerability.getUuid().toString(), AnalysisState.NOT_AFFECTED, AnalysisJustification.CODE_NOT_REACHABLE,
                AnalysisResponse.WILL_NOT_FIX, "Analysis details here", "Analysis comment here", true);

        final Response response = jersey.target(V1_ANALYSIS)
                .request()
                .header("Authorization", "Bearer " + sessionToken)
                .put(Entity.entity(analysisRequest, MediaType.APPLICATION_JSON));
        assertThat(response.getStatus()).isEqualTo(HttpStatus.SC_OK);
        assertThat(response.getHeaderString(TOTAL_COUNT_HEADER)).isNull();

        final JsonObject responseJson = parseJsonObject(response);
        assertThat(responseJson).isNotNull();
        assertThat(responseJson.getString("analysisState")).isEqualTo(AnalysisState.NOT_AFFECTED.name());
        assertThat(responseJson.getString("analysisJustification")).isEqualTo(AnalysisJustification.CODE_NOT_REACHABLE.name());
        assertThat(responseJson.getString("analysisResponse")).isEqualTo(AnalysisResponse.WILL_NOT_FIX.name());
        assertThat(responseJson.getString("analysisDetails")).isEqualTo("Analysis details here");
        assertThat(responseJson.getJsonArray("analysisComments")).hasSize(6);
        assertThat(responseJson.getJsonArray("analysisComments").getJsonObject(0))
                .hasFieldOrPropertyWithValue("comment", Json.createValue("Analysis: NOT_SET → NOT_AFFECTED"))
                .hasFieldOrPropertyWithValue("commenter", Json.createValue("testuser"));
        assertThat(responseJson.getJsonArray("analysisComments").getJsonObject(1))
                .hasFieldOrPropertyWithValue("comment", Json.createValue("Justification: NOT_SET → CODE_NOT_REACHABLE"))
                .hasFieldOrPropertyWithValue("commenter", Json.createValue("testuser"));
        assertThat(responseJson.getJsonArray("analysisComments").getJsonObject(2))
                .hasFieldOrPropertyWithValue("comment", Json.createValue("Vendor Response: NOT_SET → WILL_NOT_FIX"))
                .hasFieldOrPropertyWithValue("commenter", Json.createValue("testuser"));
        assertThat(responseJson.getJsonArray("analysisComments").getJsonObject(3))
                .hasFieldOrPropertyWithValue("comment", Json.createValue("Details: Analysis details here"))
                .hasFieldOrPropertyWithValue("commenter", Json.createValue("testuser"));
        assertThat(responseJson.getJsonArray("analysisComments").getJsonObject(4))
                .hasFieldOrPropertyWithValue("comment", Json.createValue("Suppressed"))
                .hasFieldOrPropertyWithValue("commenter", Json.createValue("testuser"));
        assertThat(responseJson.getJsonArray("analysisComments").getJsonObject(5))
                .hasFieldOrPropertyWithValue("comment", Json.createValue("Analysis comment here"))
                .hasFieldOrPropertyWithValue("commenter", Json.createValue("testuser"));
        assertThat(responseJson.getBoolean("isSuppressed")).isTrue();

        assertThat(qm.getNotificationOutbox()).satisfiesExactly(notification -> {
            assertThat(notification.getScope()).isEqualTo(SCOPE_PORTFOLIO);
            assertThat(notification.getGroup()).isEqualTo(GROUP_PROJECT_AUDIT_CHANGE);
            assertThat(notification.getLevel()).isEqualTo(LEVEL_INFORMATIONAL);
            assertThat(notification.getTitle()).isEqualTo("Analysis Decision: NOT_AFFECTED");
            assertThat(notification.getContent()).isEqualTo("An analysis decision was made to a finding affecting a project");
        });
    }

    @Test
    void updateAnalysisCreateNewWithEmptyRequestTest() {
        initializeWithPermissions(Permissions.VULNERABILITY_ANALYSIS);

        final Project project = qm.createProject("Acme Example", null, "1.0", null, null, null, null, false);

        var component = new Component();
        component.setProject(project);
        component.setName("Acme Component");
        component.setVersion("1.0");
        component = qm.createComponent(component, false);

        var vulnerability = new Vulnerability();
        vulnerability.setVulnId("INT-001");
        vulnerability.setSource(Vulnerability.Source.INTERNAL);
        vulnerability.setSeverity(Severity.HIGH);
        vulnerability.setComponents(List.of(component));
        vulnerability = qm.createVulnerability(vulnerability);

        final var analysisRequest = new AnalysisRequest(project.getUuid().toString(), component.getUuid().toString(),
                vulnerability.getUuid().toString(), null, null, null, null, null, null);

        final Response response = jersey.target(V1_ANALYSIS)
                .request()
                .header(X_API_KEY, apiKey)
                .put(Entity.entity(analysisRequest, MediaType.APPLICATION_JSON));
        assertThat(response.getStatus()).isEqualTo(HttpStatus.SC_OK);
        assertThat(response.getHeaderString(TOTAL_COUNT_HEADER)).isNull();

        final JsonObject responseJson = parseJsonObject(response);
        assertThat(responseJson).isNotNull();
        assertThat(responseJson.getString("analysisState")).isEqualTo(AnalysisState.NOT_SET.name());
        assertThat(responseJson.getString("analysisJustification")).isEqualTo(AnalysisJustification.NOT_SET.name());
        assertThat(responseJson.getString("analysisResponse")).isEqualTo(AnalysisResponse.NOT_SET.name());
        assertThat(responseJson.getJsonString("analysisDetails")).isNull();
        assertThat(responseJson.getJsonArray("analysisComments")).isEmpty();
        assertThat(responseJson.getBoolean("isSuppressed")).isFalse();

        assertThat(qm.getNotificationOutbox()).isEmpty();
    }

    @Test
    void updateAnalysisUpdateExistingTest() {
        createCatchAllNotificationRule(qm, NotificationScope.PORTFOLIO);

        initializeWithPermissions(Permissions.VULNERABILITY_ANALYSIS);

        final Project project = qm.createProject("Acme Example", null, "1.0", null, null, null, null, false);

        var component = new Component();
        component.setProject(project);
        component.setName("Acme Component");
        component.setVersion("1.0");
        qm.createComponent(component, false);

        var vulnerability = new Vulnerability();
        vulnerability.setVulnId("INT-001");
        vulnerability.setSource(Vulnerability.Source.INTERNAL);
        vulnerability.setSeverity(Severity.HIGH);
        vulnerability.setComponents(List.of(component));
        vulnerability = qm.createVulnerability(vulnerability);

        qm.makeAnalysis(
                new MakeAnalysisCommand(component, vulnerability)
                        .withState(AnalysisState.NOT_AFFECTED)
                        .withJustification(AnalysisJustification.CODE_NOT_REACHABLE)
                        .withResponse(AnalysisResponse.WILL_NOT_FIX)
                        .withDetails("Analysis details here")
                        .withSuppress(true)
                        .withCommenter("Jane Doe")
                        .withComment("Analysis comment here")
                        .withOptions(EnumSet.of(
                                MakeAnalysisCommand.Option.OMIT_AUDIT_TRAIL,
                                MakeAnalysisCommand.Option.OMIT_NOTIFICATION)));

        final var analysisRequest = new AnalysisRequest(project.getUuid().toString(), component.getUuid().toString(),
                vulnerability.getUuid().toString(), AnalysisState.EXPLOITABLE, AnalysisJustification.NOT_SET,
                AnalysisResponse.UPDATE, "New analysis details here", "New analysis comment here", false);

        final Response response = jersey.target(V1_ANALYSIS)
                .request()
                .header(X_API_KEY, apiKey)
                .put(Entity.entity(analysisRequest, MediaType.APPLICATION_JSON));
        assertThat(response.getStatus()).isEqualTo(HttpStatus.SC_OK);
        assertThat(response.getHeaderString(TOTAL_COUNT_HEADER)).isNull();

        final JsonObject responseJson = parseJsonObject(response);
        assertThat(responseJson).isNotNull();
        assertThat(responseJson.getString("analysisState")).isEqualTo(AnalysisState.EXPLOITABLE.name());
        assertThat(responseJson.getString("analysisJustification")).isEqualTo(AnalysisJustification.NOT_SET.name());
        assertThat(responseJson.getString("analysisResponse")).isEqualTo(AnalysisResponse.UPDATE.name());
        assertThat(responseJson.getString("analysisDetails")).isEqualTo("New analysis details here");

        final JsonArray analysisComments = responseJson.getJsonArray("analysisComments");
        assertThat(analysisComments).hasSize(7);
        assertThat(analysisComments.getJsonObject(0))
                .hasFieldOrPropertyWithValue("comment", Json.createValue("Analysis comment here"))
                .hasFieldOrPropertyWithValue("commenter", Json.createValue("Jane Doe"));
        assertThat(analysisComments.getJsonObject(1))
                .hasFieldOrPropertyWithValue("comment", Json.createValue("Analysis: NOT_AFFECTED → EXPLOITABLE"))
                .hasFieldOrPropertyWithValue("commenter", Json.createValue("Test Users"));
        assertThat(analysisComments.getJsonObject(2))
                .hasFieldOrPropertyWithValue("comment", Json.createValue("Justification: CODE_NOT_REACHABLE → NOT_SET"))
                .hasFieldOrPropertyWithValue("commenter", Json.createValue("Test Users"));
        assertThat(analysisComments.getJsonObject(3))
                .hasFieldOrPropertyWithValue("comment", Json.createValue("Vendor Response: WILL_NOT_FIX → UPDATE"))
                .hasFieldOrPropertyWithValue("commenter", Json.createValue("Test Users"));
        assertThat(analysisComments.getJsonObject(4))
                .hasFieldOrPropertyWithValue("comment", Json.createValue("Details: New analysis details here"))
                .hasFieldOrPropertyWithValue("commenter", Json.createValue("Test Users"));
        assertThat(analysisComments.getJsonObject(5))
                .hasFieldOrPropertyWithValue("comment", Json.createValue("Unsuppressed"))
                .hasFieldOrPropertyWithValue("commenter", Json.createValue("Test Users"));
        assertThat(analysisComments.getJsonObject(6))
                .hasFieldOrPropertyWithValue("comment", Json.createValue("New analysis comment here"))
                .hasFieldOrPropertyWithValue("commenter", Json.createValue("Test Users"));
        assertThat(responseJson.getBoolean("isSuppressed")).isFalse();

        assertThat(qm.getNotificationOutbox()).satisfiesExactly(notification -> {
            assertThat(notification.getScope()).isEqualTo(SCOPE_PORTFOLIO);
            assertThat(notification.getGroup()).isEqualTo(GROUP_PROJECT_AUDIT_CHANGE);
            assertThat(notification.getLevel()).isEqualTo(LEVEL_INFORMATIONAL);
            assertThat(notification.getTitle()).isEqualTo("Analysis Decision: EXPLOITABLE");
            assertThat(notification.getContent()).isEqualTo("An analysis decision was made to a finding affecting a project");
        });
    }

    @Test
    void updateAnalysisWithNoChangesTest() {
        initializeWithPermissions(Permissions.VULNERABILITY_ANALYSIS);

        final Project project = qm.createProject("Acme Example", null, "1.0", null, null, null, null, false);

        var component = new Component();
        component.setProject(project);
        component.setName("Acme Component");
        component.setVersion("1.0");
        qm.createComponent(component, false);

        var vulnerability = new Vulnerability();
        vulnerability.setVulnId("INT-001");
        vulnerability.setSource(Vulnerability.Source.INTERNAL);
        vulnerability.setSeverity(Severity.HIGH);
        vulnerability.setComponents(List.of(component));
        vulnerability = qm.createVulnerability(vulnerability);

        qm.makeAnalysis(
                new MakeAnalysisCommand(component, vulnerability)
                        .withState(AnalysisState.NOT_AFFECTED)
                        .withJustification(AnalysisJustification.CODE_NOT_REACHABLE)
                        .withResponse(AnalysisResponse.WILL_NOT_FIX)
                        .withDetails("Analysis details here")
                        .withSuppress(true)
                        .withCommenter("Jane Doe")
                        .withComment("Analysis comment here")
                        .withOptions(EnumSet.of(
                                MakeAnalysisCommand.Option.OMIT_AUDIT_TRAIL,
                                MakeAnalysisCommand.Option.OMIT_NOTIFICATION)));

        final var analysisRequest = new AnalysisRequest(project.getUuid().toString(), component.getUuid().toString(),
                vulnerability.getUuid().toString(), AnalysisState.NOT_AFFECTED, AnalysisJustification.CODE_NOT_REACHABLE,
                AnalysisResponse.WILL_NOT_FIX, "Analysis details here", null, true);

        final Response response = jersey.target(V1_ANALYSIS)
                .request()
                .header(X_API_KEY, apiKey)
                .put(Entity.entity(analysisRequest, MediaType.APPLICATION_JSON));
        assertThat(response.getStatus()).isEqualTo(HttpStatus.SC_OK);
        assertThat(response.getHeaderString(TOTAL_COUNT_HEADER)).isNull();

        final JsonObject responseJson = parseJsonObject(response);
        assertThat(responseJson).isNotNull();
        assertThat(responseJson.getString("analysisState")).isEqualTo(AnalysisState.NOT_AFFECTED.name());
        assertThat(responseJson.getString("analysisJustification")).isEqualTo(AnalysisJustification.CODE_NOT_REACHABLE.name());
        assertThat(responseJson.getString("analysisResponse")).isEqualTo(AnalysisResponse.WILL_NOT_FIX.name());
        assertThat(responseJson.getString("analysisDetails")).isEqualTo("Analysis details here");

        final JsonArray analysisComments = responseJson.getJsonArray("analysisComments");
        assertThat(analysisComments).hasSize(2);
        assertThat(analysisComments.getJsonObject(0))
                .hasFieldOrPropertyWithValue("comment", Json.createValue("Analysis comment here"))
                .hasFieldOrPropertyWithValue("commenter", Json.createValue("Jane Doe"));
        assertThat(analysisComments.getJsonObject(0))
                .hasFieldOrPropertyWithValue("comment", Json.createValue("Analysis comment here"))
                .hasFieldOrPropertyWithValue("commenter", Json.createValue("Jane Doe"));

        assertThat(qm.getNotificationOutbox()).isEmpty();
    }

    @Test
    void updateAnalysisUpdateExistingWithEmptyRequestTest() {
        createCatchAllNotificationRule(qm, NotificationScope.PORTFOLIO);

        initializeWithPermissions(Permissions.VULNERABILITY_ANALYSIS);

        final Project project = qm.createProject("Acme Example", null, "1.0", null, null, null, null, false);

        var component = new Component();
        component.setProject(project);
        component.setName("Acme Component");
        component.setVersion("1.0");
        qm.createComponent(component, false);

        var vulnerability = new Vulnerability();
        vulnerability.setVulnId("INT-001");
        vulnerability.setSource(Vulnerability.Source.INTERNAL);
        vulnerability.setSeverity(Severity.HIGH);
        vulnerability.setComponents(List.of(component));
        vulnerability = qm.createVulnerability(vulnerability);

        qm.makeAnalysis(
                new MakeAnalysisCommand(component, vulnerability)
                        .withState(AnalysisState.NOT_AFFECTED)
                        .withJustification(AnalysisJustification.CODE_NOT_REACHABLE)
                        .withResponse(AnalysisResponse.WILL_NOT_FIX)
                        .withDetails("Analysis details here")
                        .withSuppress(true)
                        .withCommenter("Jane Doe")
                        .withComment("Analysis comment here")
                        .withOptions(EnumSet.of(
                                MakeAnalysisCommand.Option.OMIT_AUDIT_TRAIL,
                                MakeAnalysisCommand.Option.OMIT_NOTIFICATION)));

        final var analysisRequest = new AnalysisRequest(project.getUuid().toString(), component.getUuid().toString(),
                vulnerability.getUuid().toString(), null, null, null, null, null, null);

        final Response response = jersey.target(V1_ANALYSIS)
                .request()
                .header(X_API_KEY, apiKey)
                .put(Entity.entity(analysisRequest, MediaType.APPLICATION_JSON));
        assertThat(response.getStatus()).isEqualTo(HttpStatus.SC_OK);
        assertThat(response.getHeaderString(TOTAL_COUNT_HEADER)).isNull();

        final JsonObject responseJson = parseJsonObject(response);
        assertThat(responseJson).isNotNull();
        assertThat(responseJson.getString("analysisState")).isEqualTo(AnalysisState.NOT_SET.name());
        assertThat(responseJson.getString("analysisJustification")).isEqualTo(AnalysisJustification.NOT_SET.name());
        assertThat(responseJson.getString("analysisResponse")).isEqualTo(AnalysisResponse.NOT_SET.name());
        assertThat(responseJson.getString("analysisDetails")).isEqualTo("Analysis details here");

        final JsonArray analysisComments = responseJson.getJsonArray("analysisComments");
        assertThat(analysisComments).hasSize(4);
        assertThat(analysisComments.getJsonObject(0))
                .hasFieldOrPropertyWithValue("comment", Json.createValue("Analysis comment here"))
                .hasFieldOrPropertyWithValue("commenter", Json.createValue("Jane Doe"));
        assertThat(analysisComments.getJsonObject(1))
                .hasFieldOrPropertyWithValue("comment", Json.createValue("Analysis: NOT_AFFECTED → NOT_SET"))
                .hasFieldOrPropertyWithValue("commenter", Json.createValue("Test Users"));
        assertThat(analysisComments.getJsonObject(2))
                .hasFieldOrPropertyWithValue("comment", Json.createValue("Justification: CODE_NOT_REACHABLE → NOT_SET"))
                .hasFieldOrPropertyWithValue("commenter", Json.createValue("Test Users"));
        assertThat(analysisComments.getJsonObject(3))
                .hasFieldOrPropertyWithValue("comment", Json.createValue("Vendor Response: WILL_NOT_FIX → NOT_SET"))
                .hasFieldOrPropertyWithValue("commenter", Json.createValue("Test Users"));

        assertThat(qm.getNotificationOutbox()).satisfiesExactly(notification -> {
            assertThat(notification.getScope()).isEqualTo(SCOPE_PORTFOLIO);
            assertThat(notification.getGroup()).isEqualTo(GROUP_PROJECT_AUDIT_CHANGE);
            assertThat(notification.getLevel()).isEqualTo(LEVEL_INFORMATIONAL);
            assertThat(notification.getTitle()).isEqualTo("Analysis Decision: NOT_SET");
            assertThat(notification.getContent()).isEqualTo("An analysis decision was made to a finding affecting a project");
        });
    }

    @Test
    void updateAnalysisWithComponentNotFoundTest() {
        initializeWithPermissions(Permissions.VULNERABILITY_ANALYSIS);

        final Project project = qm.createProject("Acme Example", null, "1.0", null, null, null, null, false);

        var component = new Component();
        component.setProject(project);
        component.setName("Acme Component");
        component.setVersion("1.0");
        component = qm.createComponent(component, false);

        var vulnerability = new Vulnerability();
        vulnerability.setVulnId("INT-001");
        vulnerability.setSource(Vulnerability.Source.INTERNAL);
        vulnerability.setSeverity(Severity.HIGH);
        vulnerability.setComponents(List.of(component));
        vulnerability = qm.createVulnerability(vulnerability);

        final var analysisRequest = new AnalysisRequest(project.getUuid().toString(), UUID.randomUUID().toString(),
                vulnerability.getUuid().toString(), AnalysisState.NOT_AFFECTED, AnalysisJustification.CODE_NOT_REACHABLE,
                AnalysisResponse.WILL_NOT_FIX, "Analysis details here", "Analysis comment here", true);

        final Response response = jersey.target(V1_ANALYSIS)
                .request()
                .header(X_API_KEY, apiKey)
                .put(Entity.entity(analysisRequest, MediaType.APPLICATION_JSON));
        assertThat(response.getStatus()).isEqualTo(HttpStatus.SC_NOT_FOUND);
        assertThat(response.getHeaderString(TOTAL_COUNT_HEADER)).isNull();
        assertThat(getPlainTextBody(response)).isEqualTo("The component could not be found.");
    }

    @Test
    void updateAnalysisWithVulnerabilityNotFoundTest() {
        initializeWithPermissions(Permissions.VULNERABILITY_ANALYSIS);

        final Project project = qm.createProject("Acme Example", null, "1.0", null, null, null, null, false);

        var component = new Component();
        component.setProject(project);
        component.setName("Acme Component");
        component.setVersion("1.0");
        component = qm.createComponent(component, false);

        var vulnerability = new Vulnerability();
        vulnerability.setVulnId("INT-001");
        vulnerability.setSource(Vulnerability.Source.INTERNAL);
        vulnerability.setSeverity(Severity.HIGH);
        vulnerability.setComponents(List.of(component));
        vulnerability = qm.createVulnerability(vulnerability);

        final var analysisRequest = new AnalysisRequest(project.getUuid().toString(), component.getUuid().toString(),
                UUID.randomUUID().toString(), AnalysisState.NOT_AFFECTED, AnalysisJustification.CODE_NOT_REACHABLE,
                AnalysisResponse.WILL_NOT_FIX, "Analysis details here", "Analysis comment here", true);

        final Response response = jersey.target(V1_ANALYSIS)
                .request()
                .header(X_API_KEY, apiKey)
                .put(Entity.entity(analysisRequest, MediaType.APPLICATION_JSON));
        assertThat(response.getStatus()).isEqualTo(HttpStatus.SC_NOT_FOUND);
        assertThat(response.getHeaderString(TOTAL_COUNT_HEADER)).isNull();
        assertThat(getPlainTextBody(response)).isEqualTo("The vulnerability could not be found.");
    }

    // Test the scenario where an analysis was created with Dependency-Track <= 4.3.6,
    // before the additional fields "analysisJustification" and "analysisResponse" were introduced.
    // Performing an analysis with those request fields set in >= 4.4.0 then resulted in NPEs,
    // see https://github.com/DependencyTrack/dependency-track/issues/1409
    @Test
    void updateAnalysisIssue1409Test() {
        createCatchAllNotificationRule(qm, NotificationScope.PORTFOLIO);

        initializeWithPermissions(Permissions.VULNERABILITY_ANALYSIS);

        final Project project = qm.createProject("Acme Example", null, "1.0", null, null, null, null, false);

        final var component = new Component();
        component.setProject(project);
        component.setName("Acme Component");
        component.setVersion("1.0");
        qm.createComponent(component, false);

        var vulnerability = new Vulnerability();
        vulnerability.setVulnId("INT-001");
        vulnerability.setSource(Vulnerability.Source.INTERNAL);
        vulnerability.setSeverity(Severity.HIGH);
        vulnerability.setComponents(List.of(component));
        vulnerability = qm.createVulnerability(vulnerability);

        qm.makeAnalysis(
                new MakeAnalysisCommand(component, vulnerability)
                        .withState(AnalysisState.IN_TRIAGE)
                        .withOptions(EnumSet.of(
                                MakeAnalysisCommand.Option.OMIT_AUDIT_TRAIL,
                                MakeAnalysisCommand.Option.OMIT_NOTIFICATION)));

        final var analysisRequest = new AnalysisRequest(project.getUuid().toString(), component.getUuid().toString(),
                vulnerability.getUuid().toString(), AnalysisState.NOT_AFFECTED, AnalysisJustification.PROTECTED_BY_MITIGATING_CONTROL,
                AnalysisResponse.UPDATE, "New analysis details here", "New analysis comment here", false);

        final Response response = jersey.target(V1_ANALYSIS)
                .request()
                .header(X_API_KEY, apiKey)
                .put(Entity.entity(analysisRequest, MediaType.APPLICATION_JSON));
        assertThat(response.getStatus()).isEqualTo(HttpStatus.SC_OK);
        assertThat(response.getHeaderString(TOTAL_COUNT_HEADER)).isNull();

        final JsonObject responseJson = parseJsonObject(response);
        assertThat(responseJson).isNotNull();
        assertThat(responseJson.getString("analysisState")).isEqualTo(AnalysisState.NOT_AFFECTED.name());
        assertThat(responseJson.getString("analysisJustification")).isEqualTo(AnalysisJustification.PROTECTED_BY_MITIGATING_CONTROL.name());
        assertThat(responseJson.getString("analysisResponse")).isEqualTo(AnalysisResponse.UPDATE.name());
        assertThat(responseJson.getString("analysisDetails")).isEqualTo("New analysis details here");

        final JsonArray analysisComments = responseJson.getJsonArray("analysisComments");
        assertThat(analysisComments).hasSize(5);
        assertThat(analysisComments.getJsonObject(0))
                .hasFieldOrPropertyWithValue("comment", Json.createValue("Analysis: IN_TRIAGE → NOT_AFFECTED"))
                .hasFieldOrPropertyWithValue("commenter", Json.createValue("Test Users"));
        assertThat(analysisComments.getJsonObject(1))
                .hasFieldOrPropertyWithValue("comment", Json.createValue("Justification: NOT_SET → PROTECTED_BY_MITIGATING_CONTROL"))
                .hasFieldOrPropertyWithValue("commenter", Json.createValue("Test Users"));
        assertThat(analysisComments.getJsonObject(2))
                .hasFieldOrPropertyWithValue("comment", Json.createValue("Vendor Response: NOT_SET → UPDATE"))
                .hasFieldOrPropertyWithValue("commenter", Json.createValue("Test Users"));
        assertThat(analysisComments.getJsonObject(3))
                .hasFieldOrPropertyWithValue("comment", Json.createValue("Details: New analysis details here"))
                .hasFieldOrPropertyWithValue("commenter", Json.createValue("Test Users"));
        assertThat(analysisComments.getJsonObject(4))
                .hasFieldOrPropertyWithValue("comment", Json.createValue("New analysis comment here"))
                .hasFieldOrPropertyWithValue("commenter", Json.createValue("Test Users"));
        assertThat(responseJson.getBoolean("isSuppressed")).isFalse();

        assertThat(qm.getNotificationOutbox()).satisfiesExactly(notification -> {
            assertThat(notification.getScope()).isEqualTo(SCOPE_PORTFOLIO);
            assertThat(notification.getGroup()).isEqualTo(GROUP_PROJECT_AUDIT_CHANGE);
            assertThat(notification.getLevel()).isEqualTo(LEVEL_INFORMATIONAL);
            assertThat(notification.getTitle()).isEqualTo("Analysis Decision: NOT_AFFECTED");
            assertThat(notification.getContent()).isEqualTo("An analysis decision was made to a finding affecting a project");
        });
    }

    @Test
    void updateAnalysisUnauthorizedTest() {
        final var analysisRequest = new AnalysisRequest(UUID.randomUUID().toString(), UUID.randomUUID().toString(),
                UUID.randomUUID().toString(), AnalysisState.NOT_AFFECTED, AnalysisJustification.PROTECTED_BY_MITIGATING_CONTROL,
                AnalysisResponse.UPDATE, "Analysis details here", "Analysis comment here", false);

        final Response response = jersey.target(V1_ANALYSIS)
                .request()
                .header(X_API_KEY, apiKey)
                .put(Entity.entity(analysisRequest, MediaType.APPLICATION_JSON));
        assertThat(response.getStatus()).isEqualTo(HttpStatus.SC_FORBIDDEN);
        assertThat(response.getHeaderString(TOTAL_COUNT_HEADER)).isNull();
    }

    @Test
    void updateAnalysisWithAclTest() {
        enablePortfolioAccessControl();

        initializeWithPermissions(Permissions.VULNERABILITY_ANALYSIS);

        final var project = new Project();
        project.setName("acme-app");
        qm.persist(project);

        final var component = new Component();
        component.setProject(project);
        component.setName("acme-lib");
        qm.persist(component);

        final var vuln = new Vulnerability();
        vuln.setVulnId("INT-001");
        vuln.setSource(Vulnerability.Source.INTERNAL);
        qm.persist(vuln);

        final Supplier<Response> responseSupplier = () -> jersey
                .target(V1_ANALYSIS)
                .request()
                .header(X_API_KEY, apiKey)
                .put(Entity.json(/* language=JSON */ """
                        {
                          "project": "%s",
                          "component": "%s",
                          "vulnerability": "%s",
                          "comment": "bar"
                        }
                        """.formatted(project.getUuid(), component.getUuid(), vuln.getUuid())));

        Response response = responseSupplier.get();
        assertThat(response.getStatus()).isEqualTo(HttpStatus.SC_FORBIDDEN);
        assertThat(response.getHeaderString(TOTAL_COUNT_HEADER)).isNull();
        assertThatJson(getPlainTextBody(response)).isEqualTo(/* language=JSON */ """
                {
                  "status": 403,
                  "title": "Project access denied",
                  "detail": "Access to the requested project is forbidden"
                }
                """);

        project.addAccessTeam(super.team);

        response = responseSupplier.get();
        assertThat(response.getStatus()).isEqualTo(HttpStatus.SC_OK);
        assertThat(response.getHeaderString(TOTAL_COUNT_HEADER)).isNull();
    }

    @Test
    void updateAnalysisWithAssociatedVulnerabilityPolicyTest() {
        initializeWithPermissions(Permissions.VULNERABILITY_ANALYSIS);

        final var project = new Project();
        project.setName("acme-app");
        qm.persist(project);

        final var component = new Component();
        component.setProject(project);
        component.setName("acme-lib");
        qm.persist(component);

        final var vuln = new Vulnerability();
        vuln.setVulnId("CVE-123");
        vuln.setSource(Vulnerability.Source.NVD);
        qm.persist(vuln);

        qm.addVulnerability(vuln, component, "internal");
        final long analysisId = qm.makeAnalysis(
                new MakeAnalysisCommand(component, vuln)
                        .withState(AnalysisState.NOT_AFFECTED)
                        .withSuppress(true));

        final VulnPolicyIdentityRow vulnPolicy = withJdbiHandle(handle -> {
            final var policyAnalysis = new VulnerabilityPolicyAnalysis();
            policyAnalysis.setState(VulnerabilityPolicyAnalysis.State.EXPLOITABLE);

            final var policy = new VulnerabilityPolicy();
            policy.setName("foo");
            policy.setAnalysis(policyAnalysis);
            policy.setCondition("true");
            return handle.attach(VulnerabilityPolicyDao.class).create(policy);
        });

        useJdbiHandle(handle -> handle.createUpdate("""
                        WITH "VULN_POLICY" AS (
                          SELECT "ID"
                            FROM "VULNERABILITY_POLICY"
                           WHERE "NAME" = :policyName
                        )
                        UPDATE "ANALYSIS"
                           SET "VULNERABILITY_POLICY_ID" = (SELECT "ID" FROM "VULN_POLICY")
                         WHERE "ID" = :analysisId
                        """)
                .bind("policyName", vulnPolicy.name())
                .bind("analysisId", analysisId)
                .execute());

        final Response response = jersey.target(V1_ANALYSIS)
                .request()
                .header(X_API_KEY, apiKey)
                .put(Entity.entity("""
                        {
                          "project": "%s",
                          "component": "%s",
                          "vulnerability": "%s",
                          "comment": "foo"
                        }
                        """.formatted(project.getUuid(), component.getUuid(), vuln.getUuid()), MediaType.APPLICATION_JSON));
        assertThat(response.getStatus()).isEqualTo(200);
    }

}
