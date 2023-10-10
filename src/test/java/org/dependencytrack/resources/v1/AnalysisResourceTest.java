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

import alpine.notification.Notification;
import alpine.notification.NotificationLevel;
import alpine.notification.NotificationService;
import alpine.notification.Subscriber;
import alpine.notification.Subscription;
import alpine.server.filters.ApiFilter;
import alpine.server.filters.AuthenticationFilter;
import alpine.server.filters.AuthorizationFilter;
import net.jcip.annotations.NotThreadSafe;
import org.apache.http.HttpStatus;
import org.dependencytrack.ResourceTest;
import org.dependencytrack.auth.Permissions;
import org.dependencytrack.model.Analysis;
import org.dependencytrack.model.AnalysisJustification;
import org.dependencytrack.model.AnalysisResponse;
import org.dependencytrack.model.AnalysisState;
import org.dependencytrack.model.Component;
import org.dependencytrack.model.Project;
import org.dependencytrack.model.Severity;
import org.dependencytrack.model.Vulnerability;
import org.dependencytrack.notification.NotificationConstants;
import org.dependencytrack.notification.NotificationGroup;
import org.dependencytrack.notification.NotificationScope;
import org.dependencytrack.resources.v1.vo.AnalysisRequest;
import org.dependencytrack.util.NotificationUtil;
import org.glassfish.jersey.server.ResourceConfig;
import org.glassfish.jersey.servlet.ServletContainer;
import org.glassfish.jersey.test.DeploymentContext;
import org.glassfish.jersey.test.ServletDeploymentContext;
import org.junit.AfterClass;
import org.junit.BeforeClass;
import org.junit.Test;

import javax.json.Json;
import javax.json.JsonArray;
import javax.json.JsonObject;
import javax.ws.rs.client.Entity;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;
import java.time.Duration;
import java.util.List;
import java.util.UUID;
import java.util.concurrent.ConcurrentLinkedQueue;

import static org.assertj.core.api.Assertions.assertThat;
import static org.dependencytrack.assertion.Assertions.assertConditionWithTimeout;

@NotThreadSafe
public class AnalysisResourceTest extends ResourceTest {

    @Override
    protected DeploymentContext configureDeployment() {
        return ServletDeploymentContext.forServlet(new ServletContainer(
                        new ResourceConfig(AnalysisResource.class)
                                .register(ApiFilter.class)
                                .register(AuthenticationFilter.class)
                                .register(AuthorizationFilter.class)))
                .build();
    }

    public static class NotificationSubscriber implements Subscriber {

        @Override
        public void inform(final Notification notification) {
            AnalysisResourceTest.NOTIFICATIONS.add(notification);
        }

    }

    private static final ConcurrentLinkedQueue<Notification> NOTIFICATIONS = new ConcurrentLinkedQueue<>();

    @BeforeClass
    public static void setUpClass() {
        NotificationService.getInstance().subscribe(new Subscription(NotificationSubscriber.class));
    }

    @AfterClass
    public static void tearDownClass() {
        NotificationService.getInstance().unsubscribe(new Subscription(NotificationSubscriber.class));
    }

    @Override
    public void tearDown() throws Exception {
        NOTIFICATIONS.clear();
        super.tearDown();
    }

    @Test
    public void retrieveAnalysisTest() {
        initializeWithPermissions(Permissions.VIEW_VULNERABILITY);

        final Project project = qm.createProject("Acme Example", null, "1.0", null, null, null, true, false);

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
        vulnerability = qm.createVulnerability(vulnerability, false);

        final Analysis analysis = qm.makeAnalysis(component, vulnerability, AnalysisState.NOT_AFFECTED,
                AnalysisJustification.CODE_NOT_REACHABLE, AnalysisResponse.WILL_NOT_FIX, "Analysis details here", true);
        qm.makeAnalysisComment(analysis, "Analysis comment here", "Jane Doe");

        final Response response = target(V1_ANALYSIS)
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
    public void retrieveAnalysisWithoutExistingAnalysisTest() {
        initializeWithPermissions(Permissions.VIEW_VULNERABILITY);

        final Project project = qm.createProject("Acme Example", null, "1.0", null, null, null, true, false);

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
        vulnerability = qm.createVulnerability(vulnerability, false);

        final Response response = target(V1_ANALYSIS)
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
    public void noAnalysisExists() {
        initializeWithPermissions(Permissions.VIEW_VULNERABILITY);
        final Project project = qm.createProject("Acme Example", null, "1.0", null, null, null, true, false);

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
        vulnerability = qm.createVulnerability(vulnerability, false);

        final Response response = target(V1_ANALYSIS)
                .queryParam("component", component.getUuid())
                .queryParam("vulnerability", vulnerability.getUuid())
                .request()
                .header(X_API_KEY, apiKey)
                .get(Response.class);
        assertThat(response.getStatus()).isEqualTo(HttpStatus.SC_NOT_FOUND);
        assertThat(getPlainTextBody(response)).isEqualTo("No analysis exists.");
    }

    @Test
    public void retrieveAnalysisWithProjectNotFoundTest() {
        initializeWithPermissions(Permissions.VIEW_VULNERABILITY);

        final Project project = qm.createProject("Acme Example", null, "1.0", null, null, null, true, false);

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
        vulnerability = qm.createVulnerability(vulnerability, false);

        final Response response = target(V1_ANALYSIS)
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
    public void retrieveAnalysisWithComponentNotFoundTest() {
        initializeWithPermissions(Permissions.VIEW_VULNERABILITY);

        final Project project = qm.createProject("Acme Example", null, "1.0", null, null, null, true, false);

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
        vulnerability = qm.createVulnerability(vulnerability, false);

        final Response response = target(V1_ANALYSIS)
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
    public void retrieveAnalysisWithVulnerabilityNotFoundTest() {
        initializeWithPermissions(Permissions.VIEW_VULNERABILITY);

        final Project project = qm.createProject("Acme Example", null, "1.0", null, null, null, true, false);

        var component = new Component();
        component.setProject(project);
        component.setName("Acme Component");
        component.setVersion("1.0");
        component = qm.createComponent(component, false);

        final var vulnerability = new Vulnerability();
        vulnerability.setVulnId("INT-001");
        vulnerability.setSource(Vulnerability.Source.INTERNAL);
        vulnerability.setSeverity(Severity.HIGH);
        vulnerability.setComponents(List.of(component));
        qm.createVulnerability(vulnerability, false);

        final Response response = target(V1_ANALYSIS)
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
    public void retrieveAnalysisUnauthorizedTest() {
        final Response response = target(V1_ANALYSIS)
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
    public void updateAnalysisCreateNewTest() throws Exception {
        initializeWithPermissions(Permissions.VULNERABILITY_ANALYSIS);

        final Project project = qm.createProject("Acme Example", null, "1.0", null, null, null, true, false);

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
        vulnerability = qm.createVulnerability(vulnerability, false);

        final var analysisRequest = new AnalysisRequest(project.getUuid().toString(), component.getUuid().toString(),
                vulnerability.getUuid().toString(), AnalysisState.NOT_AFFECTED, AnalysisJustification.CODE_NOT_REACHABLE,
                AnalysisResponse.WILL_NOT_FIX, "Analysis details here", "Analysis comment here", true);

        final Response response = target(V1_ANALYSIS)
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
        assertThat(responseJson.getJsonArray("analysisComments")).hasSize(2);
        assertThat(responseJson.getJsonArray("analysisComments").getJsonObject(0))
                .hasFieldOrPropertyWithValue("comment", Json.createValue("Analysis: NOT_SET → NOT_AFFECTED"))
                .doesNotContainKey("commenter"); // Not set when authenticating via API key
        assertThat(responseJson.getJsonArray("analysisComments").getJsonObject(1))
                .hasFieldOrPropertyWithValue("comment", Json.createValue("Analysis comment here"))
                .doesNotContainKey("commenter"); // Not set when authenticating via API key
        assertThat(responseJson.getBoolean("isSuppressed")).isTrue();

        assertConditionWithTimeout(() -> NOTIFICATIONS.size() == 2, Duration.ofSeconds(5));
        final Notification projectNotification = NOTIFICATIONS.poll();
        assertThat(projectNotification).isNotNull();
        final Notification notification = NOTIFICATIONS.poll();
        assertThat(notification).isNotNull();
        assertThat(notification.getScope()).isEqualTo(NotificationScope.PORTFOLIO.name());
        assertThat(notification.getGroup()).isEqualTo(NotificationGroup.PROJECT_AUDIT_CHANGE.name());
        assertThat(notification.getLevel()).isEqualTo(NotificationLevel.INFORMATIONAL);
        assertThat(notification.getTitle()).isEqualTo(NotificationUtil.generateNotificationTitle(NotificationConstants.Title.ANALYSIS_DECISION_NOT_AFFECTED, project));
        assertThat(notification.getContent()).isEqualTo("An analysis decision was made to a finding affecting a project");
    }

    @Test
    public void updateAnalysisCreateNewWithEmptyRequestTest() throws Exception {
        initializeWithPermissions(Permissions.VULNERABILITY_ANALYSIS);

        final Project project = qm.createProject("Acme Example", null, "1.0", null, null, null, true, false);

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
        vulnerability = qm.createVulnerability(vulnerability, false);

        final var analysisRequest = new AnalysisRequest(project.getUuid().toString(), component.getUuid().toString(),
                vulnerability.getUuid().toString(), null, null, null, null, null, null);

        final Response response = target(V1_ANALYSIS)
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

        assertConditionWithTimeout(() -> NOTIFICATIONS.size() == 2, Duration.ofSeconds(5));
        final Notification projectNotification = NOTIFICATIONS.poll();
        assertThat(projectNotification).isNotNull();
        final Notification notification = NOTIFICATIONS.poll();
        assertThat(notification).isNotNull();
        assertThat(notification.getScope()).isEqualTo(NotificationScope.PORTFOLIO.name());
        assertThat(notification.getGroup()).isEqualTo(NotificationGroup.PROJECT_AUDIT_CHANGE.name());
        assertThat(notification.getLevel()).isEqualTo(NotificationLevel.INFORMATIONAL);
        assertThat(notification.getTitle()).isEqualTo(NotificationUtil.generateNotificationTitle(NotificationConstants.Title.ANALYSIS_DECISION_NOT_SET, project));
        assertThat(notification.getContent()).isEqualTo("An analysis decision was made to a finding affecting a project");
    }

    @Test
    public void updateAnalysisUpdateExistingTest() throws Exception {
        initializeWithPermissions(Permissions.VULNERABILITY_ANALYSIS);

        final Project project = qm.createProject("Acme Example", null, "1.0", null, null, null, true, false);

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
        vulnerability = qm.createVulnerability(vulnerability, false);

        final Analysis analysis = qm.makeAnalysis(component, vulnerability, AnalysisState.NOT_AFFECTED,
                AnalysisJustification.CODE_NOT_REACHABLE, AnalysisResponse.WILL_NOT_FIX, "Analysis details here", true);
        qm.makeAnalysisComment(analysis, "Analysis comment here", "Jane Doe");

        final var analysisRequest = new AnalysisRequest(project.getUuid().toString(), component.getUuid().toString(),
                vulnerability.getUuid().toString(), AnalysisState.EXPLOITABLE, AnalysisJustification.NOT_SET,
                AnalysisResponse.UPDATE, "New analysis details here", "New analysis comment here", false);

        final Response response = target(V1_ANALYSIS)
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
                .doesNotContainKey("commenter"); // Not set when authenticating via API key
        assertThat(analysisComments.getJsonObject(2))
                .hasFieldOrPropertyWithValue("comment", Json.createValue("Justification: CODE_NOT_REACHABLE → NOT_SET"))
                .doesNotContainKey("commenter"); // Not set when authenticating via API key
        assertThat(analysisComments.getJsonObject(3))
                .hasFieldOrPropertyWithValue("comment", Json.createValue("Vendor Response: WILL_NOT_FIX → UPDATE"))
                .doesNotContainKey("commenter"); // Not set when authenticating via API key
        assertThat(analysisComments.getJsonObject(4))
                .hasFieldOrPropertyWithValue("comment", Json.createValue("Details: New analysis details here"))
                .doesNotContainKey("commenter"); // Not set when authenticating via API key
        assertThat(analysisComments.getJsonObject(5))
                .hasFieldOrPropertyWithValue("comment", Json.createValue("Unsuppressed"))
                .doesNotContainKey("commenter"); // Not set when authenticating via API key
        assertThat(analysisComments.getJsonObject(6))
                .hasFieldOrPropertyWithValue("comment", Json.createValue("New analysis comment here"))
                .doesNotContainKey("commenter"); // Not set when authenticating via API key
        assertThat(responseJson.getBoolean("isSuppressed")).isFalse();

        assertConditionWithTimeout(() -> NOTIFICATIONS.size() == 2, Duration.ofSeconds(5));
        final Notification projectNotification = NOTIFICATIONS.poll();
        assertThat(projectNotification).isNotNull();
        final Notification notification = NOTIFICATIONS.poll();
        assertThat(notification).isNotNull();
        assertThat(notification.getScope()).isEqualTo(NotificationScope.PORTFOLIO.name());
        assertThat(notification.getGroup()).isEqualTo(NotificationGroup.PROJECT_AUDIT_CHANGE.name());
        assertThat(notification.getLevel()).isEqualTo(NotificationLevel.INFORMATIONAL);
        assertThat(notification.getTitle()).isEqualTo(NotificationUtil.generateNotificationTitle(NotificationConstants.Title.ANALYSIS_DECISION_EXPLOITABLE, project));
        assertThat(notification.getContent()).isEqualTo("An analysis decision was made to a finding affecting a project");
    }

    @Test
    public void updateAnalysisWithNoChangesTest() throws Exception{
        initializeWithPermissions(Permissions.VULNERABILITY_ANALYSIS);

        final Project project = qm.createProject("Acme Example", null, "1.0", null, null, null, true, false);

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
        vulnerability = qm.createVulnerability(vulnerability, false);

        final Analysis analysis = qm.makeAnalysis(component, vulnerability, AnalysisState.NOT_AFFECTED,
                AnalysisJustification.CODE_NOT_REACHABLE, AnalysisResponse.WILL_NOT_FIX, "Analysis details here", true);
        qm.makeAnalysisComment(analysis, "Analysis comment here", "Jane Doe");

        final var analysisRequest = new AnalysisRequest(project.getUuid().toString(), component.getUuid().toString(),
                vulnerability.getUuid().toString(), AnalysisState.NOT_AFFECTED, AnalysisJustification.CODE_NOT_REACHABLE,
                AnalysisResponse.WILL_NOT_FIX, "Analysis details here", null, true);

        final Response response = target(V1_ANALYSIS)
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
        assertThat(analysisComments).hasSize(1);
        assertThat(analysisComments.getJsonObject(0))
                .hasFieldOrPropertyWithValue("comment", Json.createValue("Analysis comment here"))
                .hasFieldOrPropertyWithValue("commenter", Json.createValue("Jane Doe"));

        assertConditionWithTimeout(() -> NOTIFICATIONS.size() == 1, Duration.ofSeconds(5));
    }

    @Test
    public void updateAnalysisUpdateExistingWithEmptyRequestTest() throws Exception {
        initializeWithPermissions(Permissions.VULNERABILITY_ANALYSIS);

        final Project project = qm.createProject("Acme Example", null, "1.0", null, null, null, true, false);

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
        vulnerability = qm.createVulnerability(vulnerability, false);

        final Analysis analysis = qm.makeAnalysis(component, vulnerability, AnalysisState.NOT_AFFECTED,
                AnalysisJustification.CODE_NOT_REACHABLE, AnalysisResponse.WILL_NOT_FIX, "Analysis details here", true);
        qm.makeAnalysisComment(analysis, "Analysis comment here", "Jane Doe");

        final var analysisRequest = new AnalysisRequest(project.getUuid().toString(), component.getUuid().toString(),
                vulnerability.getUuid().toString(), null, null, null, null, null, null);

        final Response response = target(V1_ANALYSIS)
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
                .doesNotContainKey("commenter"); // Not set when authenticating via API key
        assertThat(analysisComments.getJsonObject(2))
                .hasFieldOrPropertyWithValue("comment", Json.createValue("Justification: CODE_NOT_REACHABLE → NOT_SET"))
                .doesNotContainKey("commenter"); // Not set when authenticating via API key
        assertThat(analysisComments.getJsonObject(3))
                .hasFieldOrPropertyWithValue("comment", Json.createValue("Vendor Response: WILL_NOT_FIX → NOT_SET"))
                .doesNotContainKey("commenter"); // Not set when authenticating via API key

        assertConditionWithTimeout(() -> NOTIFICATIONS.size() == 2, Duration.ofSeconds(5));
        final Notification projectNotification = NOTIFICATIONS.poll();
        assertThat(projectNotification).isNotNull();
        final Notification notification = NOTIFICATIONS.poll();
        assertThat(notification).isNotNull();
        assertThat(notification.getScope()).isEqualTo(NotificationScope.PORTFOLIO.name());
        assertThat(notification.getGroup()).isEqualTo(NotificationGroup.PROJECT_AUDIT_CHANGE.name());
        assertThat(notification.getLevel()).isEqualTo(NotificationLevel.INFORMATIONAL);
        assertThat(notification.getTitle()).isEqualTo(NotificationUtil.generateNotificationTitle(NotificationConstants.Title.ANALYSIS_DECISION_NOT_SET, project));
        assertThat(notification.getContent()).isEqualTo("An analysis decision was made to a finding affecting a project");
    }

    @Test
    public void updateAnalysisWithProjectNotFoundTest() {
        initializeWithPermissions(Permissions.VULNERABILITY_ANALYSIS);

        final Project project = qm.createProject("Acme Example", null, "1.0", null, null, null, true, false);

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
        vulnerability = qm.createVulnerability(vulnerability, false);

        final var analysisRequest = new AnalysisRequest(UUID.randomUUID().toString(), component.getUuid().toString(),
                vulnerability.getUuid().toString(), AnalysisState.NOT_AFFECTED, AnalysisJustification.CODE_NOT_REACHABLE,
                AnalysisResponse.WILL_NOT_FIX, "Analysis details here", "Analysis comment here", true);

        final Response response = target(V1_ANALYSIS)
                .request()
                .header(X_API_KEY, apiKey)
                .put(Entity.entity(analysisRequest, MediaType.APPLICATION_JSON));
        assertThat(response.getStatus()).isEqualTo(HttpStatus.SC_NOT_FOUND);
        assertThat(response.getHeaderString(TOTAL_COUNT_HEADER)).isNull();
        assertThat(getPlainTextBody(response)).isEqualTo("The project could not be found.");
    }

    @Test
    public void updateAnalysisWithComponentNotFoundTest() {
        initializeWithPermissions(Permissions.VULNERABILITY_ANALYSIS);

        final Project project = qm.createProject("Acme Example", null, "1.0", null, null, null, true, false);

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
        vulnerability = qm.createVulnerability(vulnerability, false);

        final var analysisRequest = new AnalysisRequest(project.getUuid().toString(), UUID.randomUUID().toString(),
                vulnerability.getUuid().toString(), AnalysisState.NOT_AFFECTED, AnalysisJustification.CODE_NOT_REACHABLE,
                AnalysisResponse.WILL_NOT_FIX, "Analysis details here", "Analysis comment here", true);

        final Response response = target(V1_ANALYSIS)
                .request()
                .header(X_API_KEY, apiKey)
                .put(Entity.entity(analysisRequest, MediaType.APPLICATION_JSON));
        assertThat(response.getStatus()).isEqualTo(HttpStatus.SC_NOT_FOUND);
        assertThat(response.getHeaderString(TOTAL_COUNT_HEADER)).isNull();
        assertThat(getPlainTextBody(response)).isEqualTo("The component could not be found.");
    }

    @Test
    public void updateAnalysisWithVulnerabilityNotFoundTest() {
        initializeWithPermissions(Permissions.VULNERABILITY_ANALYSIS);

        final Project project = qm.createProject("Acme Example", null, "1.0", null, null, null, true, false);

        var component = new Component();
        component.setProject(project);
        component.setName("Acme Component");
        component.setVersion("1.0");
        component = qm.createComponent(component, false);

        final var vulnerability = new Vulnerability();
        vulnerability.setVulnId("INT-001");
        vulnerability.setSource(Vulnerability.Source.INTERNAL);
        vulnerability.setSeverity(Severity.HIGH);
        vulnerability.setComponents(List.of(component));
        qm.createVulnerability(vulnerability, false);

        final var analysisRequest = new AnalysisRequest(project.getUuid().toString(), component.getUuid().toString(),
                UUID.randomUUID().toString(), AnalysisState.NOT_AFFECTED, AnalysisJustification.CODE_NOT_REACHABLE,
                AnalysisResponse.WILL_NOT_FIX, "Analysis details here", "Analysis comment here", true);

        final Response response = target(V1_ANALYSIS)
                .request()
                .header(X_API_KEY, apiKey)
                .put(Entity.entity(analysisRequest, MediaType.APPLICATION_JSON));
        assertThat(response.getStatus()).isEqualTo(HttpStatus.SC_NOT_FOUND);
        assertThat(response.getHeaderString(TOTAL_COUNT_HEADER)).isNull();
        assertThat(getPlainTextBody(response)).isEqualTo("The vulnerability could not be found.");
    }

    // Test the scenario where an analysis was created with Dependency-Track <= 4.3.6,
    // before the additional fields "justification" and "response" were introduced.
    // Performing an analysis with those request fields set in >= 4.4.0 then resulted in NPEs,
    // see https://github.com/DependencyTrack/dependency-track/issues/1409
    @Test
    public void updateAnalysisIssue1409Test() throws InterruptedException {
        initializeWithPermissions(Permissions.VULNERABILITY_ANALYSIS);

        final Project project = qm.createProject("Acme Example", null, "1.0", null, null, null, true, false);

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
        vulnerability = qm.createVulnerability(vulnerability, false);

        qm.makeAnalysis(component, vulnerability, AnalysisState.IN_TRIAGE, null, null, null, false);

        final var analysisRequest = new AnalysisRequest(project.getUuid().toString(), component.getUuid().toString(),
                vulnerability.getUuid().toString(), AnalysisState.NOT_AFFECTED, AnalysisJustification.PROTECTED_BY_MITIGATING_CONTROL,
                AnalysisResponse.UPDATE, "New analysis details here", "New analysis comment here", false);

        final Response response = target(V1_ANALYSIS)
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
                .doesNotContainKey("commenter"); // Not set when authenticating via API key
        assertThat(analysisComments.getJsonObject(1))
                .hasFieldOrPropertyWithValue("comment", Json.createValue("Justification: NOT_SET → PROTECTED_BY_MITIGATING_CONTROL"))
                .doesNotContainKey("commenter"); // Not set when authenticating via API key
        assertThat(analysisComments.getJsonObject(2))
                .hasFieldOrPropertyWithValue("comment", Json.createValue("Vendor Response: NOT_SET → UPDATE"))
                .doesNotContainKey("commenter"); // Not set when authenticating via API key
        assertThat(analysisComments.getJsonObject(3))
                .hasFieldOrPropertyWithValue("comment", Json.createValue("Details: New analysis details here"))
                .doesNotContainKey("commenter"); // Not set when authenticating via API key
        assertThat(analysisComments.getJsonObject(4))
                .hasFieldOrPropertyWithValue("comment", Json.createValue("New analysis comment here"))
                .doesNotContainKey("commenter"); // Not set when authenticating via API key
        assertThat(responseJson.getBoolean("isSuppressed")).isFalse();

        assertConditionWithTimeout(() -> NOTIFICATIONS.size() == 2, Duration.ofSeconds(5));
        final Notification projectNotification = NOTIFICATIONS.poll();
        assertThat(projectNotification).isNotNull();
        final Notification notification = NOTIFICATIONS.poll();
        assertThat(notification).isNotNull();
        assertThat(notification.getScope()).isEqualTo(NotificationScope.PORTFOLIO.name());
        assertThat(notification.getGroup()).isEqualTo(NotificationGroup.PROJECT_AUDIT_CHANGE.name());
        assertThat(notification.getLevel()).isEqualTo(NotificationLevel.INFORMATIONAL);
        assertThat(notification.getTitle()).isEqualTo(NotificationUtil.generateNotificationTitle(NotificationConstants.Title.ANALYSIS_DECISION_NOT_AFFECTED, project));
        assertThat(notification.getContent()).isEqualTo("An analysis decision was made to a finding affecting a project");
    }

    @Test
    public void updateAnalysisUnauthorizedTest() {
        final var analysisRequest = new AnalysisRequest(UUID.randomUUID().toString(), UUID.randomUUID().toString(),
                UUID.randomUUID().toString(), AnalysisState.NOT_AFFECTED, AnalysisJustification.PROTECTED_BY_MITIGATING_CONTROL,
                AnalysisResponse.UPDATE, "Analysis details here", "Analysis comment here", false);

        final Response response = target(V1_ANALYSIS)
                .request()
                .header(X_API_KEY, apiKey)
                .put(Entity.entity(analysisRequest, MediaType.APPLICATION_JSON));
        assertThat(response.getStatus()).isEqualTo(HttpStatus.SC_FORBIDDEN);
        assertThat(response.getHeaderString(TOTAL_COUNT_HEADER)).isNull();
    }

}
