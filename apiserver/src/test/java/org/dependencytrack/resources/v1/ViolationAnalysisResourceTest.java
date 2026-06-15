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

import alpine.server.filters.ApiFilter;
import alpine.server.filters.AuthFeature;
import jakarta.json.Json;
import jakarta.json.JsonArray;
import jakarta.json.JsonObject;
import jakarta.ws.rs.client.Entity;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import org.dependencytrack.JerseyTestExtension;
import org.dependencytrack.ResourceTest;
import org.dependencytrack.auth.Permissions;
import org.dependencytrack.model.Component;
import org.dependencytrack.model.Policy;
import org.dependencytrack.model.PolicyCondition;
import org.dependencytrack.model.PolicyCondition.Operator;
import org.dependencytrack.model.PolicyCondition.Subject;
import org.dependencytrack.model.PolicyViolation;
import org.dependencytrack.model.PolicyViolation.Type;
import org.dependencytrack.model.Project;
import org.dependencytrack.model.ViolationAnalysis;
import org.dependencytrack.model.ViolationAnalysisComment;
import org.dependencytrack.model.ViolationAnalysisState;
import org.dependencytrack.notification.NotificationScope;
import org.dependencytrack.resources.v1.vo.ViolationAnalysisRequest;
import org.glassfish.jersey.server.ResourceConfig;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;

import java.util.Date;
import java.util.UUID;
import java.util.function.Supplier;

import static net.javacrumbs.jsonunit.assertj.JsonAssertions.assertThatJson;
import static org.assertj.core.api.Assertions.assertThat;
import static org.dependencytrack.notification.NotificationTestUtil.createCatchAllNotificationRule;
import static org.dependencytrack.notification.proto.v1.Group.GROUP_PROJECT_AUDIT_CHANGE;
import static org.dependencytrack.notification.proto.v1.Level.LEVEL_INFORMATIONAL;
import static org.dependencytrack.notification.proto.v1.Scope.SCOPE_PORTFOLIO;

class ViolationAnalysisResourceTest extends ResourceTest {

    @RegisterExtension
    static JerseyTestExtension jersey = new JerseyTestExtension(
            new ResourceConfig(ViolationAnalysisResource.class)
                    .register(ApiFilter.class)
                    .register(AuthFeature.class));

    @Test
    void retrieveAnalysisTest() {
        initializeWithPermissions(Permissions.VIEW_POLICY_VIOLATION);

        final Project project = qm.createProject("Acme Example", null, "1.0", null, null, null, null, false);

        var component = new Component();
        component.setProject(project);
        component.setName("Acme Component");
        component.setVersion("1.0");
        component = qm.createComponent(component, false);

        final Policy policy = qm.createPolicy("Blacklisted Version", Policy.Operator.ALL, Policy.ViolationState.FAIL);
        final PolicyCondition condition = qm.createPolicyCondition(policy, Subject.VERSION, Operator.NUMERIC_EQUAL, "1.0");

        var violation = new PolicyViolation();
        violation.setType(Type.OPERATIONAL);
        violation.setComponent(component);
        violation.setPolicyCondition(condition);
        violation.setTimestamp(new Date());
        violation = qm.persist(violation);

        var violationAnalysis = new ViolationAnalysis();
        violationAnalysis.setComponent(component);
        violationAnalysis.setPolicyViolation(violation);
        violationAnalysis.setViolationAnalysisState(ViolationAnalysisState.APPROVED);
        violationAnalysis = qm.persist(violationAnalysis);

        var violationAnalysisComment = new ViolationAnalysisComment();
        violationAnalysisComment.setViolationAnalysis(violationAnalysis);
        violationAnalysisComment.setCommenter("Jane Doe");
        violationAnalysisComment.setComment("Analysis comment here");
        violationAnalysisComment.setTimestamp(new Date());
        qm.persist(violationAnalysisComment);

        final Response response = jersey
                .target(V1_VIOLATION_ANALYSIS)
                .queryParam("component", component.getUuid())
                .queryParam("policyViolation", violation.getUuid())
                .request()
                .header(X_API_KEY, apiKey)
                .get();
        assertThat(response.getStatus()).isEqualTo(Response.Status.OK.getStatusCode());
        assertThat(response.getHeaderString(TOTAL_COUNT_HEADER)).isNull();

        assertThatJson(getPlainTextBody(response))
                .isEqualTo(/* language=JSON */ """
                        {
                          "analysisState": "APPROVED",
                          "analysisComments": [
                            {
                              "timestamp": "${json-unit.any-number}",
                              "comment": "Analysis comment here",
                              "commenter": "Jane Doe"
                            }
                          ],
                          "isSuppressed": false
                        }
                        """);
    }

    @Test
    void shouldReturnEmptyAnalysisCommentsArrayWhenNoCommentsExist() {
        initializeWithPermissions(Permissions.VIEW_POLICY_VIOLATION);

        final Project project = qm.createProject("Acme Example", null, "1.0", null, null, null, null, false);

        var component = new Component();
        component.setProject(project);
        component.setName("Acme Component");
        component.setVersion("1.0");
        component = qm.createComponent(component, false);

        final Policy policy = qm.createPolicy("Blacklisted Version", Policy.Operator.ALL, Policy.ViolationState.FAIL);
        final PolicyCondition condition = qm.createPolicyCondition(policy, Subject.VERSION, Operator.NUMERIC_EQUAL, "1.0");

        var violation = new PolicyViolation();
        violation.setType(Type.OPERATIONAL);
        violation.setComponent(component);
        violation.setPolicyCondition(condition);
        violation.setTimestamp(new Date());
        violation = qm.persist(violation);

        final var violationAnalysis = new ViolationAnalysis();
        violationAnalysis.setComponent(component);
        violationAnalysis.setPolicyViolation(violation);
        violationAnalysis.setViolationAnalysisState(ViolationAnalysisState.APPROVED);
        qm.persist(violationAnalysis);

        final Response response = jersey
                .target(V1_VIOLATION_ANALYSIS)
                .queryParam("component", component.getUuid())
                .queryParam("policyViolation", violation.getUuid())
                .request()
                .header(X_API_KEY, apiKey)
                .get();
        assertThat(response.getStatus()).isEqualTo(Response.Status.OK.getStatusCode());

        assertThatJson(getPlainTextBody(response))
                .isEqualTo(/* language=JSON */ """
                        {
                          "analysisState": "APPROVED",
                          "analysisComments": [],
                          "isSuppressed": false
                        }
                        """);
    }

    @Test
    void retrieveAnalysisUnauthorizedTest() {
        final Response response = jersey.target(V1_VIOLATION_ANALYSIS)
                .queryParam("component", UUID.randomUUID())
                .queryParam("policyViolation", UUID.randomUUID())
                .request()
                .header(X_API_KEY, apiKey)
                .get();
        assertThat(response.getStatus()).isEqualTo(Response.Status.FORBIDDEN.getStatusCode());
        assertThat(response.getHeaderString(TOTAL_COUNT_HEADER)).isNull();
    }

    @Test
    void retrieveAnalysisComponentNotFoundTest() {
        initializeWithPermissions(Permissions.VIEW_POLICY_VIOLATION);

        final Response response = jersey.target(V1_VIOLATION_ANALYSIS)
                .queryParam("component", UUID.randomUUID())
                .queryParam("policyViolation", UUID.randomUUID())
                .request()
                .header(X_API_KEY, apiKey)
                .get();
        assertThat(response.getStatus()).isEqualTo(Response.Status.NOT_FOUND.getStatusCode());
        assertThat(response.getHeaderString(TOTAL_COUNT_HEADER)).isNull();
        assertThat(getPlainTextBody(response)).contains("component could not be found");
    }

    @Test
    void retrieveAnalysisViolationNotFoundTest() {
        initializeWithPermissions(Permissions.VIEW_POLICY_VIOLATION);

        final Project project = qm.createProject("Acme Example", null, "1.0", null, null, null, null, false);

        var component = new Component();
        component.setProject(project);
        component.setName("Acme Component");
        component.setVersion("1.0");
        component = qm.createComponent(component, false);

        final Response response = jersey.target(V1_VIOLATION_ANALYSIS)
                .queryParam("component", component.getUuid())
                .queryParam("policyViolation", UUID.randomUUID())
                .request()
                .header(X_API_KEY, apiKey)
                .get();
        assertThat(response.getStatus()).isEqualTo(Response.Status.NOT_FOUND.getStatusCode());
        assertThat(response.getHeaderString(TOTAL_COUNT_HEADER)).isNull();
        assertThat(getPlainTextBody(response)).contains("policy violation could not be found");
    }

    @Test
    void retrieveAnalysisAclTest() {
        initializeWithPermissions(Permissions.VIEW_POLICY_VIOLATION);
        enablePortfolioAccessControl();

        final var project = new Project();
        project.setName("acme-app");
        qm.persist(project);

        final Component component = new Component();
        component.setProject(project);
        component.setName("acme-lib");
        qm.persist(component);

        final Supplier<Response> responseSupplier = () -> jersey
                .target(V1_VIOLATION_ANALYSIS)
                .queryParam("component", component.getUuid())
                .queryParam("policyViolation", UUID.randomUUID())
                .request()
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
        assertThat(response.getStatus()).isEqualTo(404);
    }

    @Test
    void updateAnalysisCreateNewTest() {
        createCatchAllNotificationRule(qm, NotificationScope.PORTFOLIO);

        initializeWithPermissions(Permissions.POLICY_VIOLATION_ANALYSIS);

        final Project project = qm.createProject("Acme Example", null, "1.0", null, null, null, null, false);

        var component = new Component();
        component.setProject(project);
        component.setName("Acme Component");
        component.setVersion("1.0");
        component = qm.createComponent(component, false);

        final Policy policy = qm.createPolicy("Blacklisted Version", Policy.Operator.ALL, Policy.ViolationState.FAIL);
        final PolicyCondition condition = qm.createPolicyCondition(policy, Subject.VERSION, Operator.NUMERIC_EQUAL, "1.0");

        var violation = new PolicyViolation();
        violation.setType(Type.OPERATIONAL);
        violation.setComponent(component);
        violation.setPolicyCondition(condition);
        violation.setTimestamp(new Date());
        violation = qm.persist(violation);

        final var request = new ViolationAnalysisRequest(component.getUuid().toString(),
                violation.getUuid().toString(), ViolationAnalysisState.APPROVED, "Some comment", false);

        final Response response = jersey.target(V1_VIOLATION_ANALYSIS)
                .request()
                .header(X_API_KEY, apiKey)
                .put(Entity.entity(request, MediaType.APPLICATION_JSON));
        assertThat(response.getStatus()).isEqualTo(Response.Status.OK.getStatusCode());
        assertThat(response.getHeaderString(TOTAL_COUNT_HEADER)).isNull();

        final JsonObject jsonObject = parseJsonObject(response);
        assertThat(jsonObject).isNotNull();
        assertThat(jsonObject.getString("analysisState")).isEqualTo("APPROVED");
        assertThat(jsonObject.getBoolean("isSuppressed")).isFalse();

        assertThat(jsonObject.getJsonArray("analysisComments")).hasSize(2);
        assertThat(jsonObject.getJsonArray("analysisComments")).satisfiesExactlyInAnyOrder(
                obj1 -> assertThat(obj1.asJsonObject())
                        .hasFieldOrPropertyWithValue("comment", Json.createValue("NOT_SET → APPROVED"))
                        .hasFieldOrPropertyWithValue("commenter", Json.createValue("Test Users")),
                obj2 -> assertThat(obj2.asJsonObject())
                        .hasFieldOrPropertyWithValue("comment", Json.createValue("Some comment"))
                        .hasFieldOrPropertyWithValue("commenter", Json.createValue("Test Users")));

        assertThat(qm.getNotificationOutbox()).satisfiesExactly(notification -> {
            assertThat(notification.getScope()).isEqualTo(SCOPE_PORTFOLIO);
            assertThat(notification.getGroup()).isEqualTo(GROUP_PROJECT_AUDIT_CHANGE);
            assertThat(notification.getLevel()).isEqualTo(LEVEL_INFORMATIONAL);
            assertThat(notification.getTitle()).isEqualTo("Violation Analysis Decision: APPROVED on Project: [Acme Example : 1.0]");
            assertThat(notification.getContent()).isEqualTo("An violation analysis decision was made to a policy violation affecting a project");
        });
    }

    @Test
    void updateAnalysisCreateNewWithEmptyRequestTest() {
        createCatchAllNotificationRule(qm, NotificationScope.PORTFOLIO);

        initializeWithPermissions(Permissions.POLICY_VIOLATION_ANALYSIS);

        final Project project = qm.createProject("Acme Example", null, "1.0", null, null, null, null, false);

        var component = new Component();
        component.setProject(project);
        component.setName("Acme Component");
        component.setVersion("1.0");
        component = qm.createComponent(component, false);

        final Policy policy = qm.createPolicy("Blacklisted Version", Policy.Operator.ALL, Policy.ViolationState.FAIL);
        final PolicyCondition condition = qm.createPolicyCondition(policy, Subject.VERSION, Operator.NUMERIC_EQUAL, "1.0");

        var violation = new PolicyViolation();
        violation.setType(Type.OPERATIONAL);
        violation.setComponent(component);
        violation.setPolicyCondition(condition);
        violation.setTimestamp(new Date());
        violation = qm.persist(violation);

        final var request = new ViolationAnalysisRequest(component.getUuid().toString(),
                violation.getUuid().toString(), null, null, null);

        final Response response = jersey.target(V1_VIOLATION_ANALYSIS)
                .request()
                .header(X_API_KEY, apiKey)
                .put(Entity.entity(request, MediaType.APPLICATION_JSON));
        assertThat(response.getStatus()).isEqualTo(Response.Status.OK.getStatusCode());
        assertThat(response.getHeaderString(TOTAL_COUNT_HEADER)).isNull();

        final JsonObject jsonObject = parseJsonObject(response);
        assertThat(jsonObject).isNotNull();
        assertThat(jsonObject.getString("analysisState")).isEqualTo(ViolationAnalysisState.NOT_SET.name());
        assertThat(jsonObject.getBoolean("isSuppressed")).isFalse();
        assertThat(jsonObject.getJsonArray("analysisComments")).isEmpty();

        assertThat(qm.getNotificationOutbox()).isEmpty();
    }

    @Test
    void updateAnalysisUpdateExistingTest() {
        createCatchAllNotificationRule(qm, NotificationScope.PORTFOLIO);

        initializeWithPermissions(Permissions.POLICY_VIOLATION_ANALYSIS);

        final Project project = qm.createProject("Acme Example", null, "1.0", null, null, null, null, false);

        var component = new Component();
        component.setProject(project);
        component.setName("Acme Component");
        component.setVersion("1.0");
        component = qm.createComponent(component, false);

        final Policy policy = qm.createPolicy("Blacklisted Version", Policy.Operator.ALL, Policy.ViolationState.FAIL);
        final PolicyCondition condition = qm.createPolicyCondition(policy, Subject.VERSION, Operator.NUMERIC_EQUAL, "1.0");

        var violation = new PolicyViolation();
        violation.setType(Type.OPERATIONAL);
        violation.setComponent(component);
        violation.setPolicyCondition(condition);
        violation.setTimestamp(new Date());
        violation = qm.persist(violation);

        final var violationAnalysis = new ViolationAnalysis();
        violationAnalysis.setComponent(component);
        violationAnalysis.setPolicyViolation(violation);
        violationAnalysis.setViolationAnalysisState(ViolationAnalysisState.APPROVED);
        violationAnalysis.setSuppressed(true);
        qm.persist(violationAnalysis);

        final var request = new ViolationAnalysisRequest(component.getUuid().toString(),
                violation.getUuid().toString(), ViolationAnalysisState.REJECTED, "Some comment", false);

        final Response response = jersey.target(V1_VIOLATION_ANALYSIS)
                .request()
                .header(X_API_KEY, apiKey)
                .put(Entity.entity(request, MediaType.APPLICATION_JSON));
        assertThat(response.getStatus()).isEqualTo(Response.Status.OK.getStatusCode());
        assertThat(response.getHeaderString(TOTAL_COUNT_HEADER)).isNull();

        final JsonObject jsonObject = parseJsonObject(response);
        assertThat(jsonObject).isNotNull();
        assertThat(jsonObject.getString("analysisState")).isEqualTo(ViolationAnalysisState.REJECTED.name());
        assertThat(jsonObject.getBoolean("isSuppressed")).isFalse();

        final JsonArray comments = jsonObject.getJsonArray("analysisComments");
        assertThat(comments).hasSize(3);
        assertThat(comments.getJsonObject(0))
                .hasFieldOrPropertyWithValue("comment", Json.createValue("APPROVED → REJECTED"))
                .hasFieldOrPropertyWithValue("commenter", Json.createValue("Test Users"));
        assertThat(comments.getJsonObject(1))
                .hasFieldOrPropertyWithValue("comment", Json.createValue("Unsuppressed"))
                .hasFieldOrPropertyWithValue("commenter", Json.createValue("Test Users"));
        assertThat(comments.getJsonObject(2))
                .hasFieldOrPropertyWithValue("comment", Json.createValue("Some comment"))
                .hasFieldOrPropertyWithValue("commenter", Json.createValue("Test Users"));

        assertThat(qm.getNotificationOutbox()).satisfiesExactly(notification -> {
            assertThat(notification.getScope()).isEqualTo(SCOPE_PORTFOLIO);
            assertThat(notification.getGroup()).isEqualTo(GROUP_PROJECT_AUDIT_CHANGE);
            assertThat(notification.getLevel()).isEqualTo(LEVEL_INFORMATIONAL);
            assertThat(notification.getTitle()).isEqualTo("Violation Analysis Decision: REJECTED on Project: [Acme Example : 1.0]");
            assertThat(notification.getContent()).isEqualTo("An violation analysis decision was made to a policy violation affecting a project");
        });
    }

    @Test
    void updateAnalysisUpdateExistingNoChangesTest() {
        initializeWithPermissions(Permissions.POLICY_VIOLATION_ANALYSIS);

        final Project project = qm.createProject("Acme Example", null, "1.0", null, null, null, null, false);

        var component = new Component();
        component.setProject(project);
        component.setName("Acme Component");
        component.setVersion("1.0");
        component = qm.createComponent(component, false);

        final Policy policy = qm.createPolicy("Blacklisted Version", Policy.Operator.ALL, Policy.ViolationState.FAIL);
        final PolicyCondition condition = qm.createPolicyCondition(policy, Subject.VERSION, Operator.NUMERIC_EQUAL, "1.0");

        var violation = new PolicyViolation();
        violation.setType(Type.OPERATIONAL);
        violation.setComponent(component);
        violation.setPolicyCondition(condition);
        violation.setTimestamp(new Date());
        violation = qm.persist(violation);

        final var violationAnalysis = new ViolationAnalysis();
        violationAnalysis.setComponent(component);
        violationAnalysis.setPolicyViolation(violation);
        violationAnalysis.setViolationAnalysisState(ViolationAnalysisState.APPROVED);
        violationAnalysis.setSuppressed(true);
        qm.persist(violationAnalysis);

        final var request = new ViolationAnalysisRequest(component.getUuid().toString(),
                violation.getUuid().toString(), ViolationAnalysisState.APPROVED, null, true);

        final Response response = jersey.target(V1_VIOLATION_ANALYSIS)
                .request()
                .header(X_API_KEY, apiKey)
                .put(Entity.entity(request, MediaType.APPLICATION_JSON));
        assertThat(response.getStatus()).isEqualTo(Response.Status.OK.getStatusCode());
        assertThat(response.getHeaderString(TOTAL_COUNT_HEADER)).isNull();

        final JsonObject jsonObject = parseJsonObject(response);
        assertThat(jsonObject).isNotNull();
        assertThat(jsonObject.getString("analysisState")).isEqualTo(ViolationAnalysisState.APPROVED.name());
        assertThat(jsonObject.getBoolean("isSuppressed")).isTrue();
        assertThat(jsonObject.getJsonArray("analysisComments")).isEmpty();
    }

    @Test
    void updateAnalysisUpdateExistingWithEmptyRequestTest() {
        createCatchAllNotificationRule(qm, NotificationScope.PORTFOLIO);

        initializeWithPermissions(Permissions.POLICY_VIOLATION_ANALYSIS);

        final Project project = qm.createProject("Acme Example", null, "1.0", null, null, null, null, false);

        var component = new Component();
        component.setProject(project);
        component.setName("Acme Component");
        component.setVersion("1.0");
        component = qm.createComponent(component, false);

        final Policy policy = qm.createPolicy("Blacklisted Version", Policy.Operator.ALL, Policy.ViolationState.FAIL);
        final PolicyCondition condition = qm.createPolicyCondition(policy, Subject.VERSION, Operator.NUMERIC_EQUAL, "1.0");

        var violation = new PolicyViolation();
        violation.setType(Type.OPERATIONAL);
        violation.setComponent(component);
        violation.setPolicyCondition(condition);
        violation.setTimestamp(new Date());
        violation = qm.persist(violation);

        final var violationAnalysis = new ViolationAnalysis();
        violationAnalysis.setComponent(component);
        violationAnalysis.setPolicyViolation(violation);
        violationAnalysis.setViolationAnalysisState(ViolationAnalysisState.APPROVED);
        violationAnalysis.setSuppressed(true);
        qm.persist(violationAnalysis);

        final var request = new ViolationAnalysisRequest(component.getUuid().toString(),
                violation.getUuid().toString(), null, null, null);

        final Response response = jersey.target(V1_VIOLATION_ANALYSIS)
                .request()
                .header(X_API_KEY, apiKey)
                .put(Entity.entity(request, MediaType.APPLICATION_JSON));
        assertThat(response.getStatus()).isEqualTo(Response.Status.OK.getStatusCode());
        assertThat(response.getHeaderString(TOTAL_COUNT_HEADER)).isNull();

        final JsonObject jsonObject = parseJsonObject(response);
        assertThat(jsonObject).isNotNull();
        assertThat(jsonObject.getString("analysisState")).isEqualTo(ViolationAnalysisState.NOT_SET.name());
        assertThat(jsonObject.getBoolean("isSuppressed")).isTrue();
        assertThat(jsonObject.getJsonArray("analysisComments")).hasSize(1);
        assertThat(jsonObject.getJsonArray("analysisComments").getJsonObject(0))
                .hasFieldOrPropertyWithValue("comment", Json.createValue("APPROVED → NOT_SET"))
                .hasFieldOrPropertyWithValue("commenter", Json.createValue("Test Users"));

        assertThat(qm.getNotificationOutbox()).satisfiesExactly(notification -> {
            assertThat(notification.getScope()).isEqualTo(SCOPE_PORTFOLIO);
            assertThat(notification.getGroup()).isEqualTo(GROUP_PROJECT_AUDIT_CHANGE);
            assertThat(notification.getLevel()).isEqualTo(LEVEL_INFORMATIONAL);
            assertThat(notification.getTitle()).isEqualTo("Violation Analysis Decision: NOT_SET on Project: [Acme Example : 1.0]");
            assertThat(notification.getContent()).isEqualTo("An violation analysis decision was made to a policy violation affecting a project");
        });
    }

    @Test
    void updateAnalysisUnauthorizedTest() {
        final var request = new ViolationAnalysisRequest(UUID.randomUUID().toString(),
                UUID.randomUUID().toString(), ViolationAnalysisState.REJECTED, "Some comment", false);

        final Response response = jersey.target(V1_VIOLATION_ANALYSIS)
                .request()
                .header(X_API_KEY, apiKey)
                .put(Entity.entity(request, MediaType.APPLICATION_JSON));
        assertThat(response.getStatus()).isEqualTo(Response.Status.FORBIDDEN.getStatusCode());
        assertThat(response.getHeaderString(TOTAL_COUNT_HEADER)).isNull();
    }

    @Test
    void updateAnalysisComponentNotFoundTest() {
        initializeWithPermissions(Permissions.POLICY_VIOLATION_ANALYSIS);

        final var request = new ViolationAnalysisRequest(UUID.randomUUID().toString(),
                UUID.randomUUID().toString(), ViolationAnalysisState.REJECTED, "Some comment", false);

        final Response response = jersey.target(V1_VIOLATION_ANALYSIS)
                .request()
                .header(X_API_KEY, apiKey)
                .put(Entity.entity(request, MediaType.APPLICATION_JSON));
        assertThat(response.getStatus()).isEqualTo(Response.Status.NOT_FOUND.getStatusCode());
        assertThat(response.getHeaderString(TOTAL_COUNT_HEADER)).isNull();
        assertThat(getPlainTextBody(response)).contains("component could not be found");
    }

    @Test
    void updateAnalysisViolationNotFoundTest() {
        initializeWithPermissions(Permissions.POLICY_VIOLATION_ANALYSIS);

        final Project project = qm.createProject("Acme Example", null, "1.0", null, null, null, null, false);

        var component = new Component();
        component.setProject(project);
        component.setName("Acme Component");
        component.setVersion("1.0");
        component = qm.createComponent(component, false);

        final var request = new ViolationAnalysisRequest(component.getUuid().toString(),
                UUID.randomUUID().toString(), ViolationAnalysisState.REJECTED, "Some comment", false);

        final Response response = jersey.target(V1_VIOLATION_ANALYSIS)
                .request()
                .header(X_API_KEY, apiKey)
                .put(Entity.entity(request, MediaType.APPLICATION_JSON));
        assertThat(response.getStatus()).isEqualTo(Response.Status.NOT_FOUND.getStatusCode());
        assertThat(response.getHeaderString(TOTAL_COUNT_HEADER)).isNull();
        assertThat(getPlainTextBody(response)).contains("policy violation could not be found");
    }

    @Test
    void updateAnalysisAclTest() {
        initializeWithPermissions(Permissions.POLICY_VIOLATION_ANALYSIS);
        enablePortfolioAccessControl();

        final var project = new Project();
        project.setName("acme-app");
        qm.persist(project);

        final Component component = new Component();
        component.setProject(project);
        component.setName("acme-lib");
        qm.persist(component);

        final Supplier<Response> responseSupplier = () -> jersey
                .target(V1_VIOLATION_ANALYSIS)
                .queryParam("component", component.getUuid())
                .queryParam("policyViolation", UUID.randomUUID())
                .request()
                .header(X_API_KEY, apiKey)
                .put(Entity.json(/* language=JSON */ """
                        {
                          "component": "%s",
                          "policyViolation": "9b0e0cec-4bef-4d6d-b767-02f280f55e76",
                          "comment": "foo"
                        }
                        """.formatted(component.getUuid())));

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
        assertThat(response.getStatus()).isEqualTo(404);
    }

}
