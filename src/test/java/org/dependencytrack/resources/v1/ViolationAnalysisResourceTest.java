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
import alpine.server.filters.AuthorizationFilter;
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
import org.dependencytrack.model.ViolationAnalysisState;
import org.dependencytrack.resources.v1.vo.ViolationAnalysisRequest;
import org.glassfish.jersey.server.ResourceConfig;
import org.glassfish.jersey.servlet.ServletContainer;
import org.glassfish.jersey.test.DeploymentContext;
import org.glassfish.jersey.test.ServletDeploymentContext;
import org.junit.Test;

import javax.json.JsonArray;
import javax.json.JsonObject;
import javax.ws.rs.client.Entity;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;
import java.util.Date;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;

public class ViolationAnalysisResourceTest extends ResourceTest {

    @Override
    protected DeploymentContext configureDeployment() {
        return ServletDeploymentContext.forServlet(new ServletContainer(
                        new ResourceConfig(ViolationAnalysisResource.class)
                                .register(ApiFilter.class)
                                .register(AuthenticationFilter.class)
                                .register(AuthorizationFilter.class)))
                .build();
    }

    @Test
    public void retrieveAnalysisTest() {
        initializeWithPermissions(Permissions.VIEW_POLICY_VIOLATION);

        final Project project = qm.createProject("Acme Example", null, "1.0", null, null, null, true, false);

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

        final Response response = target(V1_VIOLATION_ANALYSIS)
                .queryParam("component", component.getUuid())
                .queryParam("policyViolation", violation.getUuid())
                .request()
                .header(X_API_KEY, apiKey)
                .get();
        assertThat(response.getStatus()).isEqualTo(Response.Status.OK.getStatusCode());
        assertThat(response.getHeaderString(TOTAL_COUNT_HEADER)).isNull();

        final JsonObject jsonObject = parseJsonObject(response);
        assertThat(jsonObject).isNotNull();
        assertThat(jsonObject.getString("analysisState")).isEqualTo("APPROVED");
        assertThat(jsonObject.getBoolean("isSuppressed")).isFalse();
    }

    @Test
    public void retrieveAnalysisUnauthorizedTest() {
        final Response response = target(V1_VIOLATION_ANALYSIS)
                .queryParam("component", UUID.randomUUID())
                .queryParam("policyViolation", UUID.randomUUID())
                .request()
                .header(X_API_KEY, apiKey)
                .get();
        assertThat(response.getStatus()).isEqualTo(Response.Status.FORBIDDEN.getStatusCode());
        assertThat(response.getHeaderString(TOTAL_COUNT_HEADER)).isNull();
    }

    @Test
    public void updateAnalysisTest() {
        initializeWithPermissions(Permissions.POLICY_VIOLATION_ANALYSIS);

        final Project project = qm.createProject("Acme Example", null, "1.0", null, null, null, true, false);

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
        final Response response = target(V1_VIOLATION_ANALYSIS)
                .request()
                .header(X_API_KEY, apiKey)
                .put(Entity.entity(request, MediaType.APPLICATION_JSON));
        assertThat(response.getStatus()).isEqualTo(Response.Status.OK.getStatusCode());
        assertThat(response.getHeaderString(TOTAL_COUNT_HEADER)).isNull();

        final JsonObject jsonObject = parseJsonObject(response);
        assertThat(jsonObject).isNotNull();
        assertThat(jsonObject.getString("analysisState")).isEqualTo("APPROVED");
        assertThat(jsonObject.getBoolean("isSuppressed")).isFalse();

        final JsonArray comments = jsonObject.getJsonArray("analysisComments");
        assertThat(comments).hasSize(2);
        assertThat(comments.getJsonObject(0).getString("comment")).isEqualTo("NOT_SET → APPROVED");
        assertThat(comments.getJsonObject(1).getString("comment")).isEqualTo("Some comment");
    }

    @Test
    public void updateAnalysisStateChangeTest() {
        initializeWithPermissions(Permissions.POLICY_VIOLATION_ANALYSIS);

        final Project project = qm.createProject("Acme Example", null, "1.0", null, null, null, true, false);

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
        final Response response = target(V1_VIOLATION_ANALYSIS)
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
        assertThat(comments.getJsonObject(0).getString("comment")).isEqualTo("APPROVED → REJECTED");
        assertThat(comments.getJsonObject(1).getString("comment")).isEqualTo("Unsuppressed");
        assertThat(comments.getJsonObject(2).getString("comment")).isEqualTo("Some comment");
    }

    @Test
    public void updateAnalysisUnauthorizedTest() {
        final var request = new ViolationAnalysisRequest(UUID.randomUUID().toString(),
                UUID.randomUUID().toString(), ViolationAnalysisState.REJECTED, "Some comment", false);

        final Response response = target(V1_VIOLATION_ANALYSIS)
                .request()
                .header(X_API_KEY, apiKey)
                .put(Entity.entity(request, MediaType.APPLICATION_JSON));
        assertThat(response.getStatus()).isEqualTo(Response.Status.FORBIDDEN.getStatusCode());
        assertThat(response.getHeaderString(TOTAL_COUNT_HEADER)).isNull();
    }

}