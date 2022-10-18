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
import org.dependencytrack.model.PolicyViolation;
import org.dependencytrack.model.Project;
import org.glassfish.jersey.server.ResourceConfig;
import org.glassfish.jersey.servlet.ServletContainer;
import org.glassfish.jersey.test.DeploymentContext;
import org.glassfish.jersey.test.ServletDeploymentContext;
import org.junit.Test;

import javax.json.JsonArray;
import javax.json.JsonObject;
import javax.ws.rs.core.Response;
import java.util.Date;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;

public class PolicyViolationResourceTest extends ResourceTest {

    @Override
    protected DeploymentContext configureDeployment() {
        return ServletDeploymentContext.forServlet(new ServletContainer(
                        new ResourceConfig(PolicyViolationResource.class)
                                .register(ApiFilter.class)
                                .register(AuthenticationFilter.class)
                                .register(AuthorizationFilter.class)))
                .build();
    }

    @Test
    public void getViolationsTest() {
        initializeWithPermissions(Permissions.VIEW_POLICY_VIOLATION);

        final Project project = qm.createProject("Acme Example", null, "1.0", null, null, null, true, false);

        var component = new Component();
        component.setProject(project);
        component.setName("Acme Component");
        component.setVersion("1.0");
        component = qm.createComponent(component, false);

        final Policy policy = qm.createPolicy("Blacklisted Version", Policy.Operator.ALL, Policy.ViolationState.FAIL);
        final PolicyCondition condition = qm.createPolicyCondition(policy, PolicyCondition.Subject.VERSION, PolicyCondition.Operator.NUMERIC_EQUAL, "1.0");

        var violation = new PolicyViolation();
        violation.setType(PolicyViolation.Type.OPERATIONAL);
        violation.setComponent(component);
        violation.setPolicyCondition(condition);
        violation.setTimestamp(new Date());
        violation = qm.persist(violation);

        final Response response = target(V1_POLICY_VIOLATION)
                .request()
                .header(X_API_KEY, apiKey)
                .get();
        assertThat(response.getStatus()).isEqualTo(Response.Status.OK.getStatusCode());
        assertThat(response.getHeaderString(TOTAL_COUNT_HEADER)).isEqualTo("1");

        final JsonArray jsonArray = parseJsonArray(response);
        assertThat(jsonArray).hasSize(1);

        final JsonObject jsonObject = jsonArray.getJsonObject(0);
        assertThat(jsonObject.getString("uuid")).isEqualTo(violation.getUuid().toString());
        assertThat(jsonObject.getString("type")).isEqualTo(PolicyViolation.Type.OPERATIONAL.name());
        assertThat(jsonObject.getJsonObject("policyCondition")).isNotNull();
        assertThat(jsonObject.getJsonObject("policyCondition").getJsonObject("policy")).isNotNull();
        assertThat(jsonObject.getJsonObject("policyCondition").getJsonObject("policy").getString("name")).isEqualTo("Blacklisted Version");
        assertThat(jsonObject.getJsonObject("policyCondition").getJsonObject("policy").getString("violationState")).isEqualTo("FAIL");

    }

    @Test
    public void getViolationsUnauthorizedTest() {
        final Response response = target(V1_POLICY_VIOLATION)
                .request()
                .header(X_API_KEY, apiKey)
                .get();
        assertThat(response.getStatus()).isEqualTo(Response.Status.FORBIDDEN.getStatusCode());
        assertThat(response.getHeaderString(TOTAL_COUNT_HEADER)).isNull();
    }

    @Test
    public void getViolationsByProjectTest() {
        initializeWithPermissions(Permissions.VIEW_POLICY_VIOLATION);

        final Project project = qm.createProject("Acme Example", null, "1.0", null, null, null, true, false);

        var component = new Component();
        component.setProject(project);
        component.setName("Acme Component");
        component.setVersion("1.0");
        component = qm.createComponent(component, false);

        final Policy policy = qm.createPolicy("Blacklisted Version", Policy.Operator.ALL, Policy.ViolationState.FAIL);
        final PolicyCondition condition = qm.createPolicyCondition(policy, PolicyCondition.Subject.VERSION, PolicyCondition.Operator.NUMERIC_EQUAL, "1.0");

        var violation = new PolicyViolation();
        violation.setType(PolicyViolation.Type.OPERATIONAL);
        violation.setComponent(component);
        violation.setPolicyCondition(condition);
        violation.setTimestamp(new Date());
        violation = qm.persist(violation);

        final Response response = target(V1_POLICY_VIOLATION)
                .path("/project/" + project.getUuid())
                .request()
                .header(X_API_KEY, apiKey)
                .get();
        assertThat(response.getStatus()).isEqualTo(Response.Status.OK.getStatusCode());
        assertThat(response.getHeaderString(TOTAL_COUNT_HEADER)).isEqualTo("1");

        final JsonArray jsonArray = parseJsonArray(response);
        assertThat(jsonArray).hasSize(1);

        final JsonObject jsonObject = jsonArray.getJsonObject(0);
        assertThat(jsonObject.getString("uuid")).isEqualTo(violation.getUuid().toString());
        assertThat(jsonObject.getString("type")).isEqualTo(PolicyViolation.Type.OPERATIONAL.name());
        assertThat(jsonObject.getJsonObject("policyCondition")).isNotNull();
        assertThat(jsonObject.getJsonObject("policyCondition").getJsonObject("policy")).isNotNull();
        assertThat(jsonObject.getJsonObject("policyCondition").getJsonObject("policy").getString("name")).isEqualTo("Blacklisted Version");
        assertThat(jsonObject.getJsonObject("policyCondition").getJsonObject("policy").getString("violationState")).isEqualTo("FAIL");
    }

    @Test
    public void getViolationsByProjectUnauthorizedTest() {
        final Response response = target(V1_POLICY_VIOLATION)
                .path("/project/" + UUID.randomUUID())
                .request()
                .header(X_API_KEY, apiKey)
                .get();
        assertThat(response.getStatus()).isEqualTo(Response.Status.FORBIDDEN.getStatusCode());
        assertThat(response.getHeaderString(TOTAL_COUNT_HEADER)).isNull();
    }

    @Test
    public void getViolationsByProjectNotFoundTest() {
        initializeWithPermissions(Permissions.VIEW_POLICY_VIOLATION);

        final Response response = target(V1_POLICY_VIOLATION)
                .path("/project/" + UUID.randomUUID())
                .request()
                .header(X_API_KEY, apiKey)
                .get();
        assertThat(response.getStatus()).isEqualTo(Response.Status.NOT_FOUND.getStatusCode());
        assertThat(response.getHeaderString(TOTAL_COUNT_HEADER)).isNull();
        assertThat(getPlainTextBody(response)).contains("project could not be found");
    }

    @Test
    public void getViolationsByComponentTest() {
        initializeWithPermissions(Permissions.VIEW_POLICY_VIOLATION);

        final Project project = qm.createProject("Acme Example", null, "1.0", null, null, null, true, false);

        var component = new Component();
        component.setProject(project);
        component.setName("Acme Component");
        component.setVersion("1.0");
        component = qm.createComponent(component, false);

        final Policy policy = qm.createPolicy("Blacklisted Version", Policy.Operator.ALL, Policy.ViolationState.FAIL);
        final PolicyCondition condition = qm.createPolicyCondition(policy, PolicyCondition.Subject.VERSION, PolicyCondition.Operator.NUMERIC_EQUAL, "1.0");

        var violation = new PolicyViolation();
        violation.setType(PolicyViolation.Type.OPERATIONAL);
        violation.setComponent(component);
        violation.setPolicyCondition(condition);
        violation.setTimestamp(new Date());
        violation = qm.persist(violation);

        final Response response = target(V1_POLICY_VIOLATION)
                .path("/component/" + component.getUuid())
                .request()
                .header(X_API_KEY, apiKey)
                .get();
        assertThat(response.getStatus()).isEqualTo(Response.Status.OK.getStatusCode());
        assertThat(response.getHeaderString(TOTAL_COUNT_HEADER)).isEqualTo("1");

        final JsonArray jsonArray = parseJsonArray(response);
        assertThat(jsonArray).hasSize(1);

        final JsonObject jsonObject = jsonArray.getJsonObject(0);
        assertThat(jsonObject.getString("uuid")).isEqualTo(violation.getUuid().toString());
        assertThat(jsonObject.getString("type")).isEqualTo(PolicyViolation.Type.OPERATIONAL.name());
        assertThat(jsonObject.getJsonObject("policyCondition")).isNotNull();
        assertThat(jsonObject.getJsonObject("policyCondition").getJsonObject("policy")).isNotNull();
        assertThat(jsonObject.getJsonObject("policyCondition").getJsonObject("policy").getString("name")).isEqualTo("Blacklisted Version");
        assertThat(jsonObject.getJsonObject("policyCondition").getJsonObject("policy").getString("violationState")).isEqualTo("FAIL");
    }

    @Test
    public void getViolationsByComponentUnauthorizedTest() {
        final Response response = target(V1_POLICY_VIOLATION)
                .path("/component/" + UUID.randomUUID())
                .request()
                .header(X_API_KEY, apiKey)
                .get();
        assertThat(response.getStatus()).isEqualTo(Response.Status.FORBIDDEN.getStatusCode());
        assertThat(response.getHeaderString(TOTAL_COUNT_HEADER)).isNull();
    }

    @Test
    public void getViolationsByComponentNotFoundTest() {
        initializeWithPermissions(Permissions.VIEW_POLICY_VIOLATION);

        final Response response = target(V1_POLICY_VIOLATION)
                .path("/component/" + UUID.randomUUID())
                .request()
                .header(X_API_KEY, apiKey)
                .get();
        assertThat(response.getStatus()).isEqualTo(Response.Status.NOT_FOUND.getStatusCode());
        assertThat(response.getHeaderString(TOTAL_COUNT_HEADER)).isNull();
        assertThat(getPlainTextBody(response)).contains("component could not be found");
    }

}