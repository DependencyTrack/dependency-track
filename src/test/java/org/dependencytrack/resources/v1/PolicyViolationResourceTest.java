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

import alpine.model.ConfigProperty;
import alpine.server.filters.ApiFilter;
import alpine.server.filters.AuthenticationFilter;
import alpine.server.filters.AuthorizationFilter;

import org.dependencytrack.JerseyTestRule;
import org.dependencytrack.ResourceTest;
import org.dependencytrack.auth.Permissions;
import org.dependencytrack.model.Component;
import org.dependencytrack.model.ConfigPropertyConstants;
import org.dependencytrack.model.Policy;
import org.dependencytrack.model.PolicyCondition;
import org.dependencytrack.model.PolicyViolation;
import org.dependencytrack.model.Project;
import org.dependencytrack.model.ViolationAnalysis;
import org.dependencytrack.model.ViolationAnalysisState;
import org.glassfish.jersey.server.ResourceConfig;
import org.junit.ClassRule;
import org.junit.Test;

import jakarta.json.JsonArray;
import jakarta.json.JsonObject;
import jakarta.ws.rs.core.Response;
import java.util.ArrayList;
import java.util.Date;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;

public class PolicyViolationResourceTest extends ResourceTest {

    @ClassRule
    public static JerseyTestRule jersey = new JerseyTestRule(
            new ResourceConfig(PolicyViolationResource.class)
                    .register(ApiFilter.class)
                    .register(AuthenticationFilter.class)
                    .register(AuthorizationFilter.class));

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

        final Response response = jersey.target(V1_POLICY_VIOLATION)
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
        final Response response = jersey.target(V1_POLICY_VIOLATION)
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

        var component0 = new Component();
        component0.setProject(project);
        component0.setName("Acme Component 0");
        component0.setVersion("1.0");
        component0 = qm.createComponent(component0, false);

        var componentA = new Component();
        componentA.setProject(project);
        componentA.setName("Acme Component 1");
        componentA.setVersion("1.0");
        componentA = qm.createComponent(componentA, false);

        final Policy policy0 = qm.createPolicy("Blacklisted Version 0", Policy.Operator.ALL, Policy.ViolationState.FAIL);
        final PolicyCondition condition0 = qm.createPolicyCondition(policy0, PolicyCondition.Subject.VERSION, PolicyCondition.Operator.NUMERIC_EQUAL, "1.0");

        final Policy policy1 = qm.createPolicy("Blacklisted Version 1", Policy.Operator.ALL, Policy.ViolationState.FAIL);
        final PolicyCondition condition1 = qm.createPolicyCondition(policy1, PolicyCondition.Subject.VERSION, PolicyCondition.Operator.NUMERIC_EQUAL, "1.0");

        ArrayList<PolicyViolation> filteredPolicyViolations = new ArrayList<>();
        for (int i=0; i<10; i++) {
            final boolean componentFilter = (i == 3);
            final boolean conditionFilter = (i == 7);

            var violation = new PolicyViolation();
            violation.setType(PolicyViolation.Type.OPERATIONAL);
            violation.setComponent(componentFilter ? component0 : componentA);
            violation.setPolicyCondition(conditionFilter ? condition0 : condition1);
            violation.setTimestamp(new Date());
            violation = qm.persist(violation);

            if (conditionFilter || componentFilter) {
                filteredPolicyViolations.add(violation);
            }
        }

        final Response response = jersey.target(V1_POLICY_VIOLATION)
                .queryParam("searchText", "0")
                .path("/project/" + project.getUuid())
                .request()
                .header(X_API_KEY, apiKey)
                .get();
        assertThat(response.getStatus()).isEqualTo(Response.Status.OK.getStatusCode());
        assertThat(response.getHeaderString(TOTAL_COUNT_HEADER)).isEqualTo("2");

        final JsonArray jsonArray = parseJsonArray(response);
        assertThat(jsonArray).hasSize(2);

        final JsonObject jsonObject0 = jsonArray.getJsonObject(0);
        assertThat(jsonObject0.getString("uuid")).isEqualTo(filteredPolicyViolations.get(1).getUuid().toString());
        assertThat(jsonObject0.getString("type")).isEqualTo(PolicyViolation.Type.OPERATIONAL.name());
        assertThat(jsonObject0.getJsonObject("policyCondition")).isNotNull();
        assertThat(jsonObject0.getJsonObject("policyCondition").getJsonObject("policy")).isNotNull();
        assertThat(jsonObject0.getJsonObject("policyCondition").getJsonObject("policy").getString("violationState")).isEqualTo("FAIL");
        assertThat(jsonObject0.getJsonObject("policyCondition").getJsonObject("policy").getString("name")).isEqualTo("Blacklisted Version 0");
        assertThat(jsonObject0.getJsonObject("component").getString("name")).isEqualTo("Acme Component 1");

        final JsonObject jsonObject1 = jsonArray.getJsonObject(1);
        assertThat(jsonObject1.getString("uuid")).isEqualTo(filteredPolicyViolations.get(0).getUuid().toString());
        assertThat(jsonObject1.getString("type")).isEqualTo(PolicyViolation.Type.OPERATIONAL.name());
        assertThat(jsonObject1.getJsonObject("policyCondition")).isNotNull();
        assertThat(jsonObject1.getJsonObject("policyCondition").getJsonObject("policy")).isNotNull();
        assertThat(jsonObject1.getJsonObject("policyCondition").getJsonObject("policy").getString("violationState")).isEqualTo("FAIL");
        assertThat(jsonObject1.getJsonObject("policyCondition").getJsonObject("policy").getString("name")).isEqualTo("Blacklisted Version 1");
        assertThat(jsonObject1.getJsonObject("component").getString("name")).isEqualTo("Acme Component 0");
    }

    @Test
    public void getViolationsByProjectIssue2766() {
        initializeWithPermissions(Permissions.VIEW_POLICY_VIOLATION);

        final Project projectA = qm.createProject("acme-app-a", null, "1.0", null, null, null, true, false);
        final var componentA = new Component();
        componentA.setProject(projectA);
        componentA.setName("acme-lib-a");
        componentA.setVersion("1.0.1");
        qm.persist(componentA);

        final Project projectB = qm.createProject("acme-app-b", null, "2.0", null, null, null, true, false);
        final var componentB = new Component();
        componentB.setProject(projectB);
        componentB.setName("acme-lib-b");
        componentB.setVersion("2.0.1");
        qm.persist(componentB);

        final Policy policy = qm.createPolicy("policy", Policy.Operator.ALL, Policy.ViolationState.FAIL);
        final PolicyCondition condition = qm.createPolicyCondition(policy, PolicyCondition.Subject.VERSION, PolicyCondition.Operator.NUMERIC_EQUAL, "1.0.1");
        final var violation = new PolicyViolation();
        violation.setPolicyCondition(condition);
        violation.setComponent(componentA);
        violation.setType(PolicyViolation.Type.OPERATIONAL);
        violation.setTimestamp(new Date());
        qm.persist(violation);

        // Requesting violations for projectB must not yield violations for projectA.
        final Response response = jersey.target(V1_POLICY_VIOLATION)
                .path("/project/" + projectB.getUuid())
                .request()
                .header(X_API_KEY, apiKey)
                .get();
        assertThat(response.getStatus()).isEqualTo(Response.Status.OK.getStatusCode());
        assertThat(response.getHeaderString(TOTAL_COUNT_HEADER)).isEqualTo("0");

        final JsonArray jsonArray = parseJsonArray(response);
        assertThat(jsonArray).hasSize(0);
    }

    @Test
    public void getViolationsByProjectUnauthorizedTest() {
        final Response response = jersey.target(V1_POLICY_VIOLATION)
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

        final Response response = jersey.target(V1_POLICY_VIOLATION)
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

        final Response response = jersey.target(V1_POLICY_VIOLATION)
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
        final Response response = jersey.target(V1_POLICY_VIOLATION)
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

        final Response response = jersey.target(V1_POLICY_VIOLATION)
                .path("/component/" + UUID.randomUUID())
                .request()
                .header(X_API_KEY, apiKey)
                .get();
        assertThat(response.getStatus()).isEqualTo(Response.Status.NOT_FOUND.getStatusCode());
        assertThat(response.getHeaderString(TOTAL_COUNT_HEADER)).isNull();
        assertThat(getPlainTextBody(response)).contains("component could not be found");
    }

    @Test
    public void getViolationsWithAclEnabledTest() {
        initializeWithPermissions(Permissions.VIEW_POLICY_VIOLATION);

        final Project projectA = qm.createProject("Acme Example", null, "1.0", null, null, null, true, false);
        final Project projectA_child = qm.createProject("Acme Example - Child", null, "1.0", null, projectA, null, true, false);
        final Project projectB = qm.createProject("Acme Example - Grandchild", null, "1.0", null, null, null, true, false);

        projectA.addAccessTeam(team);

        var componentA = new Component();
        componentA.setProject(projectA);
        componentA.setName("Acme Component");
        componentA.setVersion("1.0");
        componentA = qm.createComponent(componentA, false);

        var componentB = new Component();
        componentB.setProject(projectA_child);
        componentB.setName("Acme Component");
        componentB.setVersion("1.0");
        componentB = qm.createComponent(componentB, false);

        var componentC = new Component();
        componentC.setProject(projectB);
        componentC.setName("Acme Component");
        componentC.setVersion("1.0");
        componentC = qm.createComponent(componentC, false);

        var componentD = new Component();
        componentD.setProject(projectA);
        componentD.setName("Acme Component");
        componentD.setVersion("1.0");
        componentD = qm.createComponent(componentA, false);

        final Policy policy = qm.createPolicy("Blacklisted Version", Policy.Operator.ALL, Policy.ViolationState.FAIL);
        final PolicyCondition condition = qm.createPolicyCondition(policy, PolicyCondition.Subject.VERSION, PolicyCondition.Operator.NUMERIC_EQUAL, "1.0");

        var violationA = new PolicyViolation();
        violationA.setType(PolicyViolation.Type.OPERATIONAL);
        violationA.setComponent(componentA);
        violationA.setPolicyCondition(condition);
        violationA.setTimestamp(new Date());
        violationA = qm.persist(violationA);

        var violationB = new PolicyViolation();
        violationB.setType(PolicyViolation.Type.OPERATIONAL);
        violationB.setComponent(componentB);
        violationB.setPolicyCondition(condition);
        violationB.setTimestamp(new Date());
        violationB = qm.persist(violationB);

        var violationC = new PolicyViolation();
        violationC.setType(PolicyViolation.Type.OPERATIONAL);
        violationC.setComponent(componentC);
        violationC.setPolicyCondition(condition);
        violationC.setTimestamp(new Date());
        violationC = qm.persist(violationC);

        var violationD = new PolicyViolation();
        violationD.setType(PolicyViolation.Type.OPERATIONAL);
        violationD.setComponent(componentD);
        violationD.setPolicyCondition(condition);
        violationD.setTimestamp(new Date());
        violationD = qm.persist(violationD);

        final Response responseA = jersey.target(V1_POLICY_VIOLATION)
                .request()
                .header(X_API_KEY, apiKey)
                .get();
        assertThat(responseA.getStatus()).isEqualTo(Response.Status.OK.getStatusCode());
        assertThat(responseA.getHeaderString(TOTAL_COUNT_HEADER)).isEqualTo("4");
        assertThat(parseJsonArray(responseA)).hasSize(4);

        ConfigProperty aclToggle = qm.getConfigProperty(ConfigPropertyConstants.ACCESS_MANAGEMENT_ACL_ENABLED.getGroupName(), ConfigPropertyConstants.ACCESS_MANAGEMENT_ACL_ENABLED.getPropertyName());
        if (aclToggle == null) {
            qm.createConfigProperty(ConfigPropertyConstants.ACCESS_MANAGEMENT_ACL_ENABLED.getGroupName(), ConfigPropertyConstants.ACCESS_MANAGEMENT_ACL_ENABLED.getPropertyName(), "true", ConfigPropertyConstants.ACCESS_MANAGEMENT_ACL_ENABLED.getPropertyType(), ConfigPropertyConstants.ACCESS_MANAGEMENT_ACL_ENABLED.getDescription());
        } else {
            aclToggle.setPropertyValue("true");
            qm.persist(aclToggle);
        }

        final Response responseB = jersey.target(V1_POLICY_VIOLATION)
                .request()
                .header(X_API_KEY, apiKey)
                .get();
        assertThat(responseB.getStatus()).isEqualTo(Response.Status.OK.getStatusCode());
        assertThat(responseB.getHeaderString(TOTAL_COUNT_HEADER)).isEqualTo("2");

        final JsonArray jsonArray = parseJsonArray(responseB);
        assertThat(jsonArray).hasSize(2);

        final JsonObject jsonObjectA = jsonArray.getJsonObject(0);
        assertThat(jsonObjectA.getString("uuid")).isEqualTo(violationD.getUuid().toString());
        assertThat(jsonObjectA.getString("type")).isEqualTo(PolicyViolation.Type.OPERATIONAL.name());
        assertThat(jsonObjectA.getJsonObject("policyCondition")).isNotNull();
        assertThat(jsonObjectA.getJsonObject("policyCondition").getJsonObject("policy")).isNotNull();
        assertThat(jsonObjectA.getJsonObject("policyCondition").getJsonObject("policy").getString("name")).isEqualTo("Blacklisted Version");
        assertThat(jsonObjectA.getJsonObject("policyCondition").getJsonObject("policy").getString("violationState")).isEqualTo("FAIL");
        assertThat(jsonObjectA.getJsonObject("project").getString("uuid")).isEqualTo(projectA.getUuid().toString());

        final JsonObject jsonObjectB = jsonArray.getJsonObject(1);
        assertThat(jsonObjectB.getString("uuid")).isEqualTo(violationA.getUuid().toString());
        assertThat(jsonObjectB.getString("type")).isEqualTo(PolicyViolation.Type.OPERATIONAL.name());
        assertThat(jsonObjectB.getJsonObject("policyCondition")).isNotNull();
        assertThat(jsonObjectB.getJsonObject("policyCondition").getJsonObject("policy")).isNotNull();
        assertThat(jsonObjectB.getJsonObject("policyCondition").getJsonObject("policy").getString("name")).isEqualTo("Blacklisted Version");
        assertThat(jsonObjectB.getJsonObject("policyCondition").getJsonObject("policy").getString("violationState")).isEqualTo("FAIL");
        assertThat(jsonObjectB.getJsonObject("project").getString("uuid")).isEqualTo(projectA.getUuid().toString());
    }

    @Test
    public void getViolationsWithArrayFilter() {
        initializeWithPermissions(Permissions.VIEW_POLICY_VIOLATION);
        
        final Project project = qm.createProject("Acme Example", null, "1.0", null, null, null, true, false);
        
        var component = new Component();
        component.setProject(project);
        component.setName("Acme Component");
        component.setVersion("1.0");
        component = qm.createComponent(component, false);

        final Policy policyA = qm.createPolicy("Policy A", Policy.Operator.ALL, Policy.ViolationState.FAIL);
        final PolicyCondition conditionA = qm.createPolicyCondition(policyA, PolicyCondition.Subject.VERSION, PolicyCondition.Operator.NUMERIC_EQUAL, "1.0");
        var violationA = new PolicyViolation();
        violationA.setType(PolicyViolation.Type.OPERATIONAL);
        violationA.setComponent(component);
        violationA.setPolicyCondition(conditionA);
        violationA.setTimestamp(new Date());
        violationA = qm.persist(violationA);

        final Policy policyB = qm.createPolicy("Policy B", Policy.Operator.ALL, Policy.ViolationState.INFO);
        final PolicyCondition conditionB = qm.createPolicyCondition(policyB, PolicyCondition.Subject.LICENSE, PolicyCondition.Operator.IS, "unresolved");
        var violationB = new PolicyViolation();
        violationB.setType(PolicyViolation.Type.LICENSE);
        violationB.setComponent(component);
        violationB.setPolicyCondition(conditionB);
        violationB.setTimestamp(new Date());
        violationB = qm.persist(violationB);

        final Policy policyC = qm.createPolicy("Policy C", Policy.Operator.ALL, Policy.ViolationState.INFO);
        final PolicyCondition conditionC = qm.createPolicyCondition(policyC, PolicyCondition.Subject.VERSION, PolicyCondition.Operator.NUMERIC_EQUAL, "1.0");
        ViolationAnalysis violationAnalysis = new ViolationAnalysis();
        violationAnalysis.setViolationAnalysisState(ViolationAnalysisState.REJECTED);
        var violationC = new PolicyViolation();
        violationC.setType(PolicyViolation.Type.OPERATIONAL);
        violationC.setComponent(component);
        violationC.setPolicyCondition(conditionC);
        violationC.setTimestamp(new Date());
        violationC.setAnalysis(violationAnalysis);
        violationAnalysis.setPolicyViolation(violationC);
        violationC = qm.persist(violationC);

        final Policy policyD = qm.createPolicy("Policy D", Policy.Operator.ALL, Policy.ViolationState.INFO);
        final PolicyCondition conditionD = qm.createPolicyCondition(policyD, PolicyCondition.Subject.VERSION, PolicyCondition.Operator.NUMERIC_EQUAL, "1.0");
        var violationD = new PolicyViolation();
        violationD.setType(PolicyViolation.Type.OPERATIONAL);
        violationD.setComponent(component);
        violationD.setPolicyCondition(conditionD);
        violationD.setTimestamp(new Date());
        violationD = qm.persist(violationD);

        final Response response = jersey.target(V1_POLICY_VIOLATION)
                .request()
                .header(X_API_KEY, apiKey)
                .get();
        assertThat(response.getStatus()).isEqualTo(Response.Status.OK.getStatusCode());
        assertThat(response.getHeaderString(TOTAL_COUNT_HEADER)).isEqualTo("4");
        assertThat(parseJsonArray(response)).hasSize(4);

        final Response responseA = jersey.target(V1_POLICY_VIOLATION).queryParam("violationState", "FAIL")
                .request()
                .header(X_API_KEY, apiKey)
                .get();
        assertThat(responseA.getStatus()).isEqualTo(Response.Status.OK.getStatusCode());
        assertThat(responseA.getHeaderString(TOTAL_COUNT_HEADER)).isEqualTo("1");
        final JsonArray jsonArrayA = parseJsonArray(responseA);
        assertThat(jsonArrayA).hasSize(1);
        assertThat(jsonArrayA.getJsonObject(0).getString("uuid")).isEqualTo(violationA.getUuid().toString());


        final Response responseB = jersey.target(V1_POLICY_VIOLATION).queryParam("riskType", "LICENSE")
                .request()
                .header(X_API_KEY, apiKey)
                .get();
        assertThat(responseB.getStatus()).isEqualTo(Response.Status.OK.getStatusCode());
        assertThat(responseB.getHeaderString(TOTAL_COUNT_HEADER)).isEqualTo("1");
        final JsonArray jsonArrayB = parseJsonArray(responseB);
        assertThat(jsonArrayB).hasSize(1);
        assertThat(jsonArrayB.getJsonObject(0).getString("uuid")).isEqualTo(violationB.getUuid().toString());
        assertThat(jsonArrayB.getJsonObject(0).getString("uuid")).isEqualTo(violationB.getUuid().toString());

        final Response responseC = jersey.target(V1_POLICY_VIOLATION).queryParam("analysisState", "REJECTED")
                .request()
                .header(X_API_KEY, apiKey)
                .get();
        assertThat(responseC.getStatus()).isEqualTo(Response.Status.OK.getStatusCode());
        assertThat(responseC.getHeaderString(TOTAL_COUNT_HEADER)).isEqualTo("1");
        final JsonArray jsonArrayC = parseJsonArray(responseC);
        assertThat(jsonArrayC).hasSize(1);
        assertThat(jsonArrayC.getJsonObject(0).getString("uuid")).isEqualTo(violationC.getUuid().toString());
        assertThat(jsonArrayC.getJsonObject(0).getString("uuid")).isEqualTo(violationC.getUuid().toString());

        final Response responseD = jersey.target(V1_POLICY_VIOLATION).queryParam("policy", policyD.getUuid().toString())
                .request()
                .header(X_API_KEY, apiKey)
                .get();
        assertThat(responseD.getStatus()).isEqualTo(Response.Status.OK.getStatusCode());
        assertThat(responseD.getHeaderString(TOTAL_COUNT_HEADER)).isEqualTo("1");
        final JsonArray jsonArrayD = parseJsonArray(responseD);
        assertThat(jsonArrayD).hasSize(1);
        assertThat(jsonArrayD.getJsonObject(0).getString("uuid")).isEqualTo(violationD.getUuid().toString());
        assertThat(jsonArrayD.getJsonObject(0).getString("uuid")).isEqualTo(violationD.getUuid().toString());
    }

    @Test
    public void getViolationsWithInputFilter() {
        initializeWithPermissions(Permissions.VIEW_POLICY_VIOLATION);

        final Project projectA = qm.createProject("Project A", null, "1.0", null, null, null, true, false);
        final Project projectB = qm.createProject("Project B", null, "1.0", null, null, null, true, false);
        final Project projectC = qm.createProject("Project C", null, "1.0", null, null, null, true, false);
        final Project projectD = qm.createProject("Project D", null, "1.0", null, null, null, true, false);

        var componentA = new Component();
        componentA.setProject(projectA);
        componentA.setName("Component A");
        componentA.setVersion("1.0");
        componentA.setLicense("License A");
        componentA = qm.createComponent(componentA, false);
        
        var componentB = new Component();
        componentB.setProject(projectB);
        componentB.setName("Component B");
        componentB.setVersion("1.0");
        componentB.setLicense("License B");
        componentB = qm.createComponent(componentB, false);

        var componentC = new Component();
        componentC.setProject(projectC);
        componentC.setName("Component C");
        componentC.setVersion("1.0");
        componentC.setLicense("License C");
        componentC = qm.createComponent(componentC, false);

        var componentD = new Component();
        componentD.setProject(projectD);
        componentD.setName("Component D");
        componentD.setVersion("1.0");
        componentD.setLicense("License D");
        componentD = qm.createComponent(componentD, false);

        final Policy policyA = qm.createPolicy("Policy A", Policy.Operator.ALL, Policy.ViolationState.FAIL);
        final PolicyCondition conditionA = qm.createPolicyCondition(policyA, PolicyCondition.Subject.VERSION, PolicyCondition.Operator.NUMERIC_EQUAL, "1.0");
        var violationA = new PolicyViolation();
        violationA.setType(PolicyViolation.Type.OPERATIONAL);
        violationA.setComponent(componentA);
        violationA.setPolicyCondition(conditionA);
        violationA.setTimestamp(new Date());
        violationA = qm.persist(violationA);

        final Policy policyB = qm.createPolicy("Policy B", Policy.Operator.ALL, Policy.ViolationState.FAIL);
        final PolicyCondition conditionB = qm.createPolicyCondition(policyB, PolicyCondition.Subject.VERSION, PolicyCondition.Operator.NUMERIC_EQUAL, "1.0");
        var violationB = new PolicyViolation();
        violationB.setType(PolicyViolation.Type.OPERATIONAL);
        violationB.setComponent(componentB);
        violationB.setPolicyCondition(conditionB);
        violationB.setTimestamp(new Date());
        violationB = qm.persist(violationB);

        final Policy policyC = qm.createPolicy("Policy C", Policy.Operator.ALL, Policy.ViolationState.FAIL);
        final PolicyCondition conditionC = qm.createPolicyCondition(policyC, PolicyCondition.Subject.VERSION, PolicyCondition.Operator.NUMERIC_EQUAL, "1.0");
        var violationC = new PolicyViolation();
        violationC.setType(PolicyViolation.Type.OPERATIONAL);
        violationC.setComponent(componentC);
        violationC.setPolicyCondition(conditionC);
        violationC.setTimestamp(new Date());
        violationC = qm.persist(violationC);

        final Policy policyD = qm.createPolicy("Policy D", Policy.Operator.ALL, Policy.ViolationState.FAIL);
        final PolicyCondition conditionD = qm.createPolicyCondition(policyD, PolicyCondition.Subject.VERSION, PolicyCondition.Operator.NUMERIC_EQUAL, "1.0");
        var violationD = new PolicyViolation();
        violationD.setType(PolicyViolation.Type.OPERATIONAL);
        violationD.setComponent(componentD);
        violationD.setPolicyCondition(conditionD);
        violationD.setTimestamp(new Date());
        violationD = qm.persist(violationD);

        final Response response = jersey.target(V1_POLICY_VIOLATION)
                .request()
                .header(X_API_KEY, apiKey)
                .get();
        assertThat(response.getStatus()).isEqualTo(Response.Status.OK.getStatusCode());
        assertThat(response.getHeaderString(TOTAL_COUNT_HEADER)).isEqualTo("4");
        assertThat(parseJsonArray(response)).hasSize(4);

        final Response responseA = jersey.target(V1_POLICY_VIOLATION)
                .queryParam("textSearchField", "policy_name")
                .queryParam("textSearchInput", "Policy A")
                .request()
                .header(X_API_KEY, apiKey)
                .get();
        assertThat(responseA.getStatus()).isEqualTo(Response.Status.OK.getStatusCode());
        assertThat(responseA.getHeaderString(TOTAL_COUNT_HEADER)).isEqualTo("1");
        final JsonArray jsonArrayA = parseJsonArray(responseA);
        assertThat(jsonArrayA).hasSize(1);
        assertThat(jsonArrayA.getJsonObject(0).getString("uuid")).isEqualTo(violationA.getUuid().toString());

        final Response responseB = jersey.target(V1_POLICY_VIOLATION)
                .queryParam("textSearchField", "component")
                .queryParam("textSearchInput", "Component B")
                .request()
                .header(X_API_KEY, apiKey)
                .get();
        assertThat(responseB.getStatus()).isEqualTo(Response.Status.OK.getStatusCode());
        assertThat(responseB.getHeaderString(TOTAL_COUNT_HEADER)).isEqualTo("1");
        final JsonArray jsonArrayB = parseJsonArray(responseB);
        assertThat(jsonArrayB).hasSize(1);
        assertThat(jsonArrayB.getJsonObject(0).getString("uuid")).isEqualTo(violationB.getUuid().toString());

        final Response responseC = jersey.target(V1_POLICY_VIOLATION)
                .queryParam("textSearchField", "license")
                .queryParam("textSearchInput", "License C")
                .request()
                .header(X_API_KEY, apiKey)
                .get();
        assertThat(responseC.getStatus()).isEqualTo(Response.Status.OK.getStatusCode());
        assertThat(responseC.getHeaderString(TOTAL_COUNT_HEADER)).isEqualTo("1");
        final JsonArray jsonArrayC = parseJsonArray(responseC);
        assertThat(jsonArrayC).hasSize(1);
        assertThat(jsonArrayC.getJsonObject(0).getString("uuid")).isEqualTo(violationC.getUuid().toString());

        final Response responseD = jersey.target(V1_POLICY_VIOLATION)
                .queryParam("textSearchField", "project_name")
                .queryParam("textSearchInput", "Project D")
                .request()
                .header(X_API_KEY, apiKey)
                .get();
        assertThat(responseD.getStatus()).isEqualTo(Response.Status.OK.getStatusCode());
        assertThat(responseD.getHeaderString(TOTAL_COUNT_HEADER)).isEqualTo("1");
        final JsonArray jsonArrayD = parseJsonArray(responseD);
        assertThat(jsonArrayD).hasSize(1);
        assertThat(jsonArrayD.getJsonObject(0).getString("uuid")).isEqualTo(violationD.getUuid().toString());
    }
}
