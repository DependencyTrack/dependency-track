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
import alpine.server.filters.ApiFilter;
import alpine.server.filters.AuthenticationFeature;
import alpine.server.filters.AuthorizationFeature;
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
import org.dependencytrack.model.PolicyViolation;
import org.dependencytrack.model.Project;
import org.glassfish.jersey.server.ResourceConfig;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;

import java.util.Date;
import java.util.List;
import java.util.function.Supplier;

import static java.util.Collections.singletonList;
import static net.javacrumbs.jsonunit.assertj.JsonAssertions.assertThatJson;
import static org.assertj.core.api.Assertions.assertThat;

public class PolicyResourceTest extends ResourceTest {

    @RegisterExtension
    static JerseyTestExtension jersey = new JerseyTestExtension(
            new ResourceConfig(PolicyResource.class)
                    .register(ApiFilter.class)
                    .register(AuthenticationFeature.class)
                    .register(AuthorizationFeature.class));

    @Test
    public void getPoliciesTest() {
        initializeWithPermissions(Permissions.POLICY_MANAGEMENT_READ);

        for (int i = 0; i < 1000; i++) {
            qm.createPolicy("policy" + i, Policy.Operator.ANY, Policy.ViolationState.INFO);
        }

        final Response response = jersey.target(V1_POLICY)
                .request()
                .header(X_API_KEY, apiKey)
                .get();

        assertThat(response.getStatus()).isEqualTo(200);
        assertThat(response.getHeaderString(TOTAL_COUNT_HEADER)).isEqualTo("1000");

        final JsonArray json = parseJsonArray(response);
        assertThat(json).isNotNull();
        assertThat(json).hasSize(100);
        assertThat(json.getJsonObject(0).getString("name")).isEqualTo("policy0");
    }

    @Test
    public void getPolicyByUuidTest() {
        initializeWithPermissions(Permissions.POLICY_MANAGEMENT_READ);

        final Policy policy = qm.createPolicy("policy", Policy.Operator.ANY, Policy.ViolationState.INFO);

        final Response response = jersey.target(V1_POLICY + "/" + policy.getUuid())
                .request()
                .header(X_API_KEY, apiKey)
                .get();

        assertThat(response.getStatus()).isEqualTo(200);
        assertThat(response.getHeaderString(TOTAL_COUNT_HEADER)).isNull();

        final JsonObject json = parseJsonObject(response);
        assertThat(json).isNotNull();
        assertThat(json.getString("name")).isEqualTo("policy");
    }

    @Test
    public void createPolicyTest() {
        initializeWithPermissions(Permissions.POLICY_MANAGEMENT_CREATE);

        final Policy policy = new Policy();
        policy.setName("policy");
        policy.setOperator(Policy.Operator.ANY);
        policy.setViolationState(Policy.ViolationState.INFO);

        final Response response = jersey.target(V1_POLICY)
                .request()
                .header(X_API_KEY, apiKey)
                .put(Entity.entity(policy, MediaType.APPLICATION_JSON));

        assertThat(response.getStatus()).isEqualTo(201);

        final JsonObject json = parseJsonObject(response);
        assertThat(json).isNotNull();
        assertThat(json.getString("name")).isEqualTo("policy");
        assertThat(json.getString("operator")).isEqualTo("ANY");
        assertThat(json.getString("violationState")).isEqualTo("INFO");
        assertThat(UuidUtil.isValidUUID(json.getString("uuid")));
        assertThat(json.getBoolean("includeChildren")).isEqualTo(false);
    }

    @Test
    public void createPolicySpecifyOperatorAndViolationStateTest() {
        initializeWithPermissions(Permissions.POLICY_MANAGEMENT_CREATE);

        final Policy policy = new Policy();
        policy.setName("policy");
        policy.setOperator(Policy.Operator.ALL);
        policy.setViolationState(Policy.ViolationState.FAIL);

        final Response response = jersey.target(V1_POLICY)
                .request()
                .header(X_API_KEY, apiKey)
                .put(Entity.entity(policy, MediaType.APPLICATION_JSON));

        assertThat(response.getStatus()).isEqualTo(201);

        final JsonObject json = parseJsonObject(response);
        assertThat(json).isNotNull();
        assertThat(json.getString("name")).isEqualTo("policy");
        assertThat(json.getString("operator")).isEqualTo("ALL");
        assertThat(json.getString("violationState")).isEqualTo("FAIL");
        assertThat(UuidUtil.isValidUUID(json.getString("uuid")));
        assertThat(json.getBoolean("includeChildren")).isEqualTo(false);
    }

    @Test
    public void createPolicyUseDefaultValueTest() {
        initializeWithPermissions(Permissions.POLICY_MANAGEMENT_CREATE);

        final Policy policy = new Policy();
        policy.setName("policy");

        final Response response = jersey.target(V1_POLICY)
                .request()
                .header(X_API_KEY, apiKey)
                .put(Entity.entity(policy, MediaType.APPLICATION_JSON));

        assertThat(response.getStatus()).isEqualTo(201);

        final JsonObject json = parseJsonObject(response);
        assertThat(json).isNotNull();
        assertThat(json.getString("name")).isEqualTo("policy");
        assertThat(json.getString("operator")).isEqualTo("ANY");
        assertThat(json.getString("violationState")).isEqualTo("INFO");
        assertThat(UuidUtil.isValidUUID(json.getString("uuid")));
        assertThat(json.getBoolean("includeChildren")).isEqualTo(false);
    }

    @Test
    public void updatePolicyTest() {
        initializeWithPermissions(Permissions.POLICY_MANAGEMENT_UPDATE);

        final Policy policy = qm.createPolicy("policy", Policy.Operator.ANY, Policy.ViolationState.INFO);

        policy.setViolationState(Policy.ViolationState.FAIL);
        policy.setIncludeChildren(true);
        final Response response = jersey.target(V1_POLICY)
                .request()
                .header(X_API_KEY, apiKey)
                .post(Entity.entity(policy, MediaType.APPLICATION_JSON));

        assertThat(response.getStatus()).isEqualTo(200);

        final JsonObject json = parseJsonObject(response);
        assertThat(json).isNotNull();
        assertThat(json.getString("name")).isEqualTo("policy");
        assertThat(json.getString("operator")).isEqualTo("ANY");
        assertThat(json.getString("violationState")).isEqualTo("FAIL");
        assertThat(json.getBoolean("includeChildren")).isEqualTo(true);
    }

    @Test
    public void deletePolicyTest() {
        initializeWithPermissions(Permissions.POLICY_MANAGEMENT_DELETE);

        final Policy policy = qm.createPolicy("policy", Policy.Operator.ANY, Policy.ViolationState.INFO);

        final Response response = jersey.target(V1_POLICY + "/" + policy.getUuid())
                .request()
                .header(X_API_KEY, apiKey)
                .delete();

        assertThat(response.getStatus()).isEqualTo(204);
        assertThat(qm.getObjectByUuid(Policy.class, policy.getUuid())).isNull();
    }

    /**
     * This test verifies that associated conditions and violations get deleted as well when deleting a Policy.
     */
    @Test
    public void deletePolicyCascadingTest() {
        initializeWithPermissions(Permissions.POLICY_MANAGEMENT_DELETE);

        final Project project = qm.createProject("Acme Application", null, null, null, null, null, null, false);

        Component component = new Component();
        component.setProject(project);
        component.setName("ABC");
        component = qm.createComponent(component, false);

        final Policy policy = qm.createPolicy("policy", Policy.Operator.ANY, Policy.ViolationState.INFO);
        final PolicyCondition condition = qm.createPolicyCondition(policy, PolicyCondition.Subject.COORDINATES, PolicyCondition.Operator.MATCHES, "<coordinates>");

        PolicyViolation violation = new PolicyViolation();
        violation.setComponent(component);
        violation.setPolicyCondition(condition);
        violation.setType(PolicyViolation.Type.OPERATIONAL);
        violation.setTimestamp(new Date());
        qm.persist(violation);

        final Response response = jersey.target(V1_POLICY + "/" + policy.getUuid())
                .request()
                .header(X_API_KEY, apiKey)
                .delete();

        assertThat(response.getStatus()).isEqualTo(204);
        assertThat(qm.getObjectByUuid(Policy.class, policy.getUuid())).isNull();
        assertThat(qm.getObjectByUuid(PolicyCondition.class, condition.getUuid())).isNull();
    }

    @Test
    public void addProjectToPolicyTest() {
        initializeWithPermissions(Permissions.POLICY_MANAGEMENT_UPDATE);

        final Policy policy = qm.createPolicy("policy", Policy.Operator.ANY, Policy.ViolationState.INFO);
        final Project project = qm.createProject("Acme Application", null, null, null, null, null, null, false);

        final Response response = jersey.target(V1_POLICY + "/" + policy.getUuid() + "/project/" + project.getUuid())
                .request()
                .header(X_API_KEY, apiKey)
                .post(null);

        assertThat(response.getStatus()).isEqualTo(200);

        final JsonObject json = parseJsonObject(response);
        assertThat(json.getJsonArray("projects")).hasSize(1);
        assertThat(json.getJsonArray("projects").get(0).asJsonObject().getString("uuid")).isEqualTo(project.getUuid().toString());
    }

    @Test
    public void addProjectToPolicyProjectAlreadyAddedTest() {
        initializeWithPermissions(Permissions.POLICY_MANAGEMENT_UPDATE);

        final Policy policy = qm.createPolicy("policy", Policy.Operator.ANY, Policy.ViolationState.INFO);
        final Project project = qm.createProject("Acme Application", null, null, null, null, null, null, false);

        policy.setProjects(singletonList(project));
        qm.persist(policy);

        final Response response = jersey.target(V1_POLICY + "/" + policy.getUuid() + "/project/" + project.getUuid())
                .request()
                .header(X_API_KEY, apiKey)
                .post(null);

        assertThat(response.getStatus()).isEqualTo(304);
    }

    @Test
    public void addProjectToPolicyAclTest() {
        initializeWithPermissions(Permissions.POLICY_MANAGEMENT_UPDATE);
        enablePortfolioAccessControl();

        final var project = new Project();
        project.setName("acme-app");
        qm.persist(project);

        final var policy = new Policy();
        policy.setName("policy");
        policy.setOperator(Policy.Operator.ANY);
        policy.setViolationState(Policy.ViolationState.INFO);
        qm.persist(policy);

        final Supplier<Response> responseSupplier = () -> jersey
                .target(V1_POLICY + "/" + policy.getUuid() + "/project/" + project.getUuid())
                .request()
                .header(X_API_KEY, apiKey)
                .post(null);

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
    public void removeProjectFromPolicyTest() {
        initializeWithPermissions(Permissions.POLICY_MANAGEMENT_DELETE);

        final Policy policy = qm.createPolicy("policy", Policy.Operator.ANY, Policy.ViolationState.INFO);
        final Project project = qm.createProject("Acme Application", null, null, null, null, null, null, false);

        policy.setProjects(singletonList(project));
        qm.persist(policy);

        final Response response = jersey.target(V1_POLICY + "/" + policy.getUuid() + "/project/" + project.getUuid())
                .request()
                .header(X_API_KEY, apiKey)
                .delete();

        assertThat(response.getStatus()).isEqualTo(200);
    }

    @Test
    public void removeProjectFromPolicyProjectAlreadyRemovedTest() {
        initializeWithPermissions(Permissions.POLICY_MANAGEMENT_DELETE);

        final Policy policy = qm.createPolicy("policy", Policy.Operator.ANY, Policy.ViolationState.INFO);
        final Project project = qm.createProject("Acme Application", null, null, null, null, null, null, false);

        final Response response = jersey.target(V1_POLICY + "/" + policy.getUuid() + "/project/" + project.getUuid())
                .request()
                .header(X_API_KEY, apiKey)
                .delete();

        assertThat(response.getStatus()).isEqualTo(304);
    }

    @Test
    public void removeProjectFromPolicyAclTest() {
        initializeWithPermissions(Permissions.POLICY_MANAGEMENT_DELETE);
        enablePortfolioAccessControl();

        final var project = new Project();
        project.setName("acme-app");
        qm.persist(project);

        final var policy = new Policy();
        policy.setName("policy");
        policy.setOperator(Policy.Operator.ANY);
        policy.setViolationState(Policy.ViolationState.INFO);
        policy.setProjects(List.of(project));
        qm.persist(policy);

        final Supplier<Response> responseSupplier = () -> jersey
                .target(V1_POLICY + "/" + policy.getUuid() + "/project/" + project.getUuid())
                .request()
                .header(X_API_KEY, apiKey)
                .delete();

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
    public void shouldNotLeakInaccessibleProjectsViaGetPolicyWhenAclEnabled() {
        initializeWithPermissions(Permissions.POLICY_MANAGEMENT_READ);
        enablePortfolioAccessControl();

        final var accessibleProject = new Project();
        accessibleProject.setName("accessible");
        qm.persist(accessibleProject);
        accessibleProject.addAccessTeam(super.team);

        final var inaccessibleProject = new Project();
        inaccessibleProject.setName("inaccessible");
        qm.persist(inaccessibleProject);

        final var policy = new Policy();
        policy.setName("policy");
        policy.setOperator(Policy.Operator.ANY);
        policy.setViolationState(Policy.ViolationState.INFO);
        policy.setProjects(List.of(accessibleProject, inaccessibleProject));
        qm.persist(policy);

        final Response response = jersey.target(V1_POLICY + "/" + policy.getUuid())
                .request()
                .header(X_API_KEY, apiKey)
                .get();

        assertThat(response.getStatus()).isEqualTo(200);
        assertThatJson(getPlainTextBody(response))
                .inPath("$.projects[*].uuid")
                .isArray()
                .containsExactly(accessibleProject.getUuid().toString());
    }

    @Test
    public void shouldNotLeakInaccessibleProjectsViaGetPoliciesWhenAclEnabled() {
        initializeWithPermissions(Permissions.POLICY_MANAGEMENT_READ);
        enablePortfolioAccessControl();

        final var accessibleProject = new Project();
        accessibleProject.setName("accessible");
        qm.persist(accessibleProject);
        accessibleProject.addAccessTeam(super.team);

        final var inaccessibleProject = new Project();
        inaccessibleProject.setName("inaccessible");
        qm.persist(inaccessibleProject);

        final var policy = new Policy();
        policy.setName("policy");
        policy.setOperator(Policy.Operator.ANY);
        policy.setViolationState(Policy.ViolationState.INFO);
        policy.setProjects(List.of(accessibleProject, inaccessibleProject));
        qm.persist(policy);

        final Response response = jersey.target(V1_POLICY)
                .request()
                .header(X_API_KEY, apiKey)
                .get();

        assertThat(response.getStatus()).isEqualTo(200);
        assertThatJson(getPlainTextBody(response))
                .inPath("$[0].projects[*].uuid")
                .isArray()
                .containsExactly(accessibleProject.getUuid().toString());
    }

    @Test
    public void shouldNotLeakInaccessibleProjectsInAddProjectToPolicyResponseWhenAclEnabled() {
        initializeWithPermissions(Permissions.POLICY_MANAGEMENT_UPDATE);
        enablePortfolioAccessControl();

        final var inaccessibleProject = new Project();
        inaccessibleProject.setName("inaccessible");
        qm.persist(inaccessibleProject);

        final var accessibleProject = new Project();
        accessibleProject.setName("accessible");
        qm.persist(accessibleProject);
        accessibleProject.addAccessTeam(super.team);

        final var policy = new Policy();
        policy.setName("policy");
        policy.setOperator(Policy.Operator.ANY);
        policy.setViolationState(Policy.ViolationState.INFO);
        policy.setProjects(List.of(inaccessibleProject));
        qm.persist(policy);

        final Response response = jersey
                .target(V1_POLICY + "/" + policy.getUuid() + "/project/" + accessibleProject.getUuid())
                .request()
                .header(X_API_KEY, apiKey)
                .post(null);

        assertThat(response.getStatus()).isEqualTo(200);
        assertThatJson(getPlainTextBody(response))
                .inPath("$.projects[*].uuid")
                .isArray()
                .containsExactly(accessibleProject.getUuid().toString());
    }

    @Test
    public void shouldPreserveInaccessibleProjectsInDatabaseWhenScrubbingPolicyResponse() {
        initializeWithPermissions(Permissions.POLICY_MANAGEMENT_READ);
        enablePortfolioAccessControl();

        final var accessibleProject = new Project();
        accessibleProject.setName("accessible");
        qm.persist(accessibleProject);
        accessibleProject.addAccessTeam(super.team);

        final var inaccessibleProject = new Project();
        inaccessibleProject.setName("inaccessible");
        qm.persist(inaccessibleProject);

        final var policy = new Policy();
        policy.setName("policy");
        policy.setOperator(Policy.Operator.ANY);
        policy.setViolationState(Policy.ViolationState.INFO);
        policy.setProjects(List.of(accessibleProject, inaccessibleProject));
        qm.persist(policy);

        final Response response = jersey.target(V1_POLICY + "/" + policy.getUuid())
                .request()
                .header(X_API_KEY, apiKey)
                .get();
        assertThat(response.getStatus()).isEqualTo(200);

        qm.getPersistenceManager().refresh(policy);
        assertThat(policy.getProjects())
                .extracting(Project::getUuid)
                .containsExactlyInAnyOrder(accessibleProject.getUuid(), inaccessibleProject.getUuid());
    }

    @Test
    public void shouldReturnAllProjectsViaGetPolicyWhenCallerBypassesAcl() {
        initializeWithPermissions(
                Permissions.POLICY_MANAGEMENT_READ,
                Permissions.PORTFOLIO_ACCESS_CONTROL_BYPASS);
        enablePortfolioAccessControl();

        final var projectA = new Project();
        projectA.setName("a");
        qm.persist(projectA);

        final var projectB = new Project();
        projectB.setName("b");
        qm.persist(projectB);

        final var policy = new Policy();
        policy.setName("policy");
        policy.setOperator(Policy.Operator.ANY);
        policy.setViolationState(Policy.ViolationState.INFO);
        policy.setProjects(List.of(projectA, projectB));
        qm.persist(policy);

        final Response response = jersey.target(V1_POLICY + "/" + policy.getUuid())
                .request()
                .header(X_API_KEY, apiKey)
                .get();

        assertThat(response.getStatus()).isEqualTo(200);
        assertThatJson(getPlainTextBody(response))
                .inPath("$.projects[*].uuid")
                .isArray()
                .containsExactlyInAnyOrder(
                        projectA.getUuid().toString(),
                        projectB.getUuid().toString());
    }

    @Test
    public void shouldNotLeakInaccessibleProjectsInUpdatePolicyResponseWhenAclEnabled() {
        initializeWithPermissions(Permissions.POLICY_MANAGEMENT_UPDATE);
        enablePortfolioAccessControl();

        final var accessibleProject = new Project();
        accessibleProject.setName("accessible");
        qm.persist(accessibleProject);
        accessibleProject.addAccessTeam(super.team);

        final var inaccessibleProject = new Project();
        inaccessibleProject.setName("inaccessible");
        qm.persist(inaccessibleProject);

        final var policy = new Policy();
        policy.setName("policy");
        policy.setOperator(Policy.Operator.ANY);
        policy.setViolationState(Policy.ViolationState.INFO);
        policy.setProjects(List.of(accessibleProject, inaccessibleProject));
        qm.persist(policy);

        final Response response = jersey.target(V1_POLICY).request()
                .header(X_API_KEY, apiKey)
                .post(Entity.json(/* language=JSON */ """
                        {
                          "uuid": "%s",
                          "name": "renamed",
                          "operator": "ANY",
                          "violationState": "INFO"
                        }
                        """.formatted(policy.getUuid())));

        assertThat(response.getStatus()).isEqualTo(200);
        assertThatJson(getPlainTextBody(response))
                .inPath("$.projects[*].uuid")
                .isArray()
                .containsExactly(accessibleProject.getUuid().toString());
    }

    @Test
    public void shouldNotLeakInaccessibleProjectsInRemoveProjectFromPolicyResponseWhenAclEnabled() {
        initializeWithPermissions(Permissions.POLICY_MANAGEMENT_DELETE);
        enablePortfolioAccessControl();

        final var inaccessibleProject = new Project();
        inaccessibleProject.setName("inaccessible");
        qm.persist(inaccessibleProject);

        final var accessibleProject = new Project();
        accessibleProject.setName("accessible");
        qm.persist(accessibleProject);
        accessibleProject.addAccessTeam(super.team);

        final var policy = new Policy();
        policy.setName("policy");
        policy.setOperator(Policy.Operator.ANY);
        policy.setViolationState(Policy.ViolationState.INFO);
        policy.setProjects(List.of(inaccessibleProject, accessibleProject));
        qm.persist(policy);

        final Response response = jersey
                .target(V1_POLICY + "/" + policy.getUuid() + "/project/" + accessibleProject.getUuid())
                .request()
                .header(X_API_KEY, apiKey)
                .delete();

        assertThat(response.getStatus()).isEqualTo(200);
        assertThatJson(getPlainTextBody(response))
                .inPath("$.projects")
                .isArray()
                .isEmpty();
    }

}
