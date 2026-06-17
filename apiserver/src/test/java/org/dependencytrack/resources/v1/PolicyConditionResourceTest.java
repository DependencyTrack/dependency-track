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
import jakarta.ws.rs.client.Entity;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import org.dependencytrack.JerseyTestExtension;
import org.dependencytrack.ResourceTest;
import org.dependencytrack.auth.Permissions;
import org.dependencytrack.model.Policy;
import org.dependencytrack.model.Policy.Operator;
import org.dependencytrack.model.Policy.ViolationState;
import org.dependencytrack.model.PolicyCondition;
import org.glassfish.jersey.server.ResourceConfig;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;

import javax.jdo.JDOObjectNotFoundException;
import java.util.UUID;

import static net.javacrumbs.jsonunit.assertj.JsonAssertions.assertThatJson;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.AssertionsForClassTypes.assertThatExceptionOfType;
import static org.hamcrest.CoreMatchers.equalTo;

public class PolicyConditionResourceTest extends ResourceTest {

    @RegisterExtension
    static JerseyTestExtension jersey = new JerseyTestExtension(
            new ResourceConfig(PolicyConditionResource.class)
                    .register(ApiFilter.class)
                    .register(AuthFeature.class));

    @Test
    public void testCreateCondition() {
        initializeWithPermissions(Permissions.POLICY_MANAGEMENT_UPDATE);

        final var policy = new Policy();
        policy.setName("foo");
        policy.setOperator(Operator.ANY);
        policy.setViolationState(ViolationState.INFO);
        qm.persist(policy);

        final Response response = jersey.target("%s/%s/condition".formatted(V1_POLICY, policy.getUuid()))
                .request()
                .header(X_API_KEY, apiKey)
                .put(Entity.json(/* language=JSON */ """
                        {
                          "subject": "PACKAGE_URL",
                          "operator": "MATCHES",
                          "value": "pkg:maven/foo/bar"
                        }
                        """));
        assertThat(response.getStatus()).isEqualTo(201);
        assertThatJson(getPlainTextBody(response)).isEqualTo(/* language=JSON */ """
                {
                  "uuid": "${json-unit.any-string}",
                  "subject": "PACKAGE_URL",
                  "operator": "MATCHES",
                  "value": "pkg:maven/foo/bar",
                  "violationType": "OPERATIONAL"
                }
                """);
    }

    @Test
    public void testCreateConditionWhenPolicyDoesNotExist() {
        initializeWithPermissions(Permissions.POLICY_MANAGEMENT_UPDATE);

        final Response response = jersey.target("%s/cec42e01-62a7-4c86-9b8f-cd6650be2888/condition".formatted(V1_POLICY))
                .request()
                .header(X_API_KEY, apiKey)
                .put(Entity.json(/* language=JSON */ """
                        {
                          "subject": "PACKAGE_URL",
                          "operator": "MATCHES",
                          "value": "pkg:maven/foo/bar"
                        }
                        """));
        assertThat(response.getStatus()).isEqualTo(404);
        assertThat(getPlainTextBody(response)).isEqualTo("The UUID of the policy could not be found.");
    }

    @Test
    public void testCreateConditionWhenUnauthorized() {
        final Response response = jersey.target("%s/cec42e01-62a7-4c86-9b8f-cd6650be2888/condition".formatted(V1_POLICY))
                .request()
                .header(X_API_KEY, apiKey)
                .put(Entity.json(/* language=JSON */ """
                        {
                          "subject": "PACKAGE_URL",
                          "operator": "MATCHES",
                          "value": "pkg:maven/foo/bar"
                        }
                        """));
        assertThat(response.getStatus()).isEqualTo(403);
    }

    @Test
    public void testCreateConditionWithExpression() {
        initializeWithPermissions(Permissions.POLICY_MANAGEMENT_UPDATE);

        final Policy policy = qm.createPolicy("policy", Operator.ANY, ViolationState.FAIL);

        final Response response = jersey.target("%s/%s/condition".formatted(V1_POLICY, policy.getUuid()))
                .request()
                .header(X_API_KEY, apiKey)
                .put(Entity.entity(/* language=JSON */ """
                        {
                          "subject": "EXPRESSION",
                          "value": "component.name == \\"foo\\"",
                          "violationType": "SECURITY"
                        }
                        """, MediaType.APPLICATION_JSON));
        assertThat(response.getStatus()).isEqualTo(201);
        assertThatJson(getPlainTextBody(response))
                .isEqualTo(/* language=JSON */ """
                        {
                          "uuid": "${json-unit.any-string}",
                          "subject": "EXPRESSION",
                          "operator": "MATCHES",
                          "value": "component.name == \\"foo\\"",
                          "violationType": "SECURITY"
                        }
                        """);
    }

    @Test
    public void testCreateConditionWithInvalidExpression() {
        initializeWithPermissions(Permissions.POLICY_MANAGEMENT_UPDATE);

        final Policy policy = qm.createPolicy("policy", Operator.ANY, ViolationState.FAIL);

        final Response response = jersey.target("%s/%s/condition".formatted(V1_POLICY, policy.getUuid()))
                .request()
                .header(X_API_KEY, apiKey)
                .put(Entity.entity(/* language=JSON */ """
                        {
                          "subject": "EXPRESSION",
                          "value": "component.doesNotExist == \\"foo\\"",
                          "violationType": "SECURITY"
                        }
                        """, MediaType.APPLICATION_JSON));

        assertThat(response.getStatus()).isEqualTo(400);
        assertThatJson(getPlainTextBody(response))
                .isEqualTo(/* language=JSON */ """
                        {
                          "celErrors": [
                            {
                              "line": 1,
                              "column": 9,
                              "message": "undefined field 'doesNotExist'"
                            }
                          ]
                        }
                        """);
    }

    @Test
    public void testUpdateCondition() {
        initializeWithPermissions(Permissions.POLICY_MANAGEMENT_UPDATE);

        final var policy = new Policy();
        policy.setName("foo");
        policy.setOperator(Operator.ANY);
        policy.setViolationState(ViolationState.INFO);
        qm.persist(policy);

        final var condition = new PolicyCondition();
        condition.setPolicy(policy);
        condition.setSubject(PolicyCondition.Subject.PACKAGE_URL);
        condition.setOperator(PolicyCondition.Operator.MATCHES);
        condition.setValue("pkg:maven/foo/bar");
        qm.persist(condition);

        final Response response = jersey.target("%s/condition".formatted(V1_POLICY))
                .request()
                .header(X_API_KEY, apiKey)
                .post(Entity.json(/* language=JSON */ """
                        {
                          "uuid": "%s",
                          "subject": "SEVERITY",
                          "operator": "IS",
                          "value": "HIGH"
                        }
                        """.formatted(condition.getUuid())));
        assertThat(response.getStatus()).isEqualTo(200);
        assertThatJson(getPlainTextBody(response))
                .withMatcher("conditionUuid", equalTo(condition.getUuid().toString()))
                .isEqualTo(/* language=JSON */ """
                        {
                          "uuid": "${json-unit.matches:conditionUuid}",
                          "subject": "SEVERITY",
                          "operator": "IS",
                          "value": "HIGH",
                          "violationType": "SECURITY"
                        }
                        """);
    }

    @Test
    public void testUpdateConditionWhenConditionDoesNotExist() {
        initializeWithPermissions(Permissions.POLICY_MANAGEMENT_UPDATE);

        final Response response = jersey.target("%s/condition".formatted(V1_POLICY))
                .request()
                .header(X_API_KEY, apiKey)
                .post(Entity.json(/* language=JSON */ """
                        {
                          "uuid": "8683b1db-96a3-4014-baf8-03e8cab8c647",
                          "subject": "SEVERITY",
                          "operator": "IS",
                          "value": "HIGH"
                        }
                        """));
        assertThat(response.getStatus()).isEqualTo(404);
        assertThat(getPlainTextBody(response)).isEqualTo("The UUID of the policy condition could not be found.");
    }

    @Test
    public void testUpdateConditionWhenUnauthorized() {
        final Response response = jersey.target("%s/condition".formatted(V1_POLICY))
                .request()
                .header(X_API_KEY, apiKey)
                .post(Entity.json(/* language=JSON */ """
                        {
                          "uuid": "8683b1db-96a3-4014-baf8-03e8cab8c647",
                          "subject": "SEVERITY",
                          "operator": "IS",
                          "value": "HIGH"
                        }
                        """));
        assertThat(response.getStatus()).isEqualTo(403);
    }

    @Test
    public void testUpdateConditionWithExpression() {
        initializeWithPermissions(Permissions.POLICY_MANAGEMENT_UPDATE);

        final Policy policy = qm.createPolicy("policy", Operator.ANY, ViolationState.FAIL);
        final PolicyCondition condition = qm.createPolicyCondition(policy,
                PolicyCondition.Subject.VULNERABILITY_ID, PolicyCondition.Operator.IS, "foobar");

        final Response response = jersey.target("%s/condition".formatted(V1_POLICY))
                .request()
                .header(X_API_KEY, apiKey)
                .post(Entity.entity(/* language=JSON */ """
                        {
                          "uuid": "%s",
                          "subject": "EXPRESSION",
                          "value": "component.name == \\"foo\\"",
                          "violationType": "OPERATIONAL"
                        }
                        """.formatted(condition.getUuid()), MediaType.APPLICATION_JSON));

        assertThat(response.getStatus()).isEqualTo(200);
        assertThatJson(getPlainTextBody(response))
                .isEqualTo(/* language=JSON */ """
                        {
                          "uuid": "${json-unit.any-string}",
                          "subject": "EXPRESSION",
                          "operator": "MATCHES",
                          "value": "component.name == \\"foo\\"",
                          "violationType": "OPERATIONAL"
                        }
                        """);
    }

    @Test
    public void testUpdateConditionWithInvalidExpression() {
        initializeWithPermissions(Permissions.POLICY_MANAGEMENT_UPDATE);

        final Policy policy = qm.createPolicy("policy", Operator.ANY, ViolationState.FAIL);
        final PolicyCondition condition = qm.createPolicyCondition(policy,
                PolicyCondition.Subject.VULNERABILITY_ID, PolicyCondition.Operator.IS, "foobar");

        final Response response = jersey.target("%s/condition".formatted(V1_POLICY))
                .request()
                .header(X_API_KEY, apiKey)
                .post(Entity.entity(/* language=JSON */ """
                        {
                          "uuid": "%s",
                          "subject": "EXPRESSION",
                          "value": "component.doesNotExist == \\"foo\\"",
                          "violationType": "SECURITY"
                        }
                        """.formatted(condition.getUuid()), MediaType.APPLICATION_JSON));

        assertThat(response.getStatus()).isEqualTo(400);
        assertThatJson(getPlainTextBody(response))
                .isEqualTo(/* language=JSON */ """
                        {
                          "celErrors": [
                            {
                              "line": 1,
                              "column": 9,
                              "message": "undefined field 'doesNotExist'"
                            }
                          ]
                        }
                        """);
    }

    @Test
    public void testDeleteCondition() {
        initializeWithPermissions(Permissions.POLICY_MANAGEMENT_UPDATE);

        final var policy = new Policy();
        policy.setName("foo");
        policy.setOperator(Operator.ANY);
        policy.setViolationState(ViolationState.INFO);
        qm.persist(policy);

        final var condition = new PolicyCondition();
        condition.setPolicy(policy);
        condition.setSubject(PolicyCondition.Subject.PACKAGE_URL);
        condition.setOperator(PolicyCondition.Operator.MATCHES);
        condition.setValue("pkg:maven/foo/bar");
        qm.persist(condition);

        final Response response = jersey.target("%s/condition/%s".formatted(V1_POLICY, condition.getUuid()))
                .request()
                .header(X_API_KEY, apiKey)
                .delete();
        assertThat(response.getStatus()).isEqualTo(204);
        assertThat(getPlainTextBody(response)).isEmpty();

        qm.getPersistenceManager().evictAll();
        assertThatExceptionOfType(JDOObjectNotFoundException.class)
                .isThrownBy(() -> qm.getObjectById(PolicyCondition.class, condition.getId()));
    }

    @Test
    public void testDeleteConditionWhenConditionDoesNotExist() {
        initializeWithPermissions(Permissions.POLICY_MANAGEMENT_UPDATE);

        final Response response = jersey.target("%s/condition/%s".formatted(V1_POLICY, UUID.randomUUID()))
                .request()
                .header(X_API_KEY, apiKey)
                .delete();
        assertThat(response.getStatus()).isEqualTo(404);
        assertThat(getPlainTextBody(response)).isEqualTo("The UUID of the policy condition could not be found.");
    }

    @Test
    public void testDeleteConditionWhenUnauthorized() {
        final Response response = jersey.target("%s/condition/%s".formatted(V1_POLICY, UUID.randomUUID()))
                .request()
                .header(X_API_KEY, apiKey)
                .delete();
        assertThat(response.getStatus()).isEqualTo(403);
    }

}
